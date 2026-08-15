import { EventEmitter } from "node:events";
import { type IncomingMessage, createServer, type Server as HttpServer } from "node:http";
import { type WebSocket, WebSocketServer } from "ws";
import { TokenBucketRateLimiter } from "../security/rate-limiter.js";

export interface IceServerConfig {
	urls: string | string[];
	username?: string;
	credential?: string;
}

export interface RelayServerOptions {
	port?: number;
	host?: string;
	path?: string;
	key?: string;
	iceServers?: IceServerConfig[];
	rateLimitTokensPerSec?: number;
	rateLimitMaxTokens?: number;
}

export class RelayServer extends EventEmitter {
	private readonly port: number;
	private readonly host: string;
	private readonly path: string;
	private readonly key: string;
	private readonly iceServers: IceServerConfig[];
	private readonly rateLimiter: TokenBucketRateLimiter;

	private httpServer?: HttpServer;
	private wss?: WebSocketServer;
	private clients: Map<string, WebSocket> = new Map();
	private running = false;
	private actualPort = 0;

	constructor(options: RelayServerOptions = {}) {
		super();
		const envPort = process.env.SWAL_RELAY_PORT
			? parseInt(process.env.SWAL_RELAY_PORT, 10)
			: undefined;
		this.port = options.port ?? envPort ?? 9000;
		this.host = options.host ?? process.env.SWAL_RELAY_HOST ?? "0.0.0.0";
		this.path = options.path ?? "/";
		if (!this.path.endsWith("/")) {
			this.path += "/";
		}
		this.key = options.key ?? "peerjs";
		this.iceServers = options.iceServers ?? [
			{ urls: "stun:stun.l.google.com:19302" },
		];

		const tokensPerSec = options.rateLimitTokensPerSec ?? 50;
		const maxTokens = options.rateLimitMaxTokens ?? 100;
		this.rateLimiter = new TokenBucketRateLimiter({
			tokensPerInterval: tokensPerSec,
			intervalMs: 1000,
			maxTokens: maxTokens,
		});
	}

	async start(): Promise<number> {
		if (this.running) {
			return this.actualPort;
		}

		return new Promise<number>((resolve, reject) => {
			this.httpServer = createServer((req, res) => {
				if (req.url === "/health" || req.url === "/status") {
					res.writeHead(200, { "Content-Type": "application/json" });
					res.end(
						JSON.stringify({
							status: "ok",
							peers: this.clients.size,
							iceServers: this.iceServers,
						}),
					);
					return;
				}
				res.writeHead(404);
				res.end("Not Found");
			});

			this.wss = new WebSocketServer({ noServer: true });

			this.httpServer.on("upgrade", (req: IncomingMessage, socket, head) => {
				const url = new URL(req.url ?? "", `http://${req.headers.host ?? "localhost"}`);
				const clientIp = req.socket.remoteAddress || "unknown";

				if (!this.rateLimiter.consume(clientIp, 1)) {
					socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
					socket.destroy();
					return;
				}

				if (!url.pathname.startsWith(this.path)) {
					socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
					socket.destroy();
					return;
				}

				this.wss?.handleUpgrade(req, socket, head, (ws: WebSocket) => {
					this.wss?.emit("connection", ws, req);
				});
			});

			this.wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
				this.handleConnection(ws, req);
			});

			this.httpServer.on("error", (err: Error) => {
				this.emit("error", err);
				reject(err);
			});

			this.httpServer.listen(this.port, this.host, () => {
				this.running = true;
				const addr = this.httpServer?.address();
				if (addr && typeof addr === "object") {
					this.actualPort = addr.port;
				} else {
					this.actualPort = this.port;
				}
				this.emit("listening", { port: this.actualPort, host: this.host });
				resolve(this.actualPort);
			});
		});
	}

	private handleConnection(ws: WebSocket, req: IncomingMessage): void {
		const url = new URL(req.url ?? "", `http://${req.headers.host ?? "localhost"}`);
		const peerId = url.searchParams.get("id");
		const key = url.searchParams.get("key");

		if (key && key !== this.key) {
			ws.send(
				JSON.stringify({
					type: "INVALID-KEY",
					payload: { msg: "Invalid key provided" },
				}),
			);
			ws.close();
			return;
		}

		if (!peerId) {
			ws.send(
				JSON.stringify({
					type: "ERROR",
					payload: { msg: "No peer ID specified" },
				}),
			);
			ws.close();
			return;
		}

		if (!this.rateLimiter.consume(`peer:${peerId}`, 1)) {
			ws.send(
				JSON.stringify({
					type: "ERROR",
					payload: { msg: "Rate limit exceeded" },
				}),
			);
			ws.close();
			return;
		}

		if (this.clients.has(peerId)) {
			ws.send(
				JSON.stringify({
					type: "ID-TAKEN",
					payload: { msg: `ID "${peerId}" is taken` },
				}),
			);
			ws.close();
			return;
		}

		this.clients.set(peerId, ws);
		this.emit("peerConnect", { peerId });

		ws.send(
			JSON.stringify({
				type: "OPEN",
			}),
		);

		ws.on("message", (raw: Buffer | string) => {
			if (!this.rateLimiter.consume(`peer:${peerId}`, 1)) {
				return;
			}
			try {
				const msg = JSON.parse(raw.toString());
				this.handleSignalingMessage(peerId, msg);
			} catch {
				// Ignore invalid JSON
			}
		});

		ws.on("close", () => {
			if (this.clients.get(peerId) === ws) {
				this.clients.delete(peerId);
				this.emit("peerDisconnect", { peerId });
			}
		});

		ws.on("error", (err) => {
			this.emit("peerError", { peerId, error: err });
		});
	}

	private handleSignalingMessage(srcPeerId: string, msg: any): void {
		if (!msg || typeof msg !== "object") return;

		const type = msg.type;

		if (type === "HEARTBEAT") {
			const ws = this.clients.get(srcPeerId);
			if (ws && ws.readyState === ws.OPEN) {
				ws.send(JSON.stringify({ type: "HEARTBEAT" }));
			}
			return;
		}

		const dstPeerId = msg.dst;
		if (!dstPeerId) return;

		const targetWs = this.clients.get(dstPeerId);
		if (!targetWs || targetWs.readyState !== targetWs.OPEN) {
			const srcWs = this.clients.get(srcPeerId);
			if (srcWs && srcWs.readyState === srcWs.OPEN) {
				srcWs.send(
					JSON.stringify({
						type: "LEAVE",
						src: dstPeerId,
						dst: srcPeerId,
					}),
				);
			}
			return;
		}

		// Relay signaling message (OFFER, ANSWER, CANDIDATE, LEAVE) - payload only!
		targetWs.send(
			JSON.stringify({
				type,
				src: srcPeerId,
				dst: dstPeerId,
				payload: msg.payload,
			}),
		);
	}

	getConnectedPeers(): string[] {
		return Array.from(this.clients.keys());
	}

	getPort(): number {
		return this.actualPort;
	}

	getIceServers(): IceServerConfig[] {
		return this.iceServers;
	}

	async close(): Promise<void> {
		if (!this.running) return;

		for (const ws of this.clients.values()) {
			try {
				ws.close();
			} catch {
				// Ignore
			}
		}
		this.clients.clear();

		if (this.wss) {
			this.wss.close();
		}

		await new Promise<void>((resolve) => {
			if (this.httpServer) {
				this.httpServer.close(() => resolve());
			} else {
				resolve();
			}
		});

		this.running = false;
		this.emit("close");
	}
}
