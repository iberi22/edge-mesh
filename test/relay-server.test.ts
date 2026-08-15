import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { RelayServer } from "../src/transport/relay-server.js";
import { parseRelayUrl, resolveRelayUrl } from "../src/transport/relay-config.js";

describe("RelayServer and Relay Configuration", () => {
	let server: RelayServer;
	let port: number;

	beforeEach(async () => {
		// Port 0 selects an available ephemeral port
		server = new RelayServer({ port: 0 });
		port = await server.start();
	});

	afterEach(async () => {
		if (server) {
			await server.close();
		}
	});

	it("should start relay server and resolve config options", () => {
		expect(port).toBeGreaterThan(0);
		expect(server.getPort()).toBe(port);

		const resolved = resolveRelayUrl(`http://127.0.0.1:${port}/`);
		const parsed = parseRelayUrl(resolved);

		expect(parsed.host).toBe("127.0.0.1");
		expect(parsed.port).toBe(port);
		expect(parsed.secure).toBe(false);
	});

	it("should accept peer signaling connections and handle OPEN handshake", async () => {
		const wsUrl = `ws://127.0.0.1:${port}/?id=peer-1&key=peerjs`;
		const ws = new WebSocket(wsUrl);

		const openMessagePromise = new Promise<any>((resolve, reject) => {
			ws.on("message", (data) => {
				try {
					const msg = JSON.parse(data.toString());
					resolve(msg);
				} catch (err) {
					reject(err);
				}
			});
			ws.on("error", reject);
		});

		const msg = await openMessagePromise;
		expect(msg.type).toBe("OPEN");
		expect(server.getConnectedPeers()).toContain("peer-1");

		ws.close();
	});

	it("should route signaling messages between connected peers", async () => {
		const ws1 = new WebSocket(`ws://127.0.0.1:${port}/?id=peer-1&key=peerjs`);
		const ws2 = new WebSocket(`ws://127.0.0.1:${port}/?id=peer-2&key=peerjs`);

		const ws1Open = new Promise<void>((resolve) => {
			ws1.on("message", (data) => {
				const msg = JSON.parse(data.toString());
				if (msg.type === "OPEN") resolve();
			});
		});

		const ws2Open = new Promise<void>((resolve) => {
			ws2.on("message", (data) => {
				const msg = JSON.parse(data.toString());
				if (msg.type === "OPEN") resolve();
			});
		});

		await Promise.all([ws1Open, ws2Open]);

		const messagePromise = new Promise<any>((resolve) => {
			ws2.on("message", (data) => {
				const msg = JSON.parse(data.toString());
				if (msg.type === "OFFER") {
					resolve(msg);
				}
			});
		});

		// peer-1 sends OFFER to peer-2
		ws1.send(
			JSON.stringify({
				type: "OFFER",
				src: "peer-1",
				dst: "peer-2",
				payload: { sdp: "dummy-sdp-offer" },
			}),
		);

		const offerMsg = await messagePromise;
		expect(offerMsg.type).toBe("OFFER");
		expect(offerMsg.src).toBe("peer-1");
		expect(offerMsg.dst).toBe("peer-2");
		expect(offerMsg.payload).toEqual({ sdp: "dummy-sdp-offer" });

		ws1.close();
		ws2.close();
	});
});
