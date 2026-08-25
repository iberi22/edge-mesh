import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { createEnvelope, MessageDeduplicator } from "../protocol/index.js";
import type {
	Envolvente,
	NodoId,
	TipoMensaje,
	TipoTransporte,
} from "../types/index.js";
import { TIPO_MENSAJE, TIPO_TRANSPORTE } from "../types/index.js";
import type { ITransport, TransportEventMap } from "./types.js";

export interface TorConfig {
	readonly enabled: boolean;
	readonly localPort?: number;
	readonly dataDir?: string;
	readonly socksPort?: number;
	readonly controlPort?: number;
	readonly torBinary?: string;
}

export const DEFAULT_TOR_CONFIG: TorConfig = {
	enabled: false,
	localPort: 8080,
	socksPort: 9050,
	controlPort: 9051,
	torBinary: "tor",
};

/**
 * Resolve data directory for Tor state and hidden service keys.
 */
export function getTorDataDir(customPath?: string): string {
	if (customPath) return customPath;
	const home = os.homedir();
	if (process.platform === "win32") {
		return path.join(process.env.APPDATA || path.join(home, "AppData", "Roaming"), "edge-mesh", "tor");
	}
	if (process.platform === "darwin") {
		return path.join(home, "Library", "Application Support", "edge-mesh", "tor");
	}
	return path.join(home, ".local", "share", "edge-mesh", "tor");
}

/**
 * Generate standard torrc configuration for an Onion v3 Hidden Service.
 */
export function generateTorrc(config: TorConfig, dataDir: string): string {
	const hiddenServiceDir = path.join(dataDir, "onion");
	const localPort = config.localPort ?? 8080;
	const socksPort = config.socksPort ?? 9050;
	const controlPort = config.controlPort ?? 9051;

	return [
		`DataDirectory ${dataDir}`,
		`SocksPort ${socksPort}`,
		`ControlPort ${controlPort}`,
		`HiddenServiceDir ${hiddenServiceDir}`,
		`HiddenServicePort ${localPort} 127.0.0.1:${localPort}`,
		`HiddenServiceVersion 3`,
		"",
	].join("\n");
}

/**
 * TorOnionTransport provides opt-in Tor Onion v3 Hidden Service connectivity.
 */
export class TorOnionTransport implements ITransport {
	readonly tipo: TipoTransporte = TIPO_TRANSPORTE.TOR;
	readonly eventTarget: EventTarget;
	readonly nodoId: NodoId;
	readonly config: TorConfig;

	private readonly deduplicator: MessageDeduplicator;
	private torProcess: ChildProcess | null = null;
	private onionAddress: string | null = null;
	private conectado: boolean = false;
	private readonly dataDir: string;

	constructor(nodoId: NodoId, config: Partial<TorConfig> = {}) {
		this.nodoId = nodoId;
		this.eventTarget = new EventTarget();
		this.deduplicator = new MessageDeduplicator();
		this.config = { ...DEFAULT_TOR_CONFIG, ...config };
		this.dataDir = getTorDataDir(this.config.dataDir);
	}

	async start(localPort?: number): Promise<string | null> {
		if (!this.config.enabled) {
			return null;
		}

		const port = localPort ?? this.config.localPort ?? 8080;
		const hiddenServiceDir = path.join(this.dataDir, "onion");

		try {
			fs.mkdirSync(hiddenServiceDir, { recursive: true, mode: 0o700 });
		} catch (err) {
			console.warn(`[TorTransport] Failed to create data dir: ${(err as Error).message}`);
			return null;
		}

		const torrcPath = path.join(this.dataDir, "torrc");
		const torrcContent = generateTorrc({ ...this.config, localPort: port }, this.dataDir);
		fs.writeFileSync(torrcPath, torrcContent, { mode: 0o600 });

		const hostnamePath = path.join(hiddenServiceDir, "hostname");
		if (fs.existsSync(hostnamePath)) {
			this.onionAddress = fs.readFileSync(hostnamePath, "utf8").trim();
		}

		const torBin = this.config.torBinary ?? "tor";
		try {
			this.torProcess = spawn(torBin, ["-f", torrcPath], {
				stdio: ["ignore", "pipe", "pipe"],
			});

			this.torProcess.on("error", (err) => {
				console.warn(`[TorTransport] Tor binary execution error: ${err.message}`);
				this.conectado = false;
			});

			this.torProcess.on("exit", () => {
				this.conectado = false;
			});

			this.conectado = true;
		} catch (err) {
			console.warn(`[TorTransport] Failed to spawn Tor process: ${(err as Error).message}`);
			this.conectado = false;
		}

		return this.getOnionAddress();
	}

	getOnionAddress(): string | null {
		if (this.onionAddress) return this.onionAddress;
		const hostnamePath = path.join(this.dataDir, "onion", "hostname");
		if (fs.existsSync(hostnamePath)) {
			this.onionAddress = fs.readFileSync(hostnamePath, "utf8").trim();
		}
		return this.onionAddress;
	}

	async conectar(_peerId: string): Promise<void> {
		this.conectado = true;
	}

	async desconectar(): Promise<void> {
		this.conectado = false;
		if (this.torProcess) {
			this.torProcess.kill("SIGTERM");
			this.torProcess = null;
		}
	}

	async transmitir(datos: unknown, tipo?: TipoMensaje): Promise<void> {
		if (!this.conectado) return;
		const env = createEnvelope(
			tipo ?? TIPO_MENSAJE.SYNC,
			this.nodoId,
			"todos" as NodoId,
			datos,
		);
		this.emit("mensaje", { envolvente: env });
	}

	async enviar(destino: NodoId, datos: unknown, tipo?: TipoMensaje): Promise<void> {
		if (!this.conectado) return;
		const env = createEnvelope(
			tipo ?? TIPO_MENSAJE.SYNC,
			this.nodoId,
			destino,
			datos,
		);
		this.emit("mensaje", { envolvente: env });
	}

	obtenerConexiones(): readonly string[] {
		return this.conectado && this.onionAddress ? [this.onionAddress] : [];
	}

	estaConectado(): boolean {
		return this.conectado;
	}

	async cerrar(): Promise<void> {
		await this.desconectar();
	}

	on<K extends keyof TransportEventMap>(
		tipo: K,
		handler: (ev: TransportEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof TransportEventMap>(
		tipo: K,
		handler: (ev: TransportEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(tipo as string, handler as EventListener);
	}

	private emit<K extends keyof TransportEventMap>(
		tipo: K,
		detalle: TransportEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}
}
