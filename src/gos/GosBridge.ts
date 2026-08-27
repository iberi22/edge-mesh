import type { EdgeMesh } from "../edge-mesh.js";
import type { PresenceManager } from "../presence/index.js";

export interface BandwidthTelemetry {
	readonly bytesSent: number;
	readonly bytesReceived: number;
	readonly txRateBytesPerSec: number;
	readonly rxRateBytesPerSec: number;
}

export interface NodeTelemetry {
	readonly nodeId: string;
	readonly timestamp: number;
	readonly uptimeMs: number;
	readonly status: "online" | "offline" | "degraded";
	readonly activePeers: number;
	readonly bandwidth: BandwidthTelemetry;
}

export interface GosBridgeConfig {
	readonly intervalMs?: number;
	readonly presence?: PresenceManager;
	readonly onTelemetry?: (telemetry: NodeTelemetry) => void;
}

export class GosBridge {
	readonly nodeId: string;
	private readonly mesh?: EdgeMesh;
	private readonly presence?: PresenceManager;
	private readonly config: GosBridgeConfig;
	private readonly eventTarget: EventTarget;

	private readonly startTime: number;
	private bytesSent = 0;
	private bytesReceived = 0;
	private lastBytesSent = 0;
	private lastBytesReceived = 0;
	private lastSampleTime: number;
	private txRate = 0;
	private rxRate = 0;

	private intervalTimer: ReturnType<typeof setInterval> | null = null;
	private running = false;

	constructor(meshOrNodeId: EdgeMesh | string, config: GosBridgeConfig = {}) {
		this.eventTarget = new EventTarget();
		this.config = config;
		this.startTime = Date.now();
		this.lastSampleTime = this.startTime;

		if (typeof meshOrNodeId === "string") {
			this.nodeId = meshOrNodeId;
			this.presence = config.presence;
		} else {
			this.mesh = meshOrNodeId;
			this.nodeId = meshOrNodeId.config.nodoId;
			this.presence = config.presence ?? meshOrNodeId.presence;
		}
	}

	recordBytesSent(bytes: number): void {
		if (bytes > 0) {
			this.bytesSent += bytes;
		}
	}

	recordBytesReceived(bytes: number): void {
		if (bytes > 0) {
			this.bytesReceived += bytes;
		}
	}

	start(): void {
		if (this.running) return;
		this.running = true;
		this.lastSampleTime = Date.now();
		this.lastBytesSent = this.bytesSent;
		this.lastBytesReceived = this.bytesReceived;

		const interval = this.config.intervalMs ?? 5000;
		this.intervalTimer = setInterval(() => {
			this.emitTelemetry();
		}, interval);
	}

	stop(): void {
		if (!this.running) return;
		this.running = false;
		if (this.intervalTimer !== null) {
			clearInterval(this.intervalTimer);
			this.intervalTimer = null;
		}
	}

	isStreaming(): boolean {
		return this.running;
	}

	getTelemetry(): NodeTelemetry {
		const now = Date.now();
		const uptimeMs = now - this.startTime;

		this.calculateRates(now);

		let activePeers = 0;
		if (this.presence) {
			activePeers = this.presence.obtenerNodosActivos().length;
		}

		let status: "online" | "offline" | "degraded" = "online";
		if (this.presence) {
			const selfHealth = this.presence.obtenerSalud(this.nodeId as never);
			if (
				!selfHealth ||
				selfHealth.estado === "fallando" ||
				selfHealth.fallosConsecutivos > 0
			) {
				status = "degraded";
			}
		}

		return {
			nodeId: this.nodeId,
			timestamp: now,
			uptimeMs,
			status,
			activePeers,
			bandwidth: {
				bytesSent: this.bytesSent,
				bytesReceived: this.bytesReceived,
				txRateBytesPerSec: this.txRate,
				rxRateBytesPerSec: this.rxRate,
			},
		};
	}

	private calculateRates(now: number): void {
		const elapsedSec = (now - this.lastSampleTime) / 1000;
		if (elapsedSec > 0) {
			const deltaSent = this.bytesSent - this.lastBytesSent;
			const deltaReceived = this.bytesReceived - this.lastBytesReceived;
			this.txRate = Math.round((deltaSent / elapsedSec) * 100) / 100;
			this.rxRate = Math.round((deltaReceived / elapsedSec) * 100) / 100;
			this.lastBytesSent = this.bytesSent;
			this.lastBytesReceived = this.bytesReceived;
			this.lastSampleTime = now;
		}
	}

	private emitTelemetry(): void {
		const telemetry = this.getTelemetry();

		if (this.config.onTelemetry) {
			try {
				this.config.onTelemetry(telemetry);
			} catch (e) {
				console.error("Error in GosBridge onTelemetry callback:", e);
			}
		}

		const event = new CustomEvent("telemetry", { detail: telemetry });
		this.eventTarget.dispatchEvent(event);
	}

	onTelemetry(callback: (telemetry: NodeTelemetry) => void): () => void {
		const handler = (ev: Event) => {
			const customEv = ev as CustomEvent<NodeTelemetry>;
			callback(customEv.detail);
		};
		this.eventTarget.addEventListener("telemetry", handler);
		return () => {
			this.eventTarget.removeEventListener("telemetry", handler);
		};
	}
}
