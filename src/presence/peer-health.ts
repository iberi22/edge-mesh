// ─── PEER HEALTH MONITOR + RECONNECT BACKOFF ───────────────────────────────
// Lightweight helpers used by app-layer transports (e.g. p2p-mesh-core).

export type PeerHealthStatus = "healthy" | "stale" | "offline";

export interface PeerHealthState {
	readonly peerId: string;
	readonly status: PeerHealthStatus;
	readonly lastSeen: number;
	readonly lastPingAt?: number;
	readonly lastPongAt?: number;
}

export interface PeerHealthMonitorOptions {
	readonly staleAfterMs?: number;
	readonly offlineAfterMs?: number;
	readonly now?: () => number;
}

export interface ReconnectDelayOptions {
	readonly initialDelayMs?: number;
	readonly maxDelayMs?: number;
	readonly jitterRatio?: number;
	readonly random?: () => number;
}

type HealthEventName = "peer:healthy" | "peer:stale" | "peer:offline" | "sync:error";

export interface PeerHealthMonitor {
	on(
		eventName: HealthEventName,
		listener: (state: PeerHealthState | { peerId: string; error: unknown }) => void,
	): PeerHealthMonitor;
	off(
		eventName: HealthEventName,
		listener: (state: PeerHealthState | { peerId: string; error: unknown }) => void,
	): PeerHealthMonitor;
	markConnected(peerId: string): PeerHealthState;
	markPing(peerId: string): PeerHealthState;
	markPong(peerId: string): PeerHealthState;
	markOffline(peerId: string): PeerHealthState;
	reportSyncError(peerId: string, error: unknown): void;
	sweep(): PeerHealthState[];
	get(peerId: string): PeerHealthState | undefined;
	list(): PeerHealthState[];
}

export function getReconnectDelay(
	attempt: number,
	options: ReconnectDelayOptions = {},
): number {
	const initialDelayMs = options.initialDelayMs ?? 1_000;
	const maxDelayMs = options.maxDelayMs ?? 30_000;
	const jitterRatio = options.jitterRatio ?? 0;
	const baseDelay = Math.min(
		initialDelayMs * 2 ** Math.max(0, attempt),
		maxDelayMs,
	);
	if (jitterRatio <= 0) return baseDelay;
	const random = options.random ?? Math.random;
	const jitter = baseDelay * jitterRatio * random();
	return Math.min(Math.round(baseDelay + jitter), maxDelayMs);
}

class PeerHealthMonitorImpl implements PeerHealthMonitor {
	private readonly peers = new Map<string, PeerHealthState>();
	private readonly listeners = new Map<
		HealthEventName,
		Set<(state: PeerHealthState | { peerId: string; error: unknown }) => void>
	>();
	private readonly now: () => number;
	private readonly staleAfterMs: number;
	private readonly offlineAfterMs: number;

	constructor(options: PeerHealthMonitorOptions = {}) {
		this.now = options.now ?? (() => Date.now());
		this.staleAfterMs = options.staleAfterMs ?? 30_000;
		this.offlineAfterMs = options.offlineAfterMs ?? 60_000;
	}

	on(
		eventName: HealthEventName,
		listener: (state: PeerHealthState | { peerId: string; error: unknown }) => void,
	): PeerHealthMonitor {
		const set = this.listeners.get(eventName) ?? new Set();
		set.add(listener);
		this.listeners.set(eventName, set);
		return this;
	}

	off(
		eventName: HealthEventName,
		listener: (state: PeerHealthState | { peerId: string; error: unknown }) => void,
	): PeerHealthMonitor {
		this.listeners.get(eventName)?.delete(listener);
		return this;
	}

	private emit(
		eventName: HealthEventName,
		payload: PeerHealthState | { peerId: string; error: unknown },
	): void {
		const set = this.listeners.get(eventName);
		if (!set) return;
		for (const listener of set) listener(payload);
	}

	markConnected(peerId: string): PeerHealthState {
		return this.setStatus(peerId, "healthy", { lastSeen: this.now() });
	}

	markPing(peerId: string): PeerHealthState {
		const current = this.getOrCreate(peerId);
		return this.setStatus(peerId, current.status, { lastPingAt: this.now() });
	}

	markPong(peerId: string): PeerHealthState {
		return this.setStatus(peerId, "healthy", {
			lastSeen: this.now(),
			lastPongAt: this.now(),
		});
	}

	markOffline(peerId: string): PeerHealthState {
		return this.setStatus(peerId, "offline", {
			lastSeen: this.getOrCreate(peerId).lastSeen,
		});
	}

	reportSyncError(peerId: string, error: unknown): void {
		this.emit("sync:error", { peerId, error });
	}

	sweep(): PeerHealthState[] {
		const now = this.now();
		const changed: PeerHealthState[] = [];
		for (const state of this.peers.values()) {
			if (state.status === "offline") continue;
			const age = now - state.lastSeen;
			if (age >= this.offlineAfterMs) {
				changed.push(this.setStatus(state.peerId, "offline"));
			} else if (age >= this.staleAfterMs && state.status !== "stale") {
				changed.push(this.setStatus(state.peerId, "stale"));
			}
		}
		return changed;
	}

	get(peerId: string): PeerHealthState | undefined {
		const state = this.peers.get(peerId);
		return state ? { ...state } : undefined;
	}

	list(): PeerHealthState[] {
		return Array.from(this.peers.values()).map((state) => ({ ...state }));
	}

	private getOrCreate(peerId: string): PeerHealthState {
		const existing = this.peers.get(peerId);
		if (existing) return existing;
		const state: PeerHealthState = {
			peerId,
			status: "healthy",
			lastSeen: this.now(),
		};
		this.peers.set(peerId, state);
		return state;
	}

	private setStatus(
		peerId: string,
		status: PeerHealthStatus,
		patch: Partial<PeerHealthState> = {},
	): PeerHealthState {
		const previous = this.getOrCreate(peerId);
		const next: PeerHealthState = {
			...previous,
			...patch,
			peerId,
			status,
		};
		this.peers.set(peerId, next);
		if (previous.status !== next.status || status === "healthy") {
			this.emit(`peer:${status}`, { ...next });
		}
		return { ...next };
	}
}

export function createPeerHealthMonitor(
	options: PeerHealthMonitorOptions = {},
): PeerHealthMonitor {
	return new PeerHealthMonitorImpl(options);
}
