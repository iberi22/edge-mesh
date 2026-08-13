import type { NodoId } from "../types/index.js";
import { PresenceManager } from "../presence/index.js";

// ─── EVENTS ────────────────────────────────────────────────────────────────

export interface AuthorityEventMap {
	failover: CustomEvent<{
		readonly antiguoMaster: NodoId | null;
		readonly nuevoMaster: NodoId;
		readonly razon: "timeout" | "forced" | "manual";
	}>;
	promocionado: CustomEvent<{ readonly nodoId: NodoId }>;
	degradado: CustomEvent<{ readonly nodoId: NodoId }>;
}

// ─── AUTHORITY MANAGER ─────────────────────────────────────────────────────

export class AuthorityManager {
	readonly eventTarget: EventTarget;
	private readonly localNodeId: NodoId;
	private readonly presence: PresenceManager;
	private currentMaster: NodoId | null = null;
	private running = false;
	private checkInterval: ReturnType<typeof setInterval> | null = null;

	constructor(
		localNodeId: NodoId,
		presence: PresenceManager,
		options?: {
			initialMaster?: NodoId;
		},
	) {
		this.eventTarget = new EventTarget();
		this.localNodeId = localNodeId;
		this.presence = presence;
		this.currentMaster = options?.initialMaster ?? null;
	}

	// ─── API DE AUTHORITY ───────────────────────────────────────────────────

	selectSuccessor(
		nodosActivos: readonly NodoId[],
		masterActual?: NodoId | null,
	): NodoId | null {
		const master = masterActual !== undefined ? masterActual : this.currentMaster;
		const candidatos = nodosActivos.filter((id) => id !== master);
		if (candidatos.length === 0) {
			return null;
		}
		// Deterministic sort: seniority (alphabetic order of NodoId string)
		const ordenados = [...candidatos].sort((a, b) => a.localeCompare(b));
		return ordenados[0] ?? null;
	}

	promoteSuccessor(
		nuevoMaster: NodoId,
		razon: "timeout" | "forced" | "manual" = "manual",
	): void {
		const antiguoMaster = this.currentMaster;
		if (antiguoMaster === nuevoMaster) {
			return;
		}

		this.currentMaster = nuevoMaster;

		this.emit("failover", {
			antiguoMaster,
			nuevoMaster,
			razon,
		});

		if (nuevoMaster === this.localNodeId) {
			this.emit("promocionado", { nodoId: this.localNodeId });
		} else if (antiguoMaster === this.localNodeId) {
			this.emit("degradado", { nodoId: this.localNodeId });
		}
	}

	checkHostHealth(hostId: NodoId): boolean {
		if (hostId === this.localNodeId) {
			return true;
		}
		const activos = this.presence.obtenerNodosActivos();
		return activos.includes(hostId);
	}

	forceHostFailover(): void {
		this.handleMasterFailure("forced");
	}

	// ─── LIFECYCLE ──────────────────────────────────────────────────────────

	iniciar(): void {
		if (this.running) return;
		this.running = true;

		this.presence.on("nodoDesaparecio", this.handleNodoDesaparecio);

		// Periodic health check as a safety fallback
		this.checkInterval = setInterval(() => {
			this.verificarSaludMaster();
		}, 1000);
	}

	detener(): void {
		if (!this.running) return;
		this.running = false;

		this.presence.off("nodoDesaparecio", this.handleNodoDesaparecio);

		if (this.checkInterval) {
			clearInterval(this.checkInterval);
			this.checkInterval = null;
		}
	}

	// ─── GETTERS & HELPERS ───────────────────────────────────────────────────

	obtenerMaster(): NodoId | null {
		return this.currentMaster;
	}

	obtenerTodosLosNodosActivos(): readonly NodoId[] {
		const activos = [...this.presence.obtenerNodosActivos()];
		if (!activos.includes(this.localNodeId)) {
			activos.push(this.localNodeId);
		}
		return activos;
	}

	private handleNodoDesaparecio = (ev: any) => {
		const { nodoId } = ev.detail;
		if (nodoId === this.currentMaster) {
			this.handleMasterFailure("timeout");
		}
	};

	private verificarSaludMaster(): void {
		if (this.currentMaster && this.currentMaster !== this.localNodeId) {
			if (!this.checkHostHealth(this.currentMaster)) {
				this.handleMasterFailure("timeout");
			}
		}
	}

	private handleMasterFailure(razon: "timeout" | "forced" | "manual"): void {
		const antiguoMaster = this.currentMaster;
		const todosActivos = this.obtenerTodosLosNodosActivos();
		const sucesor = this.selectSuccessor(todosActivos, antiguoMaster);

		if (sucesor) {
			this.promoteSuccessor(sucesor, razon);
		}
	}

	// ─── EVENTS ─────────────────────────────────────────────────────────────

	on<K extends keyof AuthorityEventMap>(
		tipo: K,
		handler: (ev: AuthorityEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof AuthorityEventMap>(
		tipo: K,
		handler: (ev: AuthorityEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof AuthorityEventMap>(
		tipo: K,
		detalle: AuthorityEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}
}

// ─── FACTORY ───────────────────────────────────────────────────────────────

export function createAuthorityManager(
	localNodeId: NodoId,
	presence: PresenceManager,
	options?: {
		initialMaster?: NodoId;
	},
): AuthorityManager {
	return new AuthorityManager(localNodeId, presence, options);
}
