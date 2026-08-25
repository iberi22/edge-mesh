import type {
	GovernancePolicy,
	NodoId,
	ParPublico,
	PayloadVotacion,
	VerificadorVotos,
} from "../types/index.js";
import { POLITICA_GOBERNANZA } from "../types/index.js";
import { hexABytes } from "../protocol/utils.js";

export type { VerificadorVotos };

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const POLITICA_POR_DEFECTO: GovernancePolicy = {
	politica: POLITICA_GOBERNANZA.DEMOCRATICA,
	umbral: 0.51,
	ventanaMs: 30_000,
	pesoNodo: {},
	reglas: [],
} as const;

// ─── VOTE ──────────────────────────────────────────────────────────────────

export interface Propuesta {
	readonly id: string;
	readonly tipo: string;
	readonly proponente: NodoId;
	readonly datos: unknown;
	readonly timestamp: number;
	readonly expiracion: number;
	votos: PayloadVotacion[];
	estado: EstadoPropuesta;
}

export const ESTADO_PROPUESTA = {
	ABIERTA: "abierta",
	APROBADA: "aprobada",
	RECHAZADA: "rechazada",
	EXPIRADA: "expirada",
} as const;

export type EstadoPropuesta =
	(typeof ESTADO_PROPUESTA)[keyof typeof ESTADO_PROPUESTA];

// ─── GOVERANCE MANAGER ─────────────────────────────────────────────────────

export interface GovernanceEventMap {
	propuestaCreada: CustomEvent<{ readonly propuesta: Propuesta }>;
	votoRecibido: CustomEvent<{
		readonly propuesta: string;
		readonly voto: PayloadVotacion;
	}>;
	propuestaResultado: CustomEvent<{
		readonly propuesta: string;
		readonly resultado: EstadoPropuesta;
	}>;
	politicaCambiada: CustomEvent<{ readonly politica: GovernancePolicy }>;
}

export interface GovernanceManagerOptions {
	readonly requireSignedVotes?: boolean;
}

export class GovernanceManager {
	readonly eventTarget: EventTarget;
	private politica: GovernancePolicy;
	private readonly propuestas: Map<string, Propuesta>;
	private readonly timers: Map<string, ReturnType<typeof setTimeout>>;
	private readonly verificador?: VerificadorVotos;
	private readonly requireSignedVotes: boolean;

	constructor(
		politica?: GovernancePolicy,
		verificador?: VerificadorVotos,
		options?: GovernanceManagerOptions,
	) {
		this.eventTarget = new EventTarget();
		this.politica = { ...POLITICA_POR_DEFECTO, ...politica };
		this.propuestas = new Map();
		this.timers = new Map();
		this.verificador = verificador;
		this.requireSignedVotes = options?.requireSignedVotes ?? false;
	}

	// ─── PROPUESTAS ───────────────────────────────────────────────────────

	crearPropuesta(
		id: string,
		tipo: string,
		proponente: NodoId,
		datos: unknown,
		expiracionMs?: number,
	): Propuesta {
		const expiracion = expiracionMs ?? this.politica.ventanaMs;

		const propuesta: Propuesta = {
			id,
			tipo,
			proponente,
			datos,
			timestamp: Date.now(),
			expiracion: Date.now() + expiracion,
			votos: [],
			estado: ESTADO_PROPUESTA.ABIERTA,
		};

		this.propuestas.set(id, propuesta);

		const timer = setTimeout(() => {
			this.cerrarPropuesta(id);
		}, expiracion);

		this.timers.set(id, timer);

		this.emit("propuestaCreada", { propuesta });
		return propuesta;
	}

	votar(id: string, voto: PayloadVotacion): boolean {
		const propuesta = this.propuestas.get(id);
		if (propuesta === undefined) return false;
		if (propuesta.estado !== ESTADO_PROPUESTA.ABIERTA) return false;
		if (Date.now() > propuesta.expiracion) return false;

		// Requerir firma estricta si configurado
		if (this.requireSignedVotes && !voto.firma) {
			return false;
		}

		// Verificación criptográfica si hay verificador y firma
		if (this.verificador && voto.firma) {
			const clavePublica = this.verificador.obtenerClavePublica(voto.nodoId);
			if (!clavePublica) return false;

			const mensajeBytes = new TextEncoder().encode(
				JSON.stringify({
					propuestaId: id,
					nodoId: voto.nodoId,
					voto: voto.voto,
					timestamp: voto.timestamp,
				}),
			);
			const firmaBytes =
				typeof voto.firma === "string"
					? hexABytes(voto.firma)
					: voto.firma instanceof Uint8Array
						? voto.firma
						: new Uint8Array(voto.firma);

			const valido = this.verificador.verificarFirma(
				mensajeBytes,
				firmaBytes,
				clavePublica,
			);
			if (!valido) return false;
		}

		// Evitar voto duplicado del mismo nodo
		const yaVoto = propuesta.votos.some((v) => v.nodoId === voto.nodoId);
		if (yaVoto) return false;

		const nuevosVotos = [...propuesta.votos, voto];
		propuesta.votos = nuevosVotos;
		this.propuestas.set(id, propuesta);

		this.emit("votoRecibido", { propuesta: id, voto });

		// Verificar si ya se alcanzó el umbral
		if (this.verificarUmbral(propuesta)) {
			this.cerrarPropuesta(id, ESTADO_PROPUESTA.APROBADA);
		}

		return true;
	}

	private cerrarPropuesta(id: string, forzar?: EstadoPropuesta): void {
		const propuesta = this.propuestas.get(id);
		if (propuesta === undefined) return;

		const timer = this.timers.get(id);
		if (timer !== undefined) {
			clearTimeout(timer);
			this.timers.delete(id);
		}

		let resultado: EstadoPropuesta;

		if (forzar !== undefined) {
			resultado = forzar;
		} else {
			resultado = this.verificarUmbral(propuesta)
				? ESTADO_PROPUESTA.APROBADA
				: ESTADO_PROPUESTA.RECHAZADA;
		}

		propuesta.estado = resultado;
		this.propuestas.set(id, propuesta);

		this.emit("propuestaResultado", { propuesta: id, resultado });
	}

	private verificarUmbral(propuesta: Propuesta): boolean {
		const pesoTotal = this.calcularPesoTotal(propuesta);
		return pesoTotal >= this.politica.umbral;
	}

	private calcularPesoTotal(propuesta: Propuesta): number {
		return propuesta.votos.reduce((total, voto) => {
			const peso = this.politica.pesoNodo[voto.nodoId] ?? 1;
			return voto.voto === "a_favor" ? total + peso : total;
		}, 0);
	}

	// ─── POLITICA ─────────────────────────────────────────────────────────

	actualizarPolitica(politica: Partial<GovernancePolicy>): void {
		this.politica = { ...this.politica, ...politica };
		this.emit("politicaCambiada", { politica: this.politica });
	}

	obtenerPolitica(): GovernancePolicy {
		return { ...this.politica };
	}

	obtenerPropuestas(estado?: EstadoPropuesta): readonly Propuesta[] {
		const todas = Array.from(this.propuestas.values());
		if (estado === undefined) return todas;
		return todas.filter((p) => p.estado === estado);
	}

	obtenerPropuesta(id: string): Propuesta | null {
		return this.propuestas.get(id) ?? null;
	}

	importarPropuestas(propuestas: readonly Propuesta[]): void {
		for (const prop of propuestas) {
			this.propuestas.set(prop.id, { ...prop });
			if (prop.estado === ESTADO_PROPUESTA.ABIERTA) {
				const expiracionRestante = prop.expiracion - Date.now();
				const timerExistente = this.timers.get(prop.id);
				if (timerExistente) {
					clearTimeout(timerExistente);
				}
				if (expiracionRestante > 0) {
					const timer = setTimeout(() => {
						this.cerrarPropuesta(prop.id);
					}, expiracionRestante);
					this.timers.set(prop.id, timer);
				} else {
					this.cerrarPropuesta(prop.id);
				}
			} else {
				const timerExistente = this.timers.get(prop.id);
				if (timerExistente) {
					clearTimeout(timerExistente);
					this.timers.delete(prop.id);
				}
			}
		}
	}

	// ─── EVENTOS ──────────────────────────────────────────────────────────

	on<K extends keyof GovernanceEventMap>(
		tipo: K,
		handler: (ev: GovernanceEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof GovernanceEventMap>(
		tipo: K,
		handler: (ev: GovernanceEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof GovernanceEventMap>(
		tipo: K,
		detalle: GovernanceEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	// ─── LIMPIEZA ─────────────────────────────────────────────────────────

	limpiarPropuestasExpiradas(): void {
		const ahora = Date.now();
		for (const [id, propuesta] of this.propuestas) {
			if (propuesta.expiracion < ahora) {
				this.cerrarPropuesta(id);
			}
		}
	}

	destruir(): void {
		for (const timer of this.timers.values()) {
			clearTimeout(timer);
		}
		this.timers.clear();
		this.propuestas.clear();
	}
}

// ─── FACTORY ───────────────────────────────────────────────────────────────

export function createGovernanceManager(
	politica?: GovernancePolicy,
	verificador?: VerificadorVotos,
	options?: GovernanceManagerOptions,
): GovernanceManager {
	return new GovernanceManager(politica, verificador, options);
}

export * from "./authority.js";
export * from "./merge.js";
