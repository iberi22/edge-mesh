import { generarNonce } from "../protocol/utils.js";
import type { NamespaceCapabilityGrant, NodoId } from "../types/index.js";

/** Rol de un sujeto dentro de un namespace (string, consistente con updateRole/revokeRole). */
export type Role = string;

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const EXPIRACION_POR_DEFECTO_MS = 86_400_000; // 24h

export const CAPACIDAD_ESTANDAR = {
	LEER: "read",
	ESCRIBIR: "write",
	ADMIN: "admin",
	SINC: "sync",
	PRESENCIA: "presence",
	GOBERNANZA: "governance",
} as const;

export type CapacidadEstandar =
	(typeof CAPACIDAD_ESTANDAR)[keyof typeof CAPACIDAD_ESTANDAR];

// ─── NAMESPACE AUTHORIZER ──────────────────────────────────────────────────

export interface AuthzEventMap {
	capacidadConcedida: CustomEvent<{ readonly grant: NamespaceCapabilityGrant }>;
	capacidadRevocada: CustomEvent<{
		readonly id: string;
		readonly espacio: string;
		readonly sujeto: NodoId;
	}>;
	autorizacionFallida: CustomEvent<{
		readonly espacio: string;
		readonly sujeto: NodoId;
		readonly capacidad: string;
		readonly razon: string;
	}>;
}

export class NamespaceAuthorizer {
	readonly eventTarget: EventTarget;
	private readonly grants: Map<string, NamespaceCapabilityGrant>;
	private readonly reglasLocales: Map<string, Set<string>>;

	constructor() {
		this.eventTarget = new EventTarget();
		this.grants = new Map();
		this.reglasLocales = new Map();
	}

	// ─── GRANTS ──────────────────────────────────────────────────────────

	concederCapacidad(
		espacio: string,
		sujeto: NodoId,
		capacidad: string,
		expiracionMs: number = EXPIRACION_POR_DEFECTO_MS,
		firma?: Uint8Array,
	): NamespaceCapabilityGrant {
		const grant: NamespaceCapabilityGrant = {
			id: generarNonce(),
			espacio,
			sujeto,
			capacidad,
			fechaEmision: Date.now(),
			fechaExpiracion: Date.now() + expiracionMs,
			firma: firma ?? new Uint8Array(0),
		};

		const clave = this.crearClave(espacio, sujeto, capacidad);
		this.grants.set(clave, grant);

		this.emit("capacidadConcedida", { grant });
		return grant;
	}

	revocarCapacidad(
		espacio: string,
		sujeto: NodoId,
		capacidad: string,
	): boolean {
		const clave = this.crearClave(espacio, sujeto, capacidad);
		const grant = this.grants.get(clave);
		if (grant === undefined) return false;

		this.grants.delete(clave);

		this.emit("capacidadRevocada", {
			id: grant.id,
			espacio,
			sujeto,
		});
		return true;
	}

	verificarCapacidad(
		espacio: string,
		sujeto: NodoId,
		capacidad: string,
	): boolean {
		// Siempre verificar admin
		if (this.verificarGrant(espacio, sujeto, "admin")) return true;

		return this.verificarGrant(espacio, sujeto, capacidad);
	}

	private verificarGrant(
		espacio: string,
		sujeto: NodoId,
		capacidad: string,
	): boolean {
		const clave = this.crearClave(espacio, sujeto, capacidad);
		const grant = this.grants.get(clave);

		if (grant === undefined) {
			this.emit("autorizacionFallida", {
				espacio,
				sujeto,
				capacidad,
				razon: "Sin permiso concedido",
			});
			return false;
		}

		if (Date.now() > grant.fechaExpiracion) {
			this.grants.delete(clave);
			this.emit("autorizacionFallida", {
				espacio,
				sujeto,
				capacidad,
				razon: "Permiso expirado",
			});
			return false;
		}

		return true;
	}

	// ─── REGLAS LOCALES ──────────────────────────────────────────────────

	agregarReglaLocal(espacio: string, regla: string): void {
		const reglas = this.reglasLocales.get(espacio) ?? new Set();
		reglas.add(regla);
		this.reglasLocales.set(espacio, reglas);
	}

	removerReglaLocal(espacio: string, regla: string): boolean {
		const reglas = this.reglasLocales.get(espacio);
		if (reglas === undefined) return false;
		const resultado = reglas.delete(regla);
		if (reglas.size === 0) {
			this.reglasLocales.delete(espacio);
		}
		return resultado;
	}

	verificarReglaLocal(espacio: string, regla: string): boolean {
		return this.reglasLocales.get(espacio)?.has(regla) ?? false;
	}

	// ─── CONSULTAS ───────────────────────────────────────────────────────

	obtenerGrantsDeNodo(sujeto: NodoId): readonly NamespaceCapabilityGrant[] {
		return Array.from(this.grants.values()).filter((g) => g.sujeto === sujeto);
	}

	obtenerGrantsDeEspacio(espacio: string): readonly NamespaceCapabilityGrant[] {
		return Array.from(this.grants.values()).filter(
			(g) => g.espacio === espacio,
		);
	}

	obtenerTodosLosGrants(): readonly NamespaceCapabilityGrant[] {
		return Array.from(this.grants.values());
	}

	limpiarGrantsExpirados(): number {
		const ahora = Date.now();
		let eliminados = 0;
		for (const [clave, grant] of this.grants) {
			if (ahora > grant.fechaExpiracion) {
				this.grants.delete(clave);
				eliminados++;
			}
		}
		return eliminados;
	}

	// ─── EVENTOS ─────────────────────────────────────────────────────────

	on<K extends keyof AuthzEventMap>(
		tipo: K,
		handler: (ev: AuthzEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof AuthzEventMap>(
		tipo: K,
		handler: (ev: AuthzEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof AuthzEventMap>(
		tipo: K,
		detalle: AuthzEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	// ─── UTILIDADES ──────────────────────────────────────────────────────

	private crearClave(
		espacio: string,
		sujeto: NodoId,
		capacidad: string,
	): string {
		return `${espacio}::${sujeto}::${capacidad}`;
	}
}

// ─── FACTORY ───────────────────────────────────────────────────────────────

export function createNamespaceAuthorizer(): NamespaceAuthorizer {
	return new NamespaceAuthorizer();
}
