import { generarNonce } from "../protocol/utils.js";
import { InMemoryStorage, type IStorage } from "../storage/index.js";
import type { NamespaceCapabilityGrant, NodoId } from "../types/index.js";

/** Rol de un sujeto dentro de un namespace (string, consistente con updateRole/revokeRole). */
export type Role = string;

export interface RoleAssignment {
	readonly id: string;
	readonly rol: string;
	readonly sujeto: NodoId;
}

export interface Capability {
	readonly nombre: string;
	readonly descripcion?: string;
}

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
	private grants: Map<string, NamespaceCapabilityGrant>;
	private readonly reglasLocales: Map<string, Set<string>>;
	private roleAssignments: Map<string, RoleAssignment>;
	private capabilities: Map<string, Capability[]>;
	private readonly storage: IStorage;

	constructor(storage?: IStorage) {
		this.eventTarget = new EventTarget();
		this.grants = new Map();
		this.reglasLocales = new Map();
		this.roleAssignments = new Map();
		this.capabilities = new Map();
		this.storage = storage ?? new InMemoryStorage();

		// Background loading during construction
		void this.loadGrants();
		void this.loadRoleAssignments();
		void this.loadCapabilities();
	}

	// ─── PERSISTENCE ─────────────────────────────────────────────────────

	async saveGrants(): Promise<void> {
		await this.storage.put("authz:grants", Array.from(this.grants.entries()));
	}

	async loadGrants(): Promise<void> {
		const data = await this.storage.get("authz:grants");
		if (data) {
			let loadedMap: Map<string, NamespaceCapabilityGrant>;
			if (Array.isArray(data)) {
				loadedMap = new Map(data);
			} else if (typeof data === "object" && data !== null && "valor" in data) {
				loadedMap = new Map((data as any).valor);
			} else {
				return;
			}
			for (const [key, value] of loadedMap) {
				if (!this.grants.has(key)) {
					this.grants.set(key, value);
				}
			}
		}
	}

	async saveRoleAssignments(): Promise<void> {
		await this.storage.put(
			"authz:roleAssignments",
			Array.from(this.roleAssignments.entries()),
		);
	}

	async loadRoleAssignments(): Promise<void> {
		const data = await this.storage.get("authz:roleAssignments");
		if (data) {
			let loadedMap: Map<string, RoleAssignment>;
			if (Array.isArray(data)) {
				loadedMap = new Map(data);
			} else if (typeof data === "object" && data !== null && "valor" in data) {
				loadedMap = new Map((data as any).valor);
			} else {
				return;
			}
			for (const [key, value] of loadedMap) {
				if (!this.roleAssignments.has(key)) {
					this.roleAssignments.set(key, value);
				}
			}
		}
	}

	async saveCapabilities(): Promise<void> {
		await this.storage.put(
			"authz:capabilities",
			Array.from(this.capabilities.entries()),
		);
	}

	async loadCapabilities(): Promise<void> {
		const data = await this.storage.get("authz:capabilities");
		if (data) {
			let loadedMap: Map<string, Capability[]>;
			if (Array.isArray(data)) {
				loadedMap = new Map(data);
			} else if (typeof data === "object" && data !== null && "valor" in data) {
				loadedMap = new Map((data as any).valor);
			} else {
				return;
			}
			for (const [key, value] of loadedMap) {
				if (!this.capabilities.has(key)) {
					this.capabilities.set(key, value);
				}
			}
		}
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
		void this.saveGrants();
		return grant;
	}

	grant(
		espacio: string,
		sujeto: NodoId,
		capacidad: string,
		expiracionMs?: number,
		firma?: Uint8Array,
	): NamespaceCapabilityGrant {
		return this.concederCapacidad(espacio, sujeto, capacidad, expiracionMs, firma);
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
		void this.saveGrants();
		return true;
	}

	revoke(
		espacio: string,
		sujeto: NodoId,
		capacidad: string,
	): boolean {
		return this.revocarCapacidad(espacio, sujeto, capacidad);
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
			void this.saveGrants();
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
		if (eliminados > 0) {
			void this.saveGrants();
		}
		return eliminados;
	}

	// ─── ROLES & CAPABILITIES HELPER METHODS ─────────────────────────────

	updateRole(sujeto: NodoId, rol: string): void {
		const id = generarNonce();
		const assignment: RoleAssignment = { id, rol, sujeto };
		this.roleAssignments.set(sujeto, assignment);
		void this.saveRoleAssignments();
	}

	obtenerRoles(): Map<string, RoleAssignment> {
		return this.roleAssignments;
	}

	revokeRole(sujeto: NodoId): boolean {
		const res = this.roleAssignments.delete(sujeto);
		if (res) {
			void this.saveRoleAssignments();
		}
		return res;
	}

	concederCapacidades(espacio: string, caps: Capability[]): void {
		this.capabilities.set(espacio, caps);
		void this.saveCapabilities();
	}

	obtenerCapacidades(espacio: string): Capability[] | undefined {
		return this.capabilities.get(espacio);
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

export function createNamespaceAuthorizer(storage?: IStorage): NamespaceAuthorizer {
	return new NamespaceAuthorizer(storage);
}
