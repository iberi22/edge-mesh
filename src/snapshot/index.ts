import { InMemoryStorage, type IStorage } from "../storage/index.js";
import type { NodoId, PayloadSnapshot, NamespaceCapabilityGrant } from "../types/index.js";
import type { RoleAssignment } from "../authz/index.js";
import type { Perfil as Profile } from "../maloca/perfil.js";
import { MerkleTree } from "../maloca/evidentia.js";
import type { GovernanceSnapshot } from "../governance/merge.js";

// ─── SNAPSHOT SYSTEM TYPES & INTERFACES ──────────────────────────────────────

export type Grant = NamespaceCapabilityGrant;

export interface Subscription {
	id: string;
	topic: string;
	subscriber: string;
	timestamp: number;
}

export interface SnapshotConfig {
	intervalMs: number;        // Default: cada 5 minutos
	maxSnapshots: number;      // Default: mantener últimos 3
	include: string[];         // Namespaces a incluir
}

export interface Snapshot {
	id: string;
	timestamp: number;
	state: {
		grants: [string, Grant][];
		roleAssignments: [string, RoleAssignment][];
		profiles: [string, Profile][];
		merkleTree: MerkleTree;
		governance: GovernanceSnapshot;
		subscriptions: [string, Subscription][];
		lastOpSequence?: number;
	};
	signature?: string; // ML-DSA-65
	prevSnapshotId?: string; // Chain de snapshots
}

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const SNAPSHOT_POR_DEFECTO_CADA = 100 as const;

// ─── SNAPSHOT MANAGER ──────────────────────────────────────────────────────

export interface SnapshotManagerConfig {
	readonly docId: string;
	readonly interval?: number;
	readonly storage?: IStorage;
	readonly maxSnapshots?: number;
}

export interface SnapshotMetadata {
	readonly version: number;
	readonly timestamp: number;
	readonly nodos: readonly NodoId[];
	readonly tamanio: number;
	readonly hash: string;
}

export interface SnapshotEventMap {
	snapshotCreado: CustomEvent<{
		readonly snapshot: SnapshotMetadata;
		readonly docId: string;
	}>;
	snapshotRestaurado: CustomEvent<{
		readonly version: number;
		readonly docId: string;
	}>;
	snapshotCompartido: CustomEvent<{
		readonly snapshot: PayloadSnapshot;
	}>;
}

export class SnapshotManager {
	readonly eventTarget: EventTarget;
	readonly docId: string;
	private readonly interval: number;
	private readonly storage: IStorage;
	private readonly maxSnapshots: number;
	private contadorOperaciones: number = 0;
	private versionActual: number = 0;
	private datosActuales: Uint8Array | null = null;
	private readonly nodosConfirmados: Set<NodoId>;

	constructor(config: SnapshotManagerConfig) {
		this.eventTarget = new EventTarget();
		this.docId = config.docId;
		this.interval = config.interval ?? SNAPSHOT_POR_DEFECTO_CADA;
		this.storage = config.storage ?? new InMemoryStorage();
		this.maxSnapshots = config.maxSnapshots ?? 10;
		this.nodosConfirmados = new Set();
	}

	// ─── CREACION ────────────────────────────────────────────────────────

	incrementarOperaciones(): boolean {
		this.contadorOperaciones++;
		if (this.contadorOperaciones >= this.interval) {
			void this.crearSnapshot();
			return true;
		}
		return false;
	}

	async crearSnapshot(
		datos?: Uint8Array,
		nodos?: readonly NodoId[],
	): Promise<boolean> {
		if (datos !== undefined) {
			this.datosActuales = datos;
		}
		if (this.datosActuales === null) return false;

		this.versionActual++;

		if (nodos !== undefined) {
			this.nodosConfirmados.clear();
			for (const n of nodos) {
				this.nodosConfirmados.add(n);
			}
		}

		// Guardar snapshot
		const clave = `snapshot:${this.docId}:${this.versionActual}`;
		await this.storage.set(clave, {
			datos: this.datosActuales,
			version: this.versionActual,
			timestamp: Date.now(),
			nodos: Array.from(this.nodosConfirmados),
		});

		// Limpiar snapshots viejos
		await this.limpiarSnapshotsViejos();

		this.contadorOperaciones = 0;

		const metadata: SnapshotMetadata = {
			version: this.versionActual,
			timestamp: Date.now(),
			nodos: Array.from(this.nodosConfirmados),
			tamanio: this.datosActuales.length,
			hash: await this.calcularHash(this.datosActuales),
		};

		this.emit("snapshotCreado", { snapshot: metadata, docId: this.docId });
		return true;
	}

	// ─── RESTAURACION ────────────────────────────────────────────────────

	async restaurarSnapshot(version: number): Promise<Uint8Array | null> {
		const clave = `snapshot:${this.docId}:${version}`;
		const entry = await this.storage.get<{
			datos: Uint8Array;
			version: number;
		}>(clave);

		if (entry === null) return null;

		this.datosActuales = entry.valor.datos;
		this.versionActual = entry.valor.version;

		this.emit("snapshotRestaurado", { version, docId: this.docId });
		return this.datosActuales;
	}

	async restaurarUltimoSnapshot(): Promise<Uint8Array | null> {
		if (this.versionActual === 0) return null;
		return this.restaurarSnapshot(this.versionActual);
	}

	// ─── COMPARTIR ───────────────────────────────────────────────────────

	async prepararSnapshotCompartido(): Promise<PayloadSnapshot | null> {
		if (this.datosActuales === null) return null;

		const snapshot: PayloadSnapshot = {
			docId: this.docId,
			version: this.versionActual,
			datos: this.datosActuales,
			nodosConfirmados: Array.from(this.nodosConfirmados),
		};

		this.emit("snapshotCompartido", { snapshot });
		return snapshot;
	}

	async recibirSnapshot(snapshot: PayloadSnapshot): Promise<boolean> {
		if (snapshot.docId !== this.docId) return false;
		if (snapshot.version <= this.versionActual) return false;

		const clave = `snapshot:${this.docId}:${snapshot.version}`;
		await this.storage.set(clave, {
			datos: snapshot.datos,
			version: snapshot.version,
			timestamp: Date.now(),
			nodos: snapshot.nodosConfirmados,
		});

		this.datosActuales = snapshot.datos;
		this.versionActual = snapshot.version;
		this.nodosConfirmados.clear();
		for (const n of snapshot.nodosConfirmados) {
			this.nodosConfirmados.add(n);
		}

		this.emit("snapshotRestaurado", {
			version: snapshot.version,
			docId: this.docId,
		});

		return true;
	}

	// ─── CONFIRMACION ────────────────────────────────────────────────────

	confirmarNodo(nodoId: NodoId): void {
		this.nodosConfirmados.add(nodoId);
	}

	obtenerNodosConfirmados(): readonly NodoId[] {
		return Array.from(this.nodosConfirmados);
	}

	// ─── CONSULTAS ───────────────────────────────────────────────────────

	obtenerVersionActual(): number {
		return this.versionActual;
	}

	obtenerContadorOperaciones(): number {
		return this.contadorOperaciones;
	}

	async obtenerSnapshotsDisponibles(): Promise<readonly SnapshotMetadata[]> {
		const entries = await this.storage.list({
			prefijo: `snapshot:${this.docId}:`,
		});

		return entries.map((e) => {
			const valor = e.valor as {
				version: number;
				timestamp: number;
				nodos: NodoId[];
				datos: Uint8Array;
			};
			return {
				version: valor.version,
				timestamp: valor.timestamp,
				nodos: valor.nodos,
				tamanio: valor.datos.length,
				hash: "",
			} as SnapshotMetadata;
		});
	}

	// ─── LIMPIEZA ────────────────────────────────────────────────────────

	private async limpiarSnapshotsViejos(): Promise<void> {
		const disponibles = await this.obtenerSnapshotsDisponibles();
		if (disponibles.length <= this.maxSnapshots) return;

		const ordenados = [...disponibles].sort((a, b) => a.version - b.version);
		const aEliminar = ordenados.slice(0, ordenados.length - this.maxSnapshots);

		for (const snap of aEliminar) {
			const clave = `snapshot:${this.docId}:${snap.version}`;
			await this.storage.delete(clave);
		}
	}

	// ─── EVENTOS ─────────────────────────────────────────────────────────

	on<K extends keyof SnapshotEventMap>(
		tipo: K,
		handler: (ev: SnapshotEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof SnapshotEventMap>(
		tipo: K,
		handler: (ev: SnapshotEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof SnapshotEventMap>(
		tipo: K,
		detalle: SnapshotEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	// ─── UTILIDADES ──────────────────────────────────────────────────────

	private async calcularHash(datos: Uint8Array): Promise<string> {
		const hashBuffer = await crypto.subtle.digest(
			"SHA-256",
			datos.buffer as ArrayBuffer,
		);
		const hashArray = new Uint8Array(hashBuffer);
		return Array.from(hashArray)
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");
	}

	reiniciar(): void {
		this.contadorOperaciones = 0;
		this.versionActual = 0;
		this.datosActuales = null;
		this.nodosConfirmados.clear();
	}
}

// ─── FACTORY ───────────────────────────────────────────────────────────────

export function createSnapshotManager(
	config: SnapshotManagerConfig,
): SnapshotManager {
	return new SnapshotManager(config);
}
