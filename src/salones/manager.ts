// ─── SALON VIRTUAL ───────────────────────────────────────────────────────
// Un salón virtual es un namespace + canal de chat + Yjs doc compartido.
// Todo sincronizado en el mesh. Escalable a 50+ personas gracias al
// fan-out limitado del mesh manager.

import * as Y from "yjs";
import { ChatChannel, type Mensaje, TIPO_CANAL } from "../chat/index.js";
import type { EdgeMesh, YjsAdapter } from "../edge-mesh.js";
import { generarId } from "../protocol/utils.js";
import type { NodoId } from "../types/index.js";

// ─── CONST OBJECT PATTERNS ────────────────────────────────────────────────

export const TIPO_SALON = {
	EXAMEN: "examen",
	REUNION: "reunion",
	CHAT: "chat",
} as const;

export type TipoSalon = (typeof TIPO_SALON)[keyof typeof TIPO_SALON];

export const ESTADO_SALON = {
	CREANDO: "creando",
	ACTIVO: "activo",
	CERRADO: "cerrado",
} as const;

export type EstadoSalon = (typeof ESTADO_SALON)[keyof typeof ESTADO_SALON];

// ─── TYPES ────────────────────────────────────────────────────────────────

export interface SalonConfig {
	readonly creatorId: NodoId;
	readonly nombre: string;
	readonly tipo: TipoSalon;
	readonly maxParticipantes: number;
	readonly yjsAdapter: YjsAdapter;
	readonly edgeMesh: EdgeMesh;
}

export interface SalonInfo {
	readonly id: string;
	readonly nombre: string;
	readonly tipo: TipoSalon;
	readonly creador: NodoId;
	readonly fechaCreacion: number;
	readonly estado: EstadoSalon;
	readonly participantes: readonly string[];
	readonly maxParticipantes: number;
}

export interface SalonEventMap {
	participanteUnido: CustomEvent<{
		readonly salonId: string;
		readonly participanteId: string;
	}>;
	participanteSalio: CustomEvent<{
		readonly salonId: string;
		readonly participanteId: string;
	}>;
	mensaje: CustomEvent<{ readonly salonId: string; readonly mensaje: Mensaje }>;
	contenidoSincronizado: CustomEvent<{
		readonly salonId: string;
		readonly docId: string;
	}>;
	estadoCambiado: CustomEvent<{
		readonly salonId: string;
		readonly estado: EstadoSalon;
	}>;
	error: CustomEvent<{
		readonly salonId: string;
		readonly mensaje: string;
		readonly error?: Error;
	}>;
}

// ─── SALON VIRTUAL ────────────────────────────────────────────────────────

export class SalonVirtual extends EventTarget {
	readonly id: string;
	readonly config: SalonConfig;
	readonly edgeMesh: EdgeMesh;
	readonly yjsAdapter: YjsAdapter;
	readonly chatChannel: ChatChannel;
	private _estado: EstadoSalon = ESTADO_SALON.CREANDO;
	private readonly salonDoc: Y.Doc;
	private readonly salonMap: Y.Map<unknown>;
	private readonly salonParticipantes: Y.Array<string>;
	private readonly salonContenido: Y.Map<unknown>;

	constructor(config: SalonConfig) {
		super();
		this.id = generarId();
		this.config = config;
		this.edgeMesh = config.edgeMesh;
		this.yjsAdapter = config.yjsAdapter;
		this.salonDoc = new Y.Doc();

		// Crear tipos Yjs para el salón
		this.salonMap = this.salonDoc.getMap(`salon:${this.id}:info`);
		this.salonParticipantes = this.salonDoc.getArray(
			`salon:${this.id}:participantes`,
		);
		this.salonContenido = this.salonDoc.getMap(`salon:${this.id}:contenido`);

		// Crear canal de chat propio del salón
		this.chatChannel = new ChatChannel(
			config.creatorId,
			`salon:${this.id}`,
			this.yjsAdapter,
			TIPO_CANAL.SALON_VIRTUAL,
			config.edgeMesh.offlineQueue,
		);

		// Inicializar metadata del salón
		Y.transact(this.salonDoc, () => {
			this.salonMap.set("id", this.id);
			this.salonMap.set("nombre", config.nombre);
			this.salonMap.set("tipo", config.tipo);
			this.salonMap.set("creador", config.creatorId);
			this.salonMap.set("fechaCreacion", Date.now());
			this.salonMap.set("estado", ESTADO_SALON.ACTIVO);
			this.salonMap.set("maxParticipantes", config.maxParticipantes);
		});

		// Re-enviar eventos del chat
		this.chatChannel.addEventListener("mensaje", ((ev: Event) => {
			const customEv = ev as CustomEvent<{ mensaje: Mensaje }>;
			this.dispatchEvent(
				new CustomEvent("mensaje", {
					detail: { salonId: this.id, mensaje: customEv.detail.mensaje },
				}),
			);
		}) as EventListener);

		// Observar cambios en participantes
		this.salonParticipantes.observe(() => {
			void this.notificarParticipantes();
		});

		this._estado = ESTADO_SALON.ACTIVO;
	}

	private async notificarParticipantes(): Promise<void> {
		const participantes = this.salonParticipantes.toArray();
		// El ChatChannel ya maneja los eventos usuarioConectado/usuarioDesconectado
	}

	// ─── METODOS PUBLICOS ────────────────────────────────────────────────

	async unirse(participanteId: NodoId): Promise<void> {
		if (this._estado !== ESTADO_SALON.ACTIVO) {
			throw new Error(
				`Salon ${this.id} no esta activo (estado: ${this._estado})`,
			);
		}

		const participantes = this.salonParticipantes.toArray();
		if (participantes.length >= this.config.maxParticipantes) {
			throw new Error(
				`Salon ${this.id} ha alcanzado el maximo de ${this.config.maxParticipantes} participantes`,
			);
		}

		if (participantes.includes(participanteId)) return; // Ya unido

		Y.transact(this.salonDoc, () => {
			this.salonParticipantes.push([participanteId]);
		});

		// Unir al canal de chat del salón
		await this.chatChannel.unirseAlCanal();

		this.dispatchEvent(
			new CustomEvent("participanteUnido", {
				detail: { salonId: this.id, participanteId },
			}),
		);

		// Notificar sincronización de contenido
		this.dispatchEvent(
			new CustomEvent("contenidoSincronizado", {
				detail: { salonId: this.id, docId: `salon:${this.id}` },
			}),
		);
	}

	async abandonar(participanteId: NodoId): Promise<void> {
		const idx = this.salonParticipantes.toArray().indexOf(participanteId);
		if (idx !== -1) {
			Y.transact(this.salonDoc, () => {
				this.salonParticipantes.delete(idx, 1);
			});
		}

		await this.chatChannel.abandonarCanal();

		this.dispatchEvent(
			new CustomEvent("participanteSalio", {
				detail: { salonId: this.id, participanteId },
			}),
		);
	}

	async obtenerParticipantes(): Promise<readonly string[]> {
		return this.salonParticipantes.toArray();
	}

	async enviarMensaje(texto: string): Promise<void> {
		await this.chatChannel.enviarMensaje(texto);
	}

	async cerrar(): Promise<void> {
		this._estado = ESTADO_SALON.CERRADO;

		Y.transact(this.salonDoc, () => {
			this.salonMap.set("estado", ESTADO_SALON.CERRADO);
			// Limpiar participantes
			const len = this.salonParticipantes.length;
			if (len > 0) {
				this.salonParticipantes.delete(0, len);
			}
		});

		await this.chatChannel.abandonarCanal();
		this.salonDoc.destroy();

		this.dispatchEvent(
			new CustomEvent("estadoCambiado", {
				detail: { salonId: this.id, estado: ESTADO_SALON.CERRADO },
			}),
		);
	}

	async compartirContenido(clave: string, valor: unknown): Promise<void> {
		Y.transact(this.salonDoc, () => {
			this.salonContenido.set(clave, valor);
		});
	}

	async obtenerContenido(): Promise<ReadonlyMap<string, unknown>> {
		const contenido = new Map<string, unknown>();
		for (const [clave, valor] of this.salonContenido) {
			contenido.set(clave, valor);
		}
		return contenido;
	}

	obtenerEstado(): EstadoSalon {
		return this._estado;
	}

	obtenerInfo(): SalonInfo {
		return {
			id: this.id,
			nombre: this.config.nombre,
			tipo: this.config.tipo,
			creador: this.config.creatorId,
			fechaCreacion: this.salonMap.get("fechaCreacion") as number,
			estado: this._estado,
			participantes: this.salonParticipantes.toArray(),
			maxParticipantes: this.config.maxParticipantes,
		};
	}
}

// ─── SALONES MANAGER ───────────────────────────────────────────────────────
// Manager global de salones. Orquesta todos los salones activos.

export class SalonesManager {
	private readonly edgeMesh: EdgeMesh;
	private readonly salones: Map<string, SalonVirtual>;
	private readonly creadorPorSalon: Map<string, NodoId>;
	private readonly yjsAdapter: YjsAdapter;

	constructor(edgeMesh: EdgeMesh) {
		this.edgeMesh = edgeMesh;
		this.salones = new Map();
		this.creadorPorSalon = new Map();
		this.yjsAdapter = edgeMesh.yjsAdapter;
	}

	// ─── CREACION ────────────────────────────────────────────────────────

	async crearSalon(
		nombre: string,
		tipo?: TipoSalon,
		maxParticipantes?: number,
	): Promise<SalonVirtual> {
		const config: SalonConfig = {
			creatorId: this.edgeMesh.config.nodoId,
			nombre,
			tipo: tipo ?? TIPO_SALON.CHAT,
			maxParticipantes: maxParticipantes ?? 50,
			yjsAdapter: this.yjsAdapter,
			edgeMesh: this.edgeMesh,
		};

		const salon = new SalonVirtual(config);
		this.salones.set(salon.id, salon);
		this.creadorPorSalon.set(salon.id, this.edgeMesh.config.nodoId);

		// El creador se une automáticamente
		await salon.unirse(this.edgeMesh.config.nodoId);

		return salon;
	}

	// ─── UNION ───────────────────────────────────────────────────────────

	async unirseSalon(salonId: string): Promise<SalonVirtual> {
		const salon = this.salones.get(salonId);
		if (salon === undefined) {
			throw new Error(`Salon ${salonId} no encontrado`);
		}

		await salon.unirse(this.edgeMesh.config.nodoId);
		return salon;
	}

	// ─── ABANDONAR ───────────────────────────────────────────────────────

	async abandonarSalon(salonId: string): Promise<void> {
		const salon = this.salones.get(salonId);
		if (salon === undefined) return;

		await salon.abandonar(this.edgeMesh.config.nodoId);
	}

	// ─── CERRAR ──────────────────────────────────────────────────────────

	async cerrarSalon(salonId: string): Promise<void> {
		const salon = this.salones.get(salonId);
		if (salon === undefined) {
			throw new Error(`Salon ${salonId} no encontrado`);
		}

		const creador = this.creadorPorSalon.get(salonId);
		if (creador !== this.edgeMesh.config.nodoId) {
			throw new Error(`Solo el creador puede cerrar el salon ${salonId}`);
		}

		await salon.cerrar();
		this.salones.delete(salonId);
		this.creadorPorSalon.delete(salonId);
	}

	// ─── CONSULTAS ───────────────────────────────────────────────────────

	listarSalones(): readonly SalonVirtual[] {
		return Array.from(this.salones.values());
	}

	obtenerSalon(salonId: string): SalonVirtual | null {
		return this.salones.get(salonId) ?? null;
	}

	obtenerSalonesActivos(): readonly SalonVirtual[] {
		return Array.from(this.salones.values()).filter(
			(s) => s.obtenerEstado() === ESTADO_SALON.ACTIVO,
		);
	}

	obtenerTotalSalones(): number {
		return this.salones.size;
	}

	// ─── LIMPIEZA ────────────────────────────────────────────────────────

	async cerrarTodosLosSalones(): Promise<void> {
		for (const [id, _salon] of this.salones) {
			const salon = this.salones.get(id)!;
			await salon.cerrar();
		}
		this.salones.clear();
		this.creadorPorSalon.clear();
	}
}
