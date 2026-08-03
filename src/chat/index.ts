// ─── CHAT P2P ────────────────────────────────────────────────────────────
// Canales de chat sincronizados via Yjs para comunicación en vivo entre peers.
// Soporta mensajes, historial persistente y estados de conexión.
//
// Para WorldExams: ExamenCompartido usa Yjs.Array para sincronizar preguntas
// y respuestas en vivo entre profesor y 50+ estudiantes.

import * as Y from "yjs";
import type { YjsAdapter } from "../edge-mesh.js";
import { generarId } from "../protocol/utils.js";
import { TokenBucketRateLimiter } from "../security/rate-limiter.js";
import type { NodoId } from "../types/index.js";
import {
	type ChatMessage,
	MeshPresence,
	type OfflineMessageQueue,
	PersistentOfflineQueue,
} from "./offline-queue.js";

// ─── CONST OBJECT PATTERNS ────────────────────────────────────────────────

export const TIPO_MENSAJE_CHAT = {
	TEXTO: "texto",
	SISTEMA: "sistema",
	ARCHIVO: "archivo",
	EXAMEN: "examen",
	SALON: "salon",
} as const;

export type TipoMensajeChat =
	(typeof TIPO_MENSAJE_CHAT)[keyof typeof TIPO_MENSAJE_CHAT];

export const TIPO_CANAL = {
	PUBLICO: "publico",
	PRIVADO: "privado",
	SALON_VIRTUAL: "salon_virtual",
} as const;

export type TipoCanal = (typeof TIPO_CANAL)[keyof typeof TIPO_CANAL];

export const TIPO_PREGUNTA = {
	OPCION_MULTIPLE: "opcion_multiple",
	VERDADERO_FALSO: "verdadero_falso",
	RESPUESTA_CORTA: "respuesta_corta",
	ENSAYO: "ensayo",
} as const;

export type TipoPregunta = (typeof TIPO_PREGUNTA)[keyof typeof TIPO_PREGUNTA];

// ─── TYPES ────────────────────────────────────────────────────────────────

export interface Mensaje {
	readonly id: string;
	readonly sender: string;
	readonly text: string;
	readonly timestamp: number;
	readonly type: TipoMensajeChat;
	readonly canal: string;
	readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface Pregunta {
	readonly id: string;
	readonly tipo: TipoPregunta;
	readonly enunciado: string;
	readonly opciones?: readonly string[];
	readonly respuestaCorrecta?: unknown;
	readonly puntaje: number;
}

export interface ChatEventMap {
	mensaje: CustomEvent<{ readonly mensaje: Mensaje }>;
	historial: CustomEvent<{ readonly mensajes: readonly Mensaje[] }>;
	usuarioConectado: CustomEvent<{
		readonly usuarioId: string;
		readonly canal: string;
	}>;
	usuarioDesconectado: CustomEvent<{
		readonly usuarioId: string;
		readonly canal: string;
	}>;
	error: CustomEvent<{ readonly mensaje: string; readonly error?: Error }>;
	rate_limited: CustomEvent<{
		readonly peerId: string;
		readonly resource: string;
	}>;
}

export interface ExamenEventMap {
	preguntaAgregada: CustomEvent<{ readonly pregunta: Pregunta }>;
	preguntaCambiada: CustomEvent<{
		readonly preguntaId: string;
		readonly cambios: Partial<Pregunta>;
	}>;
	respuestaNueva: CustomEvent<{
		readonly estudianteId: string;
		readonly preguntaId: string;
		readonly respuesta: unknown;
	}>;
	examenIniciado: CustomEvent<{ readonly examenId: string }>;
	examenFinalizado: CustomEvent<{ readonly examenId: string }>;
}

// ─── CHAT CHANNEL ─────────────────────────────────────────────────────────

export class ChatChannel extends EventTarget {
	readonly nodoId: NodoId;
	readonly nombreCanal: string;
	readonly tipoCanal: TipoCanal;
	readonly yjsAdapter: YjsAdapter;
	readonly offlineQueue?: OfflineMessageQueue;
	peerId?: string;
	private readonly yjsText: Y.Text;
	private readonly yjsMeta: Y.Map<unknown>;
	private readonly yjsUsuarios: Y.Array<unknown>;
	private readonly yjsMensajes: Y.Array<unknown>;
	private historialCache: Mensaje[] = [];
	private usuariosConectados: Set<string> = new Set();
	private readonly rateLimiter = new TokenBucketRateLimiter({
		tokensPerInterval: 10,
		intervalMs: 1000,
		maxTokens: 20,
	});

	constructor(
		nodoId: NodoId,
		nombreCanal: string,
		yjsAdapter: YjsAdapter,
		tipoCanal: TipoCanal = TIPO_CANAL.PUBLICO,
		offlineQueue?: OfflineMessageQueue,
	) {
		super();
		this.nodoId = nodoId;
		this.nombreCanal = nombreCanal;
		this.tipoCanal = tipoCanal;
		this.yjsAdapter = yjsAdapter;
		this.offlineQueue = offlineQueue;

		// Detect peerId for private channel
		if (tipoCanal === TIPO_CANAL.PRIVADO) {
			if (nombreCanal.startsWith("private:")) {
				this.peerId = nombreCanal.slice("private:".length);
			} else {
				this.peerId = nombreCanal;
			}
		}

		// Cada canal usa su propio namespace Yjs
		const prefijo = `chat:${nombreCanal}`;
		this.yjsText = this.yjsAdapter.getText(`${prefijo}:texto`);
		this.yjsMeta = this.yjsAdapter.getMap(`${prefijo}:meta`);
		this.yjsUsuarios = this.yjsAdapter.getArray(`${prefijo}:usuarios`);
		this.yjsMensajes = this.yjsAdapter.getArray(`${prefijo}:mensajes`);

		this.inicializar();

		if (this.offlineQueue instanceof PersistentOfflineQueue) {
			this.offlineQueue.registerChannel(
				this.nombreCanal,
				this.peerId ?? this.nombreCanal,
				async (msg) => {
					await this.enviarMensajeDirecto(msg);
				},
			);
		}
	}

	private inicializar(): void {
		// Escuchar cambios en los mensajes Yjs
		this.yjsMensajes.observe((_eventos) => {
			void this.actualizarDesdeYjs();
		});

		// Escuchar cambios en usuarios
		this.yjsUsuarios.observe((_eventos) => {
			void this.actualizarUsuarios();
		});

		// Cargar historial inicial
		void this.cargarHistorialInicial();
	}

	private async cargarHistorialInicial(): Promise<void> {
		const raw = this.yjsMensajes.toArray();
		const mensajes = raw
			.filter((m): m is Mensaje => esMensajeValido(m))
			.sort((a, b) => a.timestamp - b.timestamp);
		this.historialCache = mensajes;

		this.dispatchEvent(new CustomEvent("historial", { detail: { mensajes } }));
	}

	private async actualizarDesdeYjs(): Promise<void> {
		const raw = this.yjsMensajes.toArray();
		const mensajes = raw.filter((m): m is Mensaje => esMensajeValido(m));

		// Detectar nuevos mensajes
		if (mensajes.length > this.historialCache.length) {
			const nuevos = mensajes.slice(this.historialCache.length);
			for (const m of nuevos) {
				if (m.sender !== this.nodoId) {
					this.dispatchEvent(
						new CustomEvent("mensaje", { detail: { mensaje: m } }),
					);
				}
			}
		}

		this.historialCache = mensajes;
	}

	private async actualizarUsuarios(): Promise<void> {
		const usuariosActualesArr = this.yjsUsuarios.toArray() as string[];
		const usuariosActuales = new Set(usuariosActualesArr);

		// Detectar nuevos
		for (const uid of usuariosActualesArr) {
			if (uid !== this.nodoId && !this.usuariosConectados.has(uid)) {
				this.dispatchEvent(
					new CustomEvent("usuarioConectado", {
						detail: { usuarioId: uid, canal: this.nombreCanal },
					}),
				);
			}
		}

		// Detectar desconexiones
		for (const uid of this.usuariosConectados) {
			if (!usuariosActuales.has(uid)) {
				this.dispatchEvent(
					new CustomEvent("usuarioDesconectado", {
						detail: { usuarioId: uid, canal: this.nombreCanal },
					}),
				);
			}
		}

		this.usuariosConectados = usuariosActuales;
	}

	// ─── METODOS PUBLICOS ────────────────────────────────────────────────

	setPeerId(peerId: string): void {
		this.peerId = peerId;
		if (this.offlineQueue instanceof PersistentOfflineQueue) {
			this.offlineQueue.registerChannel(
				this.nombreCanal,
				peerId,
				async (msg) => {
					await this.enviarMensajeDirecto(msg);
				},
			);
		}
	}

	async enviarMensajeDirecto(mensaje: ChatMessage): Promise<void> {
		Y.transact(this.yjsAdapter.doc, () => {
			this.yjsMensajes.push([mensaje]);
			this.yjsText.insert(
				this.yjsText.length,
				`\n[${mensaje.sender}] ${mensaje.text}`,
			);
		});
	}

	async sendMessage(
		texto: string,
		tipo?: TipoMensajeChat,
		metadata?: Readonly<Record<string, unknown>>,
	): Promise<string> {
		if (!this.rateLimiter.consume(this.nodoId)) {
			console.warn(
				`Rate limit exceeded for peer: ${this.nodoId} in chat channel`,
			);
			this.dispatchEvent(
				new CustomEvent("rate_limited", {
					detail: { peerId: this.nodoId, resource: "chat" },
				}),
			);
			throw new Error("Rate limit exceeded");
		}

		const targetPeer =
			this.peerId ??
			(this.tipoCanal === TIPO_CANAL.PRIVADO ? this.nombreCanal : undefined);

		if (targetPeer && !MeshPresence.isOnline(targetPeer) && this.offlineQueue) {
			const mensaje: ChatMessage = {
				id: generarId(),
				sender: this.nodoId,
				text: texto,
				timestamp: Date.now(),
				type: tipo ?? TIPO_MENSAJE_CHAT.TEXTO,
				canal: this.nombreCanal,
				metadata,
			};
			await this.offlineQueue.enqueue(this.nombreCanal, mensaje);
			return mensaje.id;
		}

		const mensaje: ChatMessage = {
			id: generarId(),
			sender: this.nodoId,
			text: texto,
			timestamp: Date.now(),
			type: tipo ?? TIPO_MENSAJE_CHAT.TEXTO,
			canal: this.nombreCanal,
			metadata,
		};

		return Y.transact(this.yjsAdapter.doc, () => {
			this.yjsMensajes.push([mensaje]);
			// También actualizar el Y.Text para sincronización en vivo
			this.yjsText.insert(
				this.yjsText.length,
				`\n[${mensaje.sender}] ${mensaje.text}`,
			);
			return mensaje.id;
		});
	}

	async enviarMensaje(
		texto: string,
		tipo?: TipoMensajeChat,
		metadata?: Readonly<Record<string, unknown>>,
	): Promise<string> {
		return this.sendMessage(texto, tipo, metadata);
	}

	async unirseAlCanal(): Promise<void> {
		const yaEnLista = this.yjsUsuarios.toArray().includes(this.nodoId);
		if (!yaEnLista) {
			Y.transact(this.yjsAdapter.doc, () => {
				this.yjsUsuarios.push([this.nodoId]);
			});
		}
		this.usuariosConectados.add(this.nodoId);
	}

	async abandonarCanal(): Promise<void> {
		const idx = this.yjsUsuarios.toArray().indexOf(this.nodoId);
		if (idx !== -1) {
			Y.transact(this.yjsAdapter.doc, () => {
				this.yjsUsuarios.delete(idx, 1);
			});
		}
		this.usuariosConectados.delete(this.nodoId);
	}

	async obtenerHistorial(limite?: number): Promise<readonly Mensaje[]> {
		const raw = this.yjsMensajes.toArray();
		const mensajes = raw
			.filter((m): m is Mensaje => esMensajeValido(m))
			.sort((a, b) => a.timestamp - b.timestamp);

		if (limite !== undefined && limite > 0) {
			return mensajes.slice(-limite);
		}
		return mensajes;
	}

	obtenerUsuariosConectados(): readonly string[] {
		return Array.from(this.usuariosConectados) as string[];
	}

	async limpiarHistorial(): Promise<void> {
		Y.transact(this.yjsAdapter.doc, () => {
			const len = this.yjsMensajes.length;
			if (len > 0) {
				this.yjsMensajes.delete(0, len);
			}
			this.yjsText.delete(0, this.yjsText.length);
		});
		this.historialCache = [];
	}
}

// ─── EXAMEN COMPARTIDO ────────────────────────────────────────────────────
// Para WorldExams: examen compartido via Yjs.Array con sincronización en vivo.
// Profesor carga preguntas, estudiantes responden, todos ven los cambios.

export class ExamenCompartido extends EventTarget {
	readonly examenId: string;
	readonly yjsAdapter: YjsAdapter;
	private readonly yjsPreguntas: Y.Array<unknown>;
	private readonly yjsRespuestas: Y.Map<unknown>;
	private readonly yjsEstado: Y.Map<unknown>;
	private cachePreguntas: Pregunta[] = [];
	private cacheRespuestas: Map<string, unknown> = new Map();

	constructor(examenId: string, yjsAdapter: YjsAdapter) {
		super();
		this.examenId = examenId;
		this.yjsAdapter = yjsAdapter;

		const prefijo = `examen:${examenId}`;
		this.yjsPreguntas = this.yjsAdapter.getArray(`${prefijo}:preguntas`);
		this.yjsRespuestas = this.yjsAdapter.getMap(`${prefijo}:respuestas`);
		this.yjsEstado = this.yjsAdapter.getMap(`${prefijo}:estado`);

		this.inicializar();
	}

	private inicializar(): void {
		this.yjsPreguntas.observe((_eventos) => {
			void this.sincronizarPreguntas();
		});

		this.yjsRespuestas.observe((eventos) => {
			for (const [clave, _valor] of eventos.changes.keys) {
				const partes = clave.split(":");
				if (partes.length === 2) {
					const [estudianteId, preguntaId] = partes;
					const respuesta = this.yjsRespuestas.get(clave);
					this.cacheRespuestas.set(clave, respuesta);
					this.dispatchEvent(
						new CustomEvent("respuestaNueva", {
							detail: { estudianteId, preguntaId, respuesta },
						}),
					);
				}
			}
		});
	}

	private async sincronizarPreguntas(): Promise<void> {
		const raw = this.yjsPreguntas.toArray();
		const preguntas = raw.filter((p): p is Pregunta => esPreguntaValida(p));

		const nuevas = preguntas.filter(
			(p) => !this.cachePreguntas.some((cp) => cp.id === p.id),
		);

		const cambiadas = preguntas.filter((p) => {
			const existente = this.cachePreguntas.find((cp) => cp.id === p.id);
			if (existente === undefined) return false;
			return JSON.stringify(existente) !== JSON.stringify(p);
		});

		this.cachePreguntas = preguntas;

		for (const p of nuevas) {
			this.dispatchEvent(
				new CustomEvent("preguntaAgregada", { detail: { pregunta: p } }),
			);
		}

		for (const p of cambiadas) {
			this.dispatchEvent(
				new CustomEvent("preguntaCambiada", {
					detail: { preguntaId: p.id, cambios: p },
				}),
			);
		}
	}

	// ─── METODOS PUBLICOS ────────────────────────────────────────────────

	async cargarPreguntas(preguntas: readonly Pregunta[]): Promise<void> {
		Y.transact(this.yjsAdapter.doc, () => {
			// Limpiar preguntas existentes
			const len = this.yjsPreguntas.length;
			if (len > 0) {
				this.yjsPreguntas.delete(0, len);
			}
			// Cargar nuevas preguntas
			this.yjsPreguntas.push([...preguntas]);
		});
	}

	async agregarPregunta(pregunta: Pregunta): Promise<void> {
		Y.transact(this.yjsAdapter.doc, () => {
			this.yjsPreguntas.push([pregunta]);
		});
	}

	async actualizarPregunta(
		preguntaId: string,
		cambios: Partial<Pregunta>,
	): Promise<void> {
		const raw = this.yjsPreguntas.toArray();
		const idx = raw.findIndex(
			(p): p is Pregunta => esPreguntaValida(p) && p.id === preguntaId,
		);

		if (idx === -1) return;

		Y.transact(this.yjsAdapter.doc, () => {
			// Mezclar pregunta existente con cambios
			const existente = raw[idx] as Pregunta;
			const actualizada = { ...existente, ...cambios };
			this.yjsPreguntas.delete(idx, 1);
			this.yjsPreguntas.insert(idx, [actualizada]);
		});
	}

	async enviarRespuesta(
		estudianteId: string,
		preguntaId: string,
		respuesta: unknown,
	): Promise<void> {
		const clave = `${estudianteId}:${preguntaId}`;
		Y.transact(this.yjsAdapter.doc, () => {
			this.yjsRespuestas.set(clave, respuesta);
		});
	}

	async obtenerRespuestas(): Promise<ReadonlyMap<string, unknown>> {
		const respuestas = new Map<string, unknown>();
		for (const [clave, valor] of this.yjsRespuestas) {
			respuestas.set(clave, valor);
		}
		return respuestas;
	}

	async obtenerRespuestasDeEstudiante(
		estudianteId: string,
	): Promise<ReadonlyMap<string, unknown>> {
		const respuestas = new Map<string, unknown>();
		for (const [clave, valor] of this.yjsRespuestas) {
			if (clave.startsWith(`${estudianteId}:`)) {
				const preguntaId = clave.slice(estudianteId.length + 1);
				respuestas.set(preguntaId, valor);
			}
		}
		return respuestas;
	}

	obtenerPreguntas(): readonly Pregunta[] {
		return [...this.cachePreguntas];
	}

	async iniciarExamen(): Promise<void> {
		Y.transact(this.yjsAdapter.doc, () => {
			this.yjsEstado.set("estado", "iniciado");
			this.yjsEstado.set("inicioTimestamp", Date.now());
		});
		this.dispatchEvent(
			new CustomEvent("examenIniciado", {
				detail: { examenId: this.examenId },
			}),
		);
	}

	async finalizarExamen(): Promise<void> {
		Y.transact(this.yjsAdapter.doc, () => {
			this.yjsEstado.set("estado", "finalizado");
			this.yjsEstado.set("finTimestamp", Date.now());
		});
		this.dispatchEvent(
			new CustomEvent("examenFinalizado", {
				detail: { examenId: this.examenId },
			}),
		);
	}

	async obtenerEstado(): Promise<Record<string, unknown>> {
		const estado: Record<string, unknown> = {};
		for (const [clave, valor] of this.yjsEstado) {
			estado[clave as string] = valor;
		}
		return estado;
	}
}

// ─── TYPE GUARDS ──────────────────────────────────────────────────────────

function esMensajeValido(valor: unknown): valor is Mensaje {
	if (typeof valor !== "object" || valor === null) return false;
	const m = valor as Record<string, unknown>;
	return (
		typeof m.id === "string" &&
		typeof m.sender === "string" &&
		typeof m.text === "string" &&
		typeof m.timestamp === "number" &&
		typeof m.type === "string"
	);
}

function esPreguntaValida(valor: unknown): valor is Pregunta {
	if (typeof valor !== "object" || valor === null) return false;
	const p = valor as Record<string, unknown>;
	return (
		typeof p.id === "string" &&
		typeof p.tipo === "string" &&
		typeof p.enunciado === "string" &&
		typeof p.puntaje === "number"
	);
}

export * from "./offline-queue.js";
