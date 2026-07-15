import { generarNonce } from "../protocol/utils.js";
import type { NamespacePartition, NodoId } from "../types/index.js";

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

export const NAMESPACE_POR_DEFECTO = "global" as const;

// ─── NAMESPACE MANAGER ─────────────────────────────────────────────────────

export interface NamespaceEventMap {
	espacioCreado: CustomEvent<{ readonly espacio: NamespacePartition }>;
	espacioEliminado: CustomEvent<{ readonly id: string }>;
	nodoUnido: CustomEvent<{
		readonly espacio: string;
		readonly nodoId: NodoId;
	}>;
	nodoAbandono: CustomEvent<{
		readonly espacio: string;
		readonly nodoId: NodoId;
	}>;
}

export class NamespaceManager {
	readonly eventTarget: EventTarget = new EventTarget();
	private readonly espacios: Map<string, NamespacePartition> = new Map();

	constructor() {
		// Crear el namespace global por defecto
		this.crearEspacioInterno(NAMESPACE_POR_DEFECTO);
	}

	// ─── CREACION ────────────────────────────────────────────────────────

	crearEspacio(
		nombre: string,
		metadatos: Readonly<Record<string, string>> = {},
	): NamespacePartition {
		return this.crearEspacioInterno(nombre, metadatos);
	}

	private crearEspacioInterno(
		nombre: string,
		metadatos: Readonly<Record<string, string>> = {},
	): NamespacePartition {
		const id = generarNonce();
		const espacio: NamespacePartition = {
			id,
			nombre,
			nodos: [],
			fechaCreacion: Date.now(),
			metadatos,
		};
		this.espacios.set(id, espacio);

		this.emit("espacioCreado", { espacio });
		return espacio;
	}

	eliminarEspacio(id: string): boolean {
		const espacio = this.espacios.get(id);
		if (espacio === undefined) return false;
		if (espacio.nombre === NAMESPACE_POR_DEFECTO) return false;

		this.espacios.delete(id);
		this.emit("espacioEliminado", { id });
		return true;
	}

	// ─── MEMBRESIA ───────────────────────────────────────────────────────

	unirNodo(espacioId: string, nodoId: NodoId): boolean {
		const espacio = this.espacios.get(espacioId);
		if (espacio === undefined) return false;

		if (espacio.nodos.includes(nodoId)) return true;

		const nuevosNodos = [...espacio.nodos, nodoId];
		this.espacios.set(espacioId, { ...espacio, nodos: nuevosNodos });

		this.emit("nodoUnido", { espacio: espacio.nombre, nodoId });
		return true;
	}

	abandonarNodo(espacioId: string, nodoId: NodoId): boolean {
		const espacio = this.espacios.get(espacioId);
		if (espacio === undefined) return false;

		if (!espacio.nodos.includes(nodoId)) return false;

		const nuevosNodos = espacio.nodos.filter((n) => n !== nodoId);
		this.espacios.set(espacioId, { ...espacio, nodos: nuevosNodos });

		this.emit("nodoAbandono", { espacio: espacio.nombre, nodoId });
		return true;
	}

	// ─── CONSULTAS ───────────────────────────────────────────────────────

	obtenerEspacio(id: string): NamespacePartition | null {
		return this.espacios.get(id) ?? null;
	}

	obtenerEspacioPorNombre(nombre: string): NamespacePartition | null {
		for (const espacio of this.espacios.values()) {
			if (espacio.nombre === nombre) return espacio;
		}
		return null;
	}

	obtenerTodosLosEspacios(): readonly NamespacePartition[] {
		return Array.from(this.espacios.values());
	}

	obtenerNodosEnEspacio(nombre: string): readonly NodoId[] {
		const espacio = this.obtenerEspacioPorNombre(nombre);
		return espacio?.nodos ?? [];
	}

	obtenerEspaciosDeNodo(nodoId: NodoId): readonly NamespacePartition[] {
		return Array.from(this.espacios.values()).filter((e) =>
			e.nodos.includes(nodoId),
		);
	}

	// ─── EVENTOS ─────────────────────────────────────────────────────────

	on<K extends keyof NamespaceEventMap>(
		tipo: K,
		handler: (ev: NamespaceEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof NamespaceEventMap>(
		tipo: K,
		handler: (ev: NamespaceEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof NamespaceEventMap>(
		tipo: K,
		detalle: NamespaceEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	reiniciar(): void {
		this.espacios.clear();
		this.crearEspacioInterno(NAMESPACE_POR_DEFECTO);
	}
}
