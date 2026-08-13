import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	NAMESPACE_POR_DEFECTO,
	NamespaceManager,
} from "../../src/namespaces/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("NamespaceManager", () => {
	let manager: NamespaceManager;

	beforeEach(() => {
		manager = new NamespaceManager();
	});

	it("debería tener el namespace por defecto al inicio", () => {
		const espacios = manager.obtenerTodosLosEspacios();
		expect(espacios.length).toBe(1);
		expect(espacios[0].nombre).toBe(NAMESPACE_POR_DEFECTO);
	});

	it("debería crear un nuevo espacio", () => {
		const nombre = "test-space";
		const metadatos = { descripcion: "espacio de prueba" };
		const espacio = manager.crearEspacio(nombre, metadatos);

		expect(espacio.nombre).toBe(nombre);
		expect(espacio.metadatos).toEqual(metadatos);
		expect(manager.obtenerEspacio(espacio.id)).toEqual(espacio);
		expect(manager.obtenerEspacioPorNombre(nombre)).toEqual(espacio);
	});

	it("debería evitar eliminar el namespace por defecto", () => {
		const global = manager.obtenerEspacioPorNombre(NAMESPACE_POR_DEFECTO);
		expect(global).not.toBeNull();

		const eliminado = manager.eliminarEspacio(global!.id);
		expect(eliminado).toBe(false);
		expect(
			manager.obtenerEspacioPorNombre(NAMESPACE_POR_DEFECTO),
		).not.toBeNull();
	});

	it("debería permitir unir y abandonar nodos", () => {
		const espacio = manager.crearEspacio("test");
		const nodoId = "peer-1" as NodoId;

		manager.unirNodo(espacio.id, nodoId);
		expect(manager.obtenerNodosEnEspacio("test")).toContain(nodoId);
		expect(manager.obtenerEspaciosDeNodo(nodoId)).toContainEqual(
			expect.objectContaining({ nombre: "test" }),
		);

		manager.abandonarNodo(espacio.id, nodoId);
		expect(manager.obtenerNodosEnEspacio("test")).not.toContain(nodoId);
	});

	it("debería disparar eventos al crear/eliminar espacios", () => {
		const creadoListener = vi.fn();
		const eliminadoListener = vi.fn();

		manager.on("espacioCreado", creadoListener as EventListener);
		manager.on("espacioEliminado", eliminadoListener as EventListener);

		const espacio = manager.crearEspacio("event-test");
		expect(creadoListener).toHaveBeenCalled();
		expect(creadoListener.mock.calls[0][0].detail.espacio.nombre).toBe(
			"event-test",
		);

		manager.eliminarEspacio(espacio.id);
		expect(eliminadoListener).toHaveBeenCalled();
		expect(eliminadoListener.mock.calls[0][0].detail.id).toBe(espacio.id);
	});

	it("debería disparar eventos al unir/abandonar nodos", () => {
		const unidoListener = vi.fn();
		const abandonoListener = vi.fn();

		manager.on("nodoUnido", unidoListener as EventListener);
		manager.on("nodoAbandono", abandonoListener as EventListener);

		const espacio = manager.crearEspacio("nodes-test");
		const nodoId = "peer-2" as NodoId;

		manager.unirNodo(espacio.id, nodoId);
		expect(unidoListener).toHaveBeenCalled();
		expect(unidoListener.mock.calls[0][0].detail.nodoId).toBe(nodoId);

		manager.abandonarNodo(espacio.id, nodoId);
		expect(abandonoListener).toHaveBeenCalled();
		expect(abandonoListener.mock.calls[0][0].detail.nodoId).toBe(nodoId);
	});

	it("debería detectar duplicados al unir nodos", () => {
		const espacio = manager.crearEspacio("dup-test");
		const nodoId = "peer-1" as NodoId;

		manager.unirNodo(espacio.id, nodoId);
		manager.unirNodo(espacio.id, nodoId); // duplicado

		expect(manager.obtenerNodosEnEspacio("dup-test").length).toBe(1);
	});

	it("debería garantizar el aislamiento de namespaces", () => {
		const espacioA = manager.crearEspacio("espacio-A");
		const espacioB = manager.crearEspacio("espacio-B");
		const nodoId = "peer-1" as NodoId;

		manager.unirNodo(espacioA.id, nodoId);

		// El nodo debe estar en espacioA, pero no en espacioB
		expect(manager.obtenerNodosEnEspacio("espacio-A")).toContain(nodoId);
		expect(manager.obtenerNodosEnEspacio("espacio-B")).not.toContain(nodoId);

		// Las búsquedas por nodo deben devolver solo el espacio en el que está unido
		const espaciosDeNodo = manager.obtenerEspaciosDeNodo(nodoId);
		expect(espaciosDeNodo.some((e) => e.nombre === "espacio-A")).toBe(true);
		expect(espaciosDeNodo.some((e) => e.nombre === "espacio-B")).toBe(false);
	});
});
