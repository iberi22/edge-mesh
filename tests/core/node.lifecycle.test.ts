import { describe, expect, it, vi } from "vitest";
import { createEdgeMeshNode } from "../../src/core/node.js";
import type { EstadoNodo, NodoId } from "../../src/types/index.js";

describe("DefaultEdgeMeshNode Lifecycle & Communication", () => {
	it("should transition states correctly on conectar: offline -> conectando -> online", async () => {
		const nodoId = "test-node-1" as NodoId;
		const node = createEdgeMeshNode(nodoId);

		const estados: EstadoNodo[] = [];
		node.on("estadoCambiado", (ev) => {
			estados.push(ev.detail.estadoNuevo);
		});

		expect(node.estado).toBe("offline");

		await node.conectar();

		expect(node.estado).toBe("online");
		expect(estados).toEqual(["conectando", "online"]);
	});

	it("should emit CustomEvent with correct detail on enviar()", async () => {
		const nodoId = "node-sender" as NodoId;
		const targetId = "node-receiver" as NodoId;
		const node = createEdgeMeshNode(nodoId);

		const enviarHandler = vi.fn();
		node.on("enviar", enviarHandler);

		const payload = { data: "hello direct" };
		await node.enviar(targetId, payload);

		expect(enviarHandler).toHaveBeenCalledTimes(1);
		const event = enviarHandler.mock.calls[0][0];
		expect(event.detail).toEqual({
			destino: targetId,
			payload,
		});
	});

	it("should emit CustomEvent with correct detail on transmitir()", async () => {
		const nodoId = "node-broadcaster" as NodoId;
		const node = createEdgeMeshNode(nodoId);

		const transmitirHandler = vi.fn();
		node.on("transmitir", transmitirHandler);

		const payload = { broadcast: "hello mesh" };
		await node.transmitir(payload);

		expect(transmitirHandler).toHaveBeenCalledTimes(1);
		const event = transmitirHandler.mock.calls[0][0];
		expect(event.detail).toEqual({ payload });
	});

	it("should be idempotent when conectar() is called multiple times when already online", async () => {
		const nodoId = "node-idempotent" as NodoId;
		const node = createEdgeMeshNode(nodoId);

		const estadoHandler = vi.fn();
		node.on("estadoCambiado", estadoHandler);

		await node.conectar();
		expect(node.estado).toBe("online");
		const callCountAfterFirstConnect = estadoHandler.mock.calls.length;

		// Second call when already online
		await node.conectar();
		expect(node.estado).toBe("online");
		expect(estadoHandler.mock.calls.length).toBe(callCountAfterFirstConnect);
	});

	it("should be a no-op when desconectar() is called while already offline", async () => {
		const nodoId = "node-offline" as NodoId;
		const node = createEdgeMeshNode(nodoId);

		const estadoHandler = vi.fn();
		const desconectadoHandler = vi.fn();

		node.on("estadoCambiado", estadoHandler);
		node.on("nodoDesconectado", desconectadoHandler);

		expect(node.estado).toBe("offline");

		await node.desconectar();

		expect(node.estado).toBe("offline");
		expect(estadoHandler).not.toHaveBeenCalled();
		expect(desconectadoHandler).not.toHaveBeenCalled();
	});
});
