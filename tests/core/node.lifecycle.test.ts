import { describe, expect, it, vi } from "vitest";
import { DefaultEdgeMeshNode } from "../../src/core/DefaultEdgeMeshNode.js";
import { createEdgeMeshNode } from "../../src/core/node.js";
import type { NodoId } from "../../src/types/index.js";

vi.mock("idb", () => ({
	openDB: vi.fn(),
}));

describe("DefaultEdgeMeshNode lifecycle & events", () => {
	const mockNodoId = "nodo-lifecycle-1" as NodoId;

	describe("idempotent conectar", () => {
		it("should connect once and be idempotent when called multiple times", async () => {
			const node = new DefaultEdgeMeshNode(mockNodoId);
			const conectadoSpy = vi.fn();
			const estadoSpy = vi.fn();

			node.on("nodoConectado", conectadoSpy);
			node.on("estadoCambiado", estadoSpy);

			await node.conectar();
			expect(node.estado).toBe("online");
			expect(conectadoSpy).toHaveBeenCalledTimes(1);
			expect(estadoSpy).toHaveBeenCalledTimes(2); // offline -> conectando -> online

			// Calling conectar again when already online should do nothing
			await node.conectar();
			expect(node.estado).toBe("online");
			expect(conectadoSpy).toHaveBeenCalledTimes(1);
			expect(estadoSpy).toHaveBeenCalledTimes(2);
		});

		it("should be idempotent when desconectar is called multiple times", async () => {
			const node = createEdgeMeshNode(mockNodoId);
			const desconectadoSpy = vi.fn();

			node.on("nodoDesconectado", desconectadoSpy);

			await node.conectar();
			await node.desconectar();
			expect(node.estado).toBe("offline");
			expect(desconectadoSpy).toHaveBeenCalledTimes(1);

			// Second desconectar call
			await node.desconectar();
			expect(node.estado).toBe("offline");
			expect(desconectadoSpy).toHaveBeenCalledTimes(1);
		});
	});

	describe("message emission via CustomEvent", () => {
		it("should emit CustomEvent on enviar call", async () => {
			const node = new DefaultEdgeMeshNode(mockNodoId);
			const targetNodeId = "nodo-target" as NodoId;
			const payload = { data: "hello" };

			const enviarHandler = vi.fn();
			node.eventTarget.addEventListener("enviar", enviarHandler as EventListener);

			await node.enviar(targetNodeId, payload);

			expect(enviarHandler).toHaveBeenCalledTimes(1);
			const eventArg = enviarHandler.mock.calls[0][0] as CustomEvent;
			expect(eventArg.type).toBe("enviar");
			expect(eventArg.detail).toEqual({
				destino: targetNodeId,
				payload,
			});
		});

		it("should emit CustomEvent on transmitir call", async () => {
			const node = new DefaultEdgeMeshNode(mockNodoId);
			const payload = { broadcast: "all" };

			const transmitirHandler = vi.fn();
			node.eventTarget.addEventListener(
				"transmitir",
				transmitirHandler as EventListener,
			);

			await node.transmitir(payload);

			expect(transmitirHandler).toHaveBeenCalledTimes(1);
			const eventArg = transmitirHandler.mock.calls[0][0] as CustomEvent;
			expect(eventArg.type).toBe("transmitir");
			expect(eventArg.detail).toEqual({
				payload,
			});
		});
	});

	describe("off listener removal", () => {
		it("should remove listener correctly using off method", async () => {
			const node = new DefaultEdgeMeshNode(mockNodoId);
			const conectadoSpy = vi.fn();

			node.on("nodoConectado", conectadoSpy);
			node.off("nodoConectado", conectadoSpy);

			await node.conectar();
			expect(conectadoSpy).not.toHaveBeenCalled();
		});
	});
});
