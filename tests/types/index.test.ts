import { describe, expect, it } from "vitest";
import {
	ESTADO_NODO,
	isEstadoNodo,
	isTipoMensaje,
	TIPO_MENSAJE,
} from "../../src/types/index.js";

describe("types", () => {
	describe("TIPO_MENSAJE", () => {
		it("should have expected message types", () => {
			expect(TIPO_MENSAJE.SYNC).toBe("sync");
			expect(TIPO_MENSAJE.HEARTBEAT).toBe("heartbeat");
			expect(TIPO_MENSAJE.ERROR).toBe("error");
		});
	});

	describe("ESTADO_NODO", () => {
		it("should have expected node states", () => {
			expect(ESTADO_NODO.OFFLINE).toBe("offline");
			expect(ESTADO_NODO.ONLINE).toBe("online");
			expect(ESTADO_NODO.CONECTANDO).toBe("conectando");
		});
	});

	describe("isTipoMensaje", () => {
		it("should return true for valid message types", () => {
			expect(isTipoMensaje("sync")).toBe(true);
			expect(isTipoMensaje("heartbeat")).toBe(true);
			expect(isTipoMensaje(TIPO_MENSAJE.AUTHZ)).toBe(true);
		});

		it("should return false for invalid message types", () => {
			expect(isTipoMensaje("invalid")).toBe(false);
			expect(isTipoMensaje("")).toBe(false);
			expect(isTipoMensaje(null)).toBe(false);
			expect(isTipoMensaje(123)).toBe(false);
		});
	});

	describe("isEstadoNodo", () => {
		it("should return true for valid node states", () => {
			expect(isEstadoNodo("offline")).toBe(true);
			expect(isEstadoNodo("online")).toBe(true);
			expect(isEstadoNodo(ESTADO_NODO.SUSPENDIDO)).toBe(true);
		});

		it("should return false for invalid node states", () => {
			expect(isEstadoNodo("invalid")).toBe(false);
			expect(isEstadoNodo("")).toBe(false);
			expect(isEstadoNodo(null)).toBe(false);
			expect(isEstadoNodo(undefined)).toBe(false);
		});
	});
});
