import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createEnvelope,
	MessageDeduplicator,
	validateEnvelope,
} from "../../src/protocol/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("protocol", () => {
	const mockNodoId = "nodo-1" as NodoId;
	const mockDestinoId = "nodo-2" as NodoId;

	describe("createEnvelope", () => {
		it("should create a valid envelope with given parameters", () => {
			const payload = { data: "test" };
			const env = createEnvelope("sync", mockNodoId, mockDestinoId, payload);

			expect(env.tipo).toBe("sync");
			expect(env.origen).toBe(mockNodoId);
			expect(env.destino).toBe(mockDestinoId);
			expect(env.payload).toEqual(payload);
			expect(env.version).toBe(1);
			expect(typeof env.id).toBe("string");
			expect(typeof env.nonce).toBe("string");
			expect(typeof env.timestamp).toBe("number");
		});

		it("should include firma if provided", () => {
			const firma = new Uint8Array([1, 2, 3]);
			const env = createEnvelope("sync", mockNodoId, mockDestinoId, {}, firma);
			expect(env.firma).toEqual(firma);
		});
	});

	describe("validateEnvelope", () => {
		it("should return true for valid envelope", () => {
			const env = createEnvelope("sync", mockNodoId, mockDestinoId, {});
			expect(validateEnvelope(env)).toBe(true);
		});

		it("should return false for invalid envelope fields", () => {
			const env = createEnvelope("sync", mockNodoId, mockDestinoId, {});

			expect(validateEnvelope({ ...env, id: "" })).toBe(false);
			expect(validateEnvelope({ ...env, tipo: "invalid" as any })).toBe(false);
			expect(validateEnvelope({ ...env, origen: "" as any })).toBe(false);
			expect(validateEnvelope({ ...env, destino: "" as any })).toBe(false);
			expect(validateEnvelope({ ...env, timestamp: 0 })).toBe(false);
			expect(validateEnvelope({ ...env, version: 0 })).toBe(false);
			expect(validateEnvelope({ ...env, nonce: "" })).toBe(false);
		});
	});

	describe("MessageDeduplicator", () => {
		let deduplicator: MessageDeduplicator;

		beforeEach(() => {
			vi.useFakeTimers();
			deduplicator = new MessageDeduplicator({ ventanaMs: 1000 });
		});

		afterEach(() => {
			vi.useRealTimers();
		});

		it("should detect duplicate messages within window", () => {
			const env = createEnvelope("sync", mockNodoId, mockDestinoId, {});

			expect(deduplicator.esDuplicado(env)).toBe(false);
			expect(deduplicator.esDuplicado(env)).toBe(true);
		});

		it("should not detect duplicate after window expires", () => {
			const env = createEnvelope("sync", mockNodoId, mockDestinoId, {});

			expect(deduplicator.esDuplicado(env)).toBe(false);

			vi.advanceTimersByTime(1001);

			expect(deduplicator.esDuplicado(env)).toBe(false);
		});

		it("should consider origin in uniqueness", () => {
			const env1 = createEnvelope("sync", mockNodoId, mockDestinoId, {});
			const env2 = { ...env1, origen: "nodo-3" as NodoId };

			expect(deduplicator.esDuplicado(env1)).toBe(false);
			expect(deduplicator.esDuplicado(env2)).toBe(false);
		});

		it("should clean up old entries when max entries reached", () => {
			const smallDeduplicator = new MessageDeduplicator({
				maxEntradas: 2,
				ventanaMs: 1000,
			});

			const env1 = createEnvelope("sync", mockNodoId, mockDestinoId, {});
			const env2 = createEnvelope(
				"sync",
				"nodo-2" as NodoId,
				mockDestinoId,
				{},
			);
			const env3 = createEnvelope(
				"sync",
				"nodo-3" as NodoId,
				mockDestinoId,
				{},
			);

			smallDeduplicator.esDuplicado(env1);
			vi.advanceTimersByTime(100);
			smallDeduplicator.esDuplicado(env2);

			vi.advanceTimersByTime(1000); // env1 and env2 are now "old"

			smallDeduplicator.esDuplicado(env3); // should trigger cleanup

			// The implementation of limpiar only deletes entries if ts < limite
			// Since we used vi.advanceTimersByTime(1000) and ventanaMs is 1000,
			// now - 1000 might not be strictly greater than seen timestamps.
			// In the implementation: if (ts < limite) { this.vistos.delete(clave); }
			// limite = ahora - 1000.
			// env1 was at T0. env2 was at T100.
			// env3 is at T1100. limite is 1100 - 1000 = 100.
			// env1 (T0) < 100, so it is deleted.
			// env2 (T100) is NOT < 100, so it is NOT deleted.
			// Total should be 2 (env2 and env3).
			expect(smallDeduplicator.obtenerEstadisticas().total).toBe(2);
		});
	});
});
