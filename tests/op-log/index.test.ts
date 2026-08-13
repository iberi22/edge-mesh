import { beforeEach, describe, expect, it, vi } from "vitest";
import { OpLog } from "../../src/op-log/index.js";
import { InMemoryStorage } from "../../src/storage/index.js";
import type { NodoId, Operacion } from "../../src/types/index.js";

describe("OpLog Module", () => {
	let oplog: OpLog;
	let storage: InMemoryStorage;
	const docId = "test-doc";
	const autor = "node-1" as NodoId;

	beforeEach(() => {
		storage = new InMemoryStorage();
		oplog = new OpLog({ docId, storage });
	});

	describe("cargarDesdeStorage", () => {
		it("should load existing operations from storage on initialization", async () => {
			// Pre-populate storage
			const op1: Operacion = {
				id: `${docId}:1:111`,
				tipo: "init-type",
				datos: { some: "data" },
				timestamp: 111,
				autor,
				secuencia: 1,
			};
			const op2: Operacion = {
				id: `${docId}:2:222`,
				tipo: "init-type-2",
				datos: { other: "data" },
				timestamp: 222,
				autor,
				secuencia: 2,
			};
			await storage.set(`op:${docId}:1`, op1);
			await storage.set(`op:${docId}:2`, op2);

			const loadedOpLog = new OpLog({ docId, storage });
			await loadedOpLog.cargarDesdeStorage();

			expect(loadedOpLog.obtenerUltimaSecuencia()).toBe(2);
			expect(loadedOpLog.obtenerTotalOperaciones()).toBe(2);

			const ops = await loadedOpLog.obtenerTodas();
			expect(ops).toHaveLength(2);
			expect(ops[0]).toEqual(op1);
			expect(ops[1]).toEqual(op2);
		});

		it("should handle empty storage gracefully", async () => {
			const loadedOpLog = new OpLog({ docId, storage });
			await loadedOpLog.cargarDesdeStorage();
			expect(loadedOpLog.obtenerUltimaSecuencia()).toBe(0);
			expect(loadedOpLog.obtenerTotalOperaciones()).toBe(0);
		});
	});

	describe("append", () => {
		it("should append a new operation and increment sequence", async () => {
			const op = await oplog.append("test-type", { foo: "bar" }, autor);
			expect(op.tipo).toBe("test-type");
			expect(op.datos).toEqual({ foo: "bar" });
			expect(op.autor).toBe(autor);
			expect(op.secuencia).toBe(1);
			expect(op.id).toContain(`${docId}:1:`);
			expect(op.timestamp).toBeGreaterThan(0);

			expect(oplog.obtenerUltimaSecuencia()).toBe(1);
			expect(oplog.obtenerTotalOperaciones()).toBe(1);
		});

		it("should emit operacionAgregada event", async () => {
			const handler = vi.fn();
			oplog.on("operacionAgregada", handler);

			const op = await oplog.append("type", {}, autor);

			expect(handler).toHaveBeenCalled();
			const event = handler.mock.calls[0][0];
			expect(event.detail.operacion).toEqual(op);
			expect(event.detail.total).toBe(1);
		});

		it("should handle failures to save in storage and emit error event", async () => {
			const faultyStorage = {
				...storage,
				set: vi.fn().mockRejectedValue(new Error("Storage writing failed")),
			};
			const faultyOpLog = new OpLog({ docId, storage: faultyStorage as any });

			const errorHandler = vi.fn();
			faultyOpLog.on("error", errorHandler);

			await expect(
				faultyOpLog.append("fail-type", { value: 1 }, autor),
			).rejects.toThrow("Error al agregar operacion: Storage writing failed");

			expect(errorHandler).toHaveBeenCalled();
			const errorEvent = errorHandler.mock.calls[0][0];
			expect(errorEvent.detail.mensaje).toBe("Storage writing failed");
			expect(errorEvent.detail.operacion).toBeDefined();
			expect(errorEvent.detail.operacion.tipo).toBe("fail-type");
		});
	});

	describe("queries", () => {
		let op1: Operacion;
		let op2: Operacion;
		let op3: Operacion;

		beforeEach(async () => {
			op1 = await oplog.append("t1", { i: 1 }, autor);
			op2 = await oplog.append("t2", { i: 2 }, autor);
			op3 = await oplog.append("t3", { i: 3 }, autor);
		});

		it("should obtenerTodas operations in sorted order of sequence", async () => {
			const ops = await oplog.obtenerTodas();
			expect(ops).toHaveLength(3);
			expect(ops[0]).toEqual(op1);
			expect(ops[1]).toEqual(op2);
			expect(ops[2]).toEqual(op3);
		});

		it("should obtenerDesde a sequence", async () => {
			const ops = await oplog.obtenerDesde(2);
			expect(ops).toHaveLength(2);
			expect(ops[0]).toEqual(op2);
			expect(ops[1]).toEqual(op3);
		});

		it("should obtenerRango of operations", async () => {
			const ops = await oplog.obtenerRango(2, 2);
			expect(ops).toHaveLength(1);
			expect(ops[0]).toEqual(op2);
		});

		it("should return empty list when range does not match any sequence", async () => {
			const ops = await oplog.obtenerRango(5, 10);
			expect(ops).toHaveLength(0);
		});

		it("should obtenerPorId from cache and from storage if cache is empty", async () => {
			// Retrieve from cache
			const opCached = await oplog.obtenerPorId(op2.id);
			expect(opCached).toEqual(op2);

			// Retrieve from storage directly (by bypassing cache)
			const emptyCacheOpLog = new OpLog({ docId, storage });
			// Store with direct key op:${docId}:${id} which is used in fallback
			await storage.set(`op:${docId}:${op2.id}`, op2);
			const opStored = await emptyCacheOpLog.obtenerPorId(op2.id);
			expect(opStored).toEqual(op2);
		});

		it("should return null for non-existent ID", async () => {
			const op = await oplog.obtenerPorId("non-existent-id");
			expect(op).toBeNull();
		});
	});

	describe("cache and compression", () => {
		it("should limit cache size based on config", async () => {
			const smallCacheOpLog = new OpLog({ docId, storage, maxEnMemoria: 2 });
			await smallCacheOpLog.append("t1", {}, autor);
			await smallCacheOpLog.append("t2", {}, autor);
			await smallCacheOpLog.append("t3", {}, autor);

			// The all operations list query uses fallback to storage, so we should still find all
			const all = await smallCacheOpLog.obtenerTodas();
			expect(all).toHaveLength(3);

			// The storage size should be 3
			expect(await smallCacheOpLog.obtenerTamanioStorage()).toBe(3);
		});

		it("should comprimir log keeping only last N operations", async () => {
			await oplog.append("t1", {}, autor);
			await oplog.append("t2", {}, autor);
			await oplog.append("t3", {}, autor);

			const handler = vi.fn();
			oplog.on("logComprimido", handler);

			await oplog.comprimir(1); // Keep only last 1

			expect(handler).toHaveBeenCalled();
			const ops = await oplog.obtenerTodas();
			expect(ops).toHaveLength(1);
			expect(ops[0].secuencia).toBe(3);

			// Check that event detail shows the range of compressed/deleted ops
			const event = handler.mock.calls[0][0];
			expect(event.detail.desde).toBe(1);
			expect(event.detail.hasta).toBe(2);
		});

		it("should compactar log removing operations older or equal to a sequence number", async () => {
			await oplog.append("t1", {}, autor); // seq 1
			await oplog.append("t2", {}, autor); // seq 2
			await oplog.append("t3", {}, autor); // seq 3

			const handler = vi.fn();
			oplog.on("logComprimido", handler);

			await oplog.compactar(2); // Remove up to sequence 2

			expect(handler).toHaveBeenCalled();
			const ops = await oplog.obtenerTodas();
			expect(ops).toHaveLength(1);
			expect(ops[0].secuencia).toBe(3);
			expect(oplog.obtenerTotalOperaciones()).toBe(1);

			const event = handler.mock.calls[0][0];
			expect(event.detail.desde).toBe(1);
			expect(event.detail.hasta).toBe(2);
		});

		it("should do nothing when compactar is called with sequence number lower than any operation", async () => {
			await oplog.append("t1", {}, autor);
			const handler = vi.fn();
			oplog.on("logComprimido", handler);

			await oplog.compactar(0);
			expect(handler).not.toHaveBeenCalled();
			expect(oplog.obtenerTotalOperaciones()).toBe(1);
		});
	});

	describe("sync and applications", () => {
		it("should aplicarOperaciones from remote and update logical clock sequence", async () => {
			const remoteOps = [
				{
					id: "remote:1",
					tipo: "t1",
					datos: {},
					timestamp: Date.now(),
					autor: "remote" as NodoId,
					secuencia: 1,
				},
				{
					id: "remote:2",
					tipo: "t2",
					datos: {},
					timestamp: Date.now(),
					autor: "remote" as NodoId,
					secuencia: 2,
				},
			];

			const aplicadas = await oplog.aplicarOperaciones(remoteOps as any);
			expect(aplicadas).toBe(2);
			expect(oplog.obtenerUltimaSecuencia()).toBe(2);
			expect(oplog.obtenerTotalOperaciones()).toBe(2);
		});

		it("should skip already applied operations or operations with older/equal sequences", async () => {
			await oplog.append("local", {}, autor); // seq 1

			const remoteOps = [
				{
					id: "remote:1",
					tipo: "t1",
					datos: {},
					timestamp: Date.now(),
					autor: "remote" as NodoId,
					secuencia: 1, // Skip, seq is <= 1
				},
				{
					id: "remote:2",
					tipo: "t2",
					datos: {},
					timestamp: Date.now(),
					autor: "remote" as NodoId,
					secuencia: 2, // Apply, seq is > 1
				},
			];

			const aplicadas = await oplog.aplicarOperaciones(remoteOps as any);
			expect(aplicadas).toBe(1); // Only seq 2 applied
			expect(oplog.obtenerUltimaSecuencia()).toBe(2);
		});

		it("should handle failure during application of specific operation gracefully", async () => {
			const faultyStorage = {
				...storage,
				set: vi
					.fn()
					.mockRejectedValueOnce(new Error("Storage failure")) // fails first remote op
					.mockResolvedValue(undefined), // succeeds second remote op
			};
			const faultyOpLog = new OpLog({ docId, storage: faultyStorage as any });

			const remoteOps = [
				{
					id: "remote:1",
					tipo: "t1",
					datos: {},
					timestamp: Date.now(),
					autor: "remote" as NodoId,
					secuencia: 1,
				},
				{
					id: "remote:2",
					tipo: "t2",
					datos: {},
					timestamp: Date.now(),
					autor: "remote" as NodoId,
					secuencia: 2,
				},
			];

			const aplicadas = await faultyOpLog.aplicarOperaciones(remoteOps as any);
			// It should skip remote:1 due to failure and proceed to apply remote:2
			expect(aplicadas).toBe(1);
			expect(faultyOpLog.obtenerUltimaSecuencia()).toBe(2);
		});
	});

	it("should reiniciar log", async () => {
		await oplog.append("t1", {}, autor);
		await oplog.reiniciar();
		expect(oplog.obtenerUltimaSecuencia()).toBe(0);
		expect(oplog.obtenerTotalOperaciones()).toBe(0);
		const all = await oplog.obtenerTodas();
		expect(all).toHaveLength(0);
	});
});
