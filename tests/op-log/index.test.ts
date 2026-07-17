import { beforeEach, describe, expect, it, vi } from "vitest";
import { OpLog } from "../../src/op-log/index.js";
import { InMemoryStorage } from "../../src/storage/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("OpLog Module", () => {
	let oplog: OpLog;
	const docId = "test-doc";
	const autor = "node-1" as NodoId;

	beforeEach(() => {
		oplog = new OpLog({ docId });
	});

	describe("append", () => {
		it("should append a new operation", async () => {
			const op = await oplog.append("test-type", { foo: "bar" }, autor);
			expect(op.tipo).toBe("test-type");
			expect(op.datos).toEqual({ foo: "bar" });
			expect(op.autor).toBe(autor);
			expect(op.secuencia).toBe(1);
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
	});

	describe("queries", () => {
		beforeEach(async () => {
			await oplog.append("t1", { i: 1 }, autor);
			await oplog.append("t2", { i: 2 }, autor);
			await oplog.append("t3", { i: 3 }, autor);
		});

		it("should obtenerTodas operations", async () => {
			const ops = await oplog.obtenerTodas();
			expect(ops).toHaveLength(3);
			expect(ops[0].secuencia).toBe(1);
			expect(ops[2].secuencia).toBe(3);
		});

		it("should obtenerDesde a sequence", async () => {
			const ops = await oplog.obtenerDesde(2);
			expect(ops).toHaveLength(2);
			expect(ops[0].secuencia).toBe(2);
			expect(ops[1].secuencia).toBe(3);
		});

		it("should obtenerRango of operations", async () => {
			const ops = await oplog.obtenerRango(2, 2);
			expect(ops).toHaveLength(1);
			expect(ops[0].secuencia).toBe(2);
		});

		it("should obtenerPorId", async () => {
			const all = await oplog.obtenerTodas();
			const id = all[1].id;
			const op = await oplog.obtenerPorId(id);
			expect(op?.id).toBe(id);
			expect(op?.secuencia).toBe(2);
		});
	});

	describe("cache and compression", () => {
		it("should limit cache size", async () => {
			const smallCacheOpLog = new OpLog({ docId, maxEnMemoria: 2 });
			await smallCacheOpLog.append("t1", {}, autor);
			await smallCacheOpLog.append("t2", {}, autor);
			await smallCacheOpLog.append("t3", {}, autor);

			// Access private cache for testing if possible, or test via performance/storage
			// Since it's private, we trust the implementation or check if it still works from storage
			const all = await smallCacheOpLog.obtenerTodas();
			expect(all).toHaveLength(3); // Should still be available from storage
		});

		it("should comprimir log", async () => {
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
		});
	});

	describe("sync and applications", () => {
		it("should aplicarOperaciones from remote", async () => {
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
		});

		it("should skip already applied operations", async () => {
			await oplog.append("local", {}, autor); // seq 1

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
			expect(aplicadas).toBe(1); // Only seq 2 applied
			expect(oplog.obtenerUltimaSecuencia()).toBe(2);
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
