import { beforeEach, describe, expect, it, vi } from "vitest";
import { OpLog } from "../../src/op-log/index.js";
import { SyncEngine } from "../../src/sync/engine.js";
import type { NodoId, Operacion } from "../../src/types/index.js";

describe("SyncEngine Module", () => {
	let engine: SyncEngine;
	let oplog: OpLog;
	const docId = "test-doc";
	const peerId = "peer-1" as NodoId;

	beforeEach(() => {
		oplog = new OpLog({ docId });
		engine = new SyncEngine({ docId, opLog: oplog });
	});

	describe("sincronizar", () => {
		it("should perform bidirectional sync successfully", async () => {
			// Local operations
			await oplog.append("t1", { val: 1 }, "local" as NodoId);

			// Remote operations to receive
			const remoteOps: Operacion[] = [
				{
					id: "remote:2",
					tipo: "t2",
					datos: { val: 2 },
					timestamp: Date.now(),
					autor: peerId,
					secuencia: 2,
				},
			];

			const enviar = vi.fn().mockResolvedValue(undefined);
			const recibir = vi.fn().mockResolvedValue(remoteOps);

			const result = await engine.sincronizar(peerId, enviar, recibir);

			expect(result.exito).toBe(true);
			expect(result.operacionesEnviadas).toBe(1);
			expect(result.operacionesRecibidas).toBe(1);
			expect(enviar).toHaveBeenCalledWith(
				expect.arrayContaining([expect.objectContaining({ secuencia: 1 })]),
			);
			expect(oplog.obtenerUltimaSecuencia()).toBe(2);
		});

		it("should handle pull-only (entrante) direction", async () => {
			engine = new SyncEngine({ docId, opLog: oplog, direction: "entrante" });
			await oplog.append("t1", { val: 1 }, "local" as NodoId);

			const remoteOps: Operacion[] = [
				{
					id: "remote:2",
					tipo: "t2",
					datos: { val: 2 },
					timestamp: Date.now(),
					autor: peerId,
					secuencia: 2,
				},
			];

			const enviar = vi.fn().mockResolvedValue(undefined);
			const recibir = vi.fn().mockResolvedValue(remoteOps);

			const result = await engine.sincronizar(peerId, enviar, recibir);

			expect(result.operacionesEnviadas).toBe(0);
			expect(result.operacionesRecibidas).toBe(1);
			expect(enviar).not.toHaveBeenCalled();
		});

		it("should handle push-only (saliente) direction", async () => {
			engine = new SyncEngine({ docId, opLog: oplog, direction: "saliente" });
			await oplog.append("t1", { val: 1 }, "local" as NodoId);

			const enviar = vi.fn().mockResolvedValue(undefined);
			const recibir = vi.fn().mockResolvedValue([]);

			const result = await engine.sincronizar(peerId, enviar, recibir);

			expect(result.operacionesEnviadas).toBe(1);
			expect(result.operacionesRecibidas).toBe(0);
			expect(recibir).not.toHaveBeenCalled();
		});

		it("should detect conflicts", async () => {
			await oplog.append("local", {}, "local" as NodoId); // seq 1

			// Remote sends op with same or lower sequence than local
			const remoteOps = [
				{
					id: "remote:1",
					tipo: "t1",
					datos: {},
					timestamp: Date.now(),
					autor: peerId,
					secuencia: 1,
				},
			];

			const conflictHandler = vi.fn();
			engine.on("conflictoDetectado", conflictHandler);

			const result = await engine.sincronizar(
				peerId,
				async () => {},
				async () => remoteOps,
			);

			expect(result.conflictos).toBe(1);
			expect(conflictHandler).toHaveBeenCalled();
		});

		it("should prevent concurrent syncs for same document", async () => {
			const slowRecibir = () =>
				new Promise<readonly unknown[]>((resolve) =>
					setTimeout(() => resolve([]), 50),
				);

			const promise1 = engine.sincronizar(peerId, async () => {}, slowRecibir);

			await expect(
				engine.sincronizar(
					peerId,
					async () => {},
					async () => [],
				),
			).rejects.toThrow("Sync en progreso");

			await promise1;
		});
	});

	describe("clocks", () => {
		it("should update and get local clock", () => {
			engine.actualizarClockLocal(10);
			expect(engine.obtenerClockLocal()).toBe(10);
			engine.actualizarClockLocal(5); // Should not go backwards
			expect(engine.obtenerClockLocal()).toBe(10);
		});

		it("should update and get remote clock", () => {
			engine.actualizarClockRemoto(peerId, 20);
			expect(engine.obtenerClockRemoto(peerId)).toBe(20);
		});
	});

	it("should report sync status", async () => {
		expect(engine.estaSincronizando()).toBe(false);
		const promise = engine.sincronizar(
			peerId,
			async () => {},
			async () => [],
		);
		expect(engine.estaSincronizando()).toBe(true);
		await promise;
		expect(engine.estaSincronizando()).toBe(false);
	});
});
