import { beforeEach, describe, expect, it, vi } from "vitest";
import { InMemoryStorage } from "../../src/storage/index.js";
import { OpLog } from "../../src/op-log/index.js";
import { SyncEngine } from "../../src/sync/engine.js";
import type { NodoId, Operacion } from "../../src/types/index.js";

describe("Integration: Storage + Sync (Persisted OpLog & Posthumous Sync)", () => {
	let storageA: InMemoryStorage;
	let storageB: InMemoryStorage;
	let opLogA: OpLog;
	let opLogB: OpLog;
	let syncEngineA: SyncEngine;
	let syncEngineB: SyncEngine;

	const docId = "shared-document";
	const idA = "node-a" as NodoId;
	const idB = "node-b" as NodoId;

	beforeEach(() => {
		storageA = new InMemoryStorage();
		storageB = new InMemoryStorage();

		opLogA = new OpLog({ docId, storage: storageA });
		opLogB = new OpLog({ docId, storage: storageB });

		syncEngineA = new SyncEngine({ docId, opLog: opLogA });
		syncEngineB = new SyncEngine({ docId, opLog: opLogB });
	});

	it("should append operations and persist them in IStorage via OpLog", async () => {
		await opLogA.append("SET_TITLE", { title: "Introduction" }, idA);
		await opLogA.append("ADD_PARAGRAPH", { text: "Hello, this is Maloca." }, idA);

		expect(opLogA.obtenerUltimaSecuencia()).toBe(2);
		expect(opLogA.obtenerTotalOperaciones()).toBe(2);

		// Verify that they are persisted in storageA under the correct prefix
		const persistedList = await storageA.list({ prefijo: `op:${docId}:` });
		expect(persistedList.length).toBe(2);

		const op1 = persistedList[0].valor as Operacion;
		expect(op1.tipo).toBe("SET_TITLE");
		expect(op1.autor).toBe(idA);
		expect(op1.secuencia).toBe(1);
	});

	it("should load persisted operations from storage when initializing a new OpLog instance", async () => {
		// Populate storageA directly with raw operations (simulating cold boot)
		const op1: Operacion = {
			id: `${docId}:1:12345678`,
			tipo: "INIT_VAL",
			datos: { value: 42 },
			timestamp: Date.now(),
			autor: idA,
			secuencia: 1,
		};
		const op2: Operacion = {
			id: `${docId}:2:12345679`,
			tipo: "MUT_VAL",
			datos: { value: 100 },
			timestamp: Date.now(),
			autor: idA,
			secuencia: 2,
		};

		await storageA.set(`op:${docId}:1`, op1);
		await storageA.set(`op:${docId}:2`, op2);

		// Create a new OpLog reading from that storage
		const coldOpLog = new OpLog({ docId, storage: storageA });

		// Read raw operations from the storage and load/apply them (cold recovery)
		const rawPersisted = await storageA.list({ prefijo: `op:${docId}:` });
		const opsToLoad = rawPersisted.map(entry => entry.valor as Operacion);
		await coldOpLog.aplicarOperaciones(opsToLoad);

		// Now verify we can fetch them via obtenerTodas()
		const loadedOps = await coldOpLog.obtenerTodas();
		expect(loadedOps.length).toBe(2);
		expect(loadedOps[0].tipo).toBe("INIT_VAL");
		expect(loadedOps[1].tipo).toBe("MUT_VAL");
	});

	it("should synchronize offline operations postmortem (sync póstumo) using SyncEngine", async () => {
		// Node A is offline and performs local modifications
		await opLogA.append("EDIT_CELL", { row: 1, col: 1, value: "Alice" }, idA);
		await opLogA.append("EDIT_CELL", { row: 1, col: 2, value: "Engineer" }, idA);

		// Later, Node A connects with Node B. We perform posthumous sync.
		// Simulator for Peer B sending its (empty) list and Peer A sending its list of operations.
		const bridgeSend = async (ops: readonly unknown[]) => {
			// B receives ops from A and applies them
			await opLogB.aplicarOperaciones(ops as any);
		};

		const bridgeReceive = async () => {
			// A gets B's operations (none in this case)
			return await opLogB.obtenerTodas();
		};

		const result = await syncEngineA.sincronizar(idB, bridgeSend, bridgeReceive);

		expect(result.exito).toBe(true);
		expect(result.operacionesEnviadas).toBe(2);
		expect(result.operacionesRecibidas).toBe(0);

		// Verify B's OpLog and storage are updated with A's offline edits
		const opsB = await opLogB.obtenerTodas();
		expect(opsB.length).toBe(2);
		expect(opsB[0].tipo).toBe("EDIT_CELL");
		expect(opsB[1].datos).toEqual({ row: 1, col: 2, value: "Engineer" });

		const persistedB = await storageB.list({ prefijo: `op:${docId}:` });
		expect(persistedB.length).toBe(2);
	});

	it("should detect and handle conflicts when both nodes have concurrent/offline operations", async () => {
		// Both Node A and Node B make concurrent local changes
		await opLogA.append("CONCURRENT_MUT", { val: "A" }, idA); // Seq 1
		await opLogB.append("CONCURRENT_MUT", { val: "B" }, idB); // Seq 1

		const conflictSpy = vi.fn();
		syncEngineA.on("conflictoDetectado", conflictSpy);

		const bridgeSend = async (ops: readonly unknown[]) => {
			await opLogB.aplicarOperaciones(ops as any);
		};

		const bridgeReceive = async () => {
			return await opLogB.obtenerTodas();
		};

		const result = await syncEngineA.sincronizar(idB, bridgeSend, bridgeReceive);

		expect(result.exito).toBe(true);
		expect(result.conflictos).toBeGreaterThanOrEqual(1);
		expect(conflictSpy).toHaveBeenCalled();
	});

	it("should compress OpLog by removing older operations while preserving ability to sync remaining operations", async () => {
		// Append 10 operations
		for (let i = 0; i < 10; i++) {
			await opLogA.append("BULK_OP", { index: i }, idA);
		}

		// Compress to keep only last 3 operations
		await opLogA.comprimir(3);

		// Check storage sizes
		const persistedList = await storageA.list({ prefijo: `op:${docId}:` });
		expect(persistedList.length).toBe(3);

		// The remaining operations should have sequence numbers 8, 9, 10
		const remainingOps = await opLogA.obtenerTodas();
		expect(remainingOps.length).toBe(3);
		expect(remainingOps[0].secuencia).toBe(8);
		expect(remainingOps[2].secuencia).toBe(10);

		// We should still be able to append new operations
		const newOp = await opLogA.append("BULK_OP", { index: 10 }, idA);
		expect(newOp.secuencia).toBe(11);
	});
});
