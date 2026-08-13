import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	createSnapshotManager,
	SnapshotManager,
} from "../../src/snapshot/index.js";
import type { NodoId, PayloadSnapshot } from "../../src/types/index.js";

// Mock crypto.subtle.digest
if (typeof global.crypto === "undefined") {
	(global as any).crypto = {
		subtle: {
			digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
		},
	};
} else {
	vi.spyOn(crypto.subtle, "digest").mockResolvedValue(new ArrayBuffer(32));
}

describe("Snapshot Module", () => {
	let manager: SnapshotManager;
	const docId = "test-doc";

	beforeEach(() => {
		manager = new SnapshotManager({ docId, interval: 3, maxSnapshots: 3 });
	});

	describe("crearSnapshot", () => {
		it("should create a snapshot, update version, and track confirmed nodes", async () => {
			const data = new Uint8Array([1, 2, 3]);
			const nodes = ["node1" as NodoId, "node2" as NodoId];
			const success = await manager.crearSnapshot(data, nodes);

			expect(success).toBe(true);
			expect(manager.obtenerVersionActual()).toBe(1);
			expect(manager.obtenerNodosConfirmados()).toEqual(nodes);

			const snapshots = await manager.obtenerSnapshotsDisponibles();
			expect(snapshots).toHaveLength(1);
			expect(snapshots[0].version).toBe(1);
			expect(snapshots[0].tamanio).toBe(3);
			expect(snapshots[0].nodos).toEqual(nodes);
			expect(manager.obtenerContadorOperaciones()).toBe(0);
		});

		it("should use existing data if none is provided but previously set", async () => {
			await manager.crearSnapshot(new Uint8Array([4, 5, 6]));
			expect(manager.obtenerVersionActual()).toBe(1);

			// create snapshot again without passing data
			const success = await manager.crearSnapshot();
			expect(success).toBe(true);
			expect(manager.obtenerVersionActual()).toBe(2);

			const restored = await manager.restaurarSnapshot(2);
			expect(restored).toEqual(new Uint8Array([4, 5, 6]));
		});

		it("should return false if creating snapshot when no data has ever been set", async () => {
			const success = await manager.crearSnapshot();
			expect(success).toBe(false);
			expect(manager.obtenerVersionActual()).toBe(0);
		});

		it("should emit snapshotCreado event", async () => {
			const handler = vi.fn();
			manager.on("snapshotCreado", handler);

			await manager.crearSnapshot(new Uint8Array([1]), []);

			expect(handler).toHaveBeenCalled();
			const event = handler.mock.calls[0][0];
			expect(event.detail.docId).toBe(docId);
			expect(event.detail.snapshot.version).toBe(1);
			expect(event.detail.snapshot.tamanio).toBe(1);
		});

		it("should clean up old snapshots keeping up to maxSnapshots", async () => {
			const m = new SnapshotManager({ docId, interval: 3, maxSnapshots: 2 });
			await m.crearSnapshot(new Uint8Array([1])); // version 1
			await m.crearSnapshot(new Uint8Array([2])); // version 2
			await m.crearSnapshot(new Uint8Array([3])); // version 3

			const available = await m.obtenerSnapshotsDisponibles();
			expect(available).toHaveLength(2);
			const versions = available.map((s) => s.version);
			expect(versions).toContain(2);
			expect(versions).toContain(3);
			expect(versions).not.toContain(1);
		});
	});

	describe("automatic snapshots", () => {
		it("should trigger snapshot after interval reached and reset counter", async () => {
			await manager.crearSnapshot(new Uint8Array([42])); // sets data
			const spy = vi.spyOn(manager, "crearSnapshot");

			expect(manager.incrementarOperaciones()).toBe(false); // 1
			expect(manager.incrementarOperaciones()).toBe(false); // 2
			expect(spy).not.toHaveBeenCalled();

			expect(manager.incrementarOperaciones()).toBe(true); // 3 -> Trigger!
			expect(spy).toHaveBeenCalled();

			// Wait for the asynchronous microtasks in crearSnapshot to complete
			await spy.mock.results[0].value;

			expect(manager.obtenerContadorOperaciones()).toBe(0);
			expect(manager.obtenerVersionActual()).toBe(2);
		});
	});

	describe("restoration", () => {
		it("should restaurarSnapshot", async () => {
			const data = new Uint8Array([4, 5, 6]);
			await manager.crearSnapshot(data);

			manager.reiniciar();
			expect(manager.obtenerVersionActual()).toBe(0);

			const handler = vi.fn();
			manager.on("snapshotRestaurado", handler);

			const restored = await manager.restaurarSnapshot(1);
			expect(restored).toEqual(data);
			expect(manager.obtenerVersionActual()).toBe(1);

			expect(handler).toHaveBeenCalled();
			expect(handler.mock.calls[0][0].detail.version).toBe(1);
			expect(handler.mock.calls[0][0].detail.docId).toBe(docId);
		});

		it("should return null when trying to restore non-existent snapshot version", async () => {
			const restored = await manager.restaurarSnapshot(999);
			expect(restored).toBeNull();
		});

		it("should restaurarUltimoSnapshot", async () => {
			await manager.crearSnapshot(new Uint8Array([1]));
			await manager.crearSnapshot(new Uint8Array([2]));

			const restored = await manager.restaurarUltimoSnapshot();
			expect(restored).toEqual(new Uint8Array([2]));
			expect(manager.obtenerVersionActual()).toBe(2);
		});

		it("should return null for restaurarUltimoSnapshot if no snapshots exist", async () => {
			const restored = await manager.restaurarUltimoSnapshot();
			expect(restored).toBeNull();
		});
	});

	describe("sharing", () => {
		it("should prepararSnapshotCompartido", async () => {
			const data = new Uint8Array([7, 8, 9]);
			await manager.crearSnapshot(data, ["n1" as NodoId]);

			const handler = vi.fn();
			manager.on("snapshotCompartido", handler);

			const shared = await manager.prepararSnapshotCompartido();
			expect(shared?.docId).toBe(docId);
			expect(shared?.datos).toEqual(data);
			expect(shared?.version).toBe(1);
			expect(shared?.nodosConfirmados).toContain("n1");

			expect(handler).toHaveBeenCalled();
			expect(handler.mock.calls[0][0].detail.snapshot).toEqual(shared);
		});

		it("should return null for prepararSnapshotCompartido if no data is present", async () => {
			const shared = await manager.prepararSnapshotCompartido();
			expect(shared).toBeNull();
		});

		it("should recibirSnapshot, apply details, and trigger event", async () => {
			const remoteSnapshot: PayloadSnapshot = {
				docId,
				version: 10,
				datos: new Uint8Array([10, 11, 12]),
				nodosConfirmados: ["remote" as NodoId],
			};

			const handler = vi.fn();
			manager.on("snapshotRestaurado", handler);

			const success = await manager.recibirSnapshot(remoteSnapshot);
			expect(success).toBe(true);
			expect(manager.obtenerVersionActual()).toBe(10);
			expect(manager.obtenerNodosConfirmados()).toContain("remote");

			expect(handler).toHaveBeenCalled();
			expect(handler.mock.calls[0][0].detail.version).toBe(10);
			expect(handler.mock.calls[0][0].detail.docId).toBe(docId);
		});

		it("should reject older or different docId snapshots", async () => {
			await manager.crearSnapshot(new Uint8Array([1])); // version 1

			const oldSnapshot: PayloadSnapshot = {
				docId,
				version: 1,
				datos: new Uint8Array([0]),
				nodosConfirmados: [],
			};
			expect(await manager.recibirSnapshot(oldSnapshot)).toBe(false);

			const wrongDocSnapshot: PayloadSnapshot = {
				docId: "wrong",
				version: 2,
				datos: new Uint8Array([0]),
				nodosConfirmados: [],
			};
			expect(await manager.recibirSnapshot(wrongDocSnapshot)).toBe(false);
		});
	});

	it("should confirm nodes", () => {
		manager.confirmarNodo("n1" as NodoId);
		expect(manager.obtenerNodosConfirmados()).toContain("n1");
		manager.confirmarNodo("n2" as NodoId);
		expect(manager.obtenerNodosConfirmados()).toContain("n2");
	});

	it("should use factory function", () => {
		const m = createSnapshotManager({ docId: "factory-test" });
		expect(m).toBeInstanceOf(SnapshotManager);
		expect(m.docId).toBe("factory-test");
	});

	it("should support off to remove event listener", async () => {
		const handler = vi.fn();
		manager.on("snapshotCreado", handler);
		manager.off("snapshotCreado", handler);

		await manager.crearSnapshot(new Uint8Array([1]), []);
		expect(handler).not.toHaveBeenCalled();
	});
});
