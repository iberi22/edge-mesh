import { describe, it, expect, beforeEach, vi } from "vitest";
import { SnapshotManager, createSnapshotManager } from "../../src/snapshot/index.js";
import type { NodoId, PayloadSnapshot } from "../../src/types/index.js";

// Mock crypto.subtle.digest
if (typeof global.crypto === "undefined") {
  (global as any).crypto = {
    subtle: {
      digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    },
  };
} else {
    vi.spyOn(crypto.subtle, 'digest').mockResolvedValue(new ArrayBuffer(32));
}

describe("Snapshot Module", () => {
  let manager: SnapshotManager;
  const docId = "test-doc";

  beforeEach(() => {
    manager = new SnapshotManager({ docId, interval: 3 });
  });

  describe("crearSnapshot", () => {
    it("should create a snapshot", async () => {
      const data = new Uint8Array([1, 2, 3]);
      const success = await manager.crearSnapshot(data, ["node1" as NodoId]);

      expect(success).toBe(true);
      expect(manager.obtenerVersionActual()).toBe(1);

      const snapshots = await manager.obtenerSnapshotsDisponibles();
      expect(snapshots).toHaveLength(1);
      expect(snapshots[0].version).toBe(1);
    });

    it("should emit snapshotCreado event", async () => {
      const handler = vi.fn();
      manager.on("snapshotCreado", handler);

      await manager.crearSnapshot(new Uint8Array([1]), []);

      expect(handler).toHaveBeenCalled();
      expect(handler.mock.calls[0][0].detail.docId).toBe(docId);
    });
  });

  describe("automatic snapshots", () => {
    it("should trigger snapshot after interval reached", async () => {
      // We need to set some data first so crearSnapshot doesn't return false immediately
      await manager.crearSnapshot(new Uint8Array([1]));
      manager.reiniciar(); // Reset but keep datosActuales in a real scenario,
      // however reiniciar() clears everything including datosActuales.

      // Let's manually set datosActuales using a hack or just use a spy that returns true
      const spy = vi.spyOn(manager, "crearSnapshot").mockResolvedValue(true);

      manager.incrementarOperaciones(); // 1
      manager.incrementarOperaciones(); // 2
      expect(spy).not.toHaveBeenCalled();

      manager.incrementarOperaciones(); // 3 -> Trigger
      expect(spy).toHaveBeenCalled();
    });
  });

  describe("restoration", () => {
    it("should restaurarSnapshot", async () => {
      const data = new Uint8Array([4, 5, 6]);
      await manager.crearSnapshot(data);

      manager.reiniciar();
      expect(manager.obtenerVersionActual()).toBe(0);

      const restored = await manager.restaurarSnapshot(1);
      expect(restored).toEqual(data);
      expect(manager.obtenerVersionActual()).toBe(1);
    });

    it("should restaurarUltimoSnapshot", async () => {
      await manager.crearSnapshot(new Uint8Array([1]));
      await manager.crearSnapshot(new Uint8Array([2]));

      const restored = await manager.restaurarUltimoSnapshot();
      expect(restored).toEqual(new Uint8Array([2]));
      expect(manager.obtenerVersionActual()).toBe(2);
    });
  });

  describe("sharing", () => {
    it("should prepararSnapshotCompartido", async () => {
      const data = new Uint8Array([7, 8, 9]);
      await manager.crearSnapshot(data, ["n1" as NodoId]);

      const shared = await manager.prepararSnapshotCompartido();
      expect(shared?.docId).toBe(docId);
      expect(shared?.datos).toEqual(data);
      expect(shared?.version).toBe(1);
      expect(shared?.nodosConfirmados).toContain("n1");
    });

    it("should recibirSnapshot", async () => {
      const remoteSnapshot: PayloadSnapshot = {
        docId,
        version: 10,
        datos: new Uint8Array([10, 11, 12]),
        nodosConfirmados: ["remote" as NodoId],
      };

      const success = await manager.recibirSnapshot(remoteSnapshot);
      expect(success).toBe(true);
      expect(manager.obtenerVersionActual()).toBe(10);
      expect(manager.obtenerNodosConfirmados()).toContain("remote");
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
  });

  it("should use factory function", () => {
    const m = createSnapshotManager({ docId: "factory-test" });
    expect(m).toBeInstanceOf(SnapshotManager);
    expect(m.docId).toBe("factory-test");
  });
});
