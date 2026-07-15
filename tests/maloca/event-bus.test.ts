import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventBus, TIPO_EVENTO_MALOCA } from "../../src/maloca/event-bus.js";
import { MeshManager } from "../../src/mesh/index.js";
import { OpLog } from "../../src/op-log/index.js";
import { InMemoryStorage } from "../../src/storage/index.js";
import type { NodoId } from "../../src/types/index.js";
import type { EdgeMesh } from "../../src/edge-mesh.js";

describe("EventBus", () => {
  let mesh: MeshManager;
  let opLog: OpLog;
  let bus: EventBus;
  const nodoId = "nodo-test" as NodoId;

  beforeEach(() => {
    mesh = new MeshManager({ nodoId }, {} as EdgeMesh);
    vi.spyOn(mesh, "transmitirConGossip").mockResolvedValue(undefined);

    opLog = new OpLog({ docId: "events", storage: new InMemoryStorage() });
    bus = new EventBus(mesh, opLog);
  });

  it("debería emitir y recibir un evento localmente", async () => {
    const handler = vi.fn();
    bus.subscribe(TIPO_EVENTO_MALOCA.PROFILE_CREATED, handler);

    const payload = { userId: "u1", name: "Alice" };
    await bus.emit(TIPO_EVENTO_MALOCA.PROFILE_CREATED, payload);

    expect(handler).toHaveBeenCalledTimes(1);
    const event = handler.mock.calls[0][0];
    expect(event.tipo).toBe(TIPO_EVENTO_MALOCA.PROFILE_CREATED);
    expect(event.payload).toEqual(payload);
    expect(event.origen).toBe(nodoId);
  });

  it("debería persistir eventos en el OpLog", async () => {
    await bus.emit("TEST_EVENT", { foo: "bar" });

    const logs = await bus.getEventLog();
    expect(logs).toHaveLength(1);
    expect(logs[0].tipo).toBe("TEST_EVENT");
  });

  it("debería manejar desuscripción", async () => {
    const handler = vi.fn();
    bus.subscribe("FOO", handler);
    bus.unsubscribe("FOO", handler);

    await bus.emit("FOO", {});
    expect(handler).not.toHaveBeenCalled();
  });
});
