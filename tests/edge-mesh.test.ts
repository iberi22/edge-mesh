import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EdgeMesh, YjsAdapter } from "../src/edge-mesh.js";
import { type NodoId, TIPO_MENSAJE } from "../src/types/index.js";
import * as Y from "yjs";

describe("YjsAdapter", () => {
  let adapter: YjsAdapter;

  beforeEach(() => {
    adapter = new YjsAdapter();
  });

  afterEach(() => {
    adapter.destroy();
  });

  it("should handle Map operations", () => {
    const map = adapter.getMap("test-map");
    map.set("key", "value");
    expect(map.get("key")).toBe("value");
  });

  it("should handle Array operations", () => {
    const array = adapter.getArray("test-array");
    array.push(["item1", "item2"]);
    expect(array.length).toBe(2);
    expect(array.get(0)).toBe("item1");
  });

  it("should handle Text operations", () => {
    const text = adapter.getText("test-text");
    text.insert(0, "Hello World");
    expect(text.toString()).toBe("Hello World");
  });

  it("should apply updates and sync state", () => {
    const adapter2 = new YjsAdapter();

    const map1 = adapter.getMap("sync-map");
    map1.set("foo", "bar");

    const update = adapter.getState();
    adapter2.applyUpdate(update);

    const map2 = adapter2.getMap("sync-map");
    expect(map2.get("foo")).toBe("bar");

    adapter2.destroy();
  });

  it("should generate state vector and merge", () => {
    const adapter2 = new YjsAdapter();

    adapter.getMap("m").set("a", 1);
    adapter2.getMap("m").set("b", 2);

    const sv1 = adapter.getStateVector();
    const update2 = Y.encodeStateAsUpdate(adapter2.doc, sv1);

    adapter.merge(update2);

    expect(adapter.getMap("m").get("a")).toBe(1);
    expect(adapter.getMap("m").get("b")).toBe(2);

    adapter2.destroy();
  });
});

describe("EdgeMesh Integration", () => {
  const nodoId = "test-node" as NodoId;
  let edgeMesh: EdgeMesh;

  beforeEach(() => {
    edgeMesh = new EdgeMesh({ nodoId, storageBackend: "mem" });
  });

  afterEach(async () => {
    // Only call detener if it's not already offline to avoid "Transicion invalida: offline -> offline"
    if (edgeMesh.nodo.estado !== "offline") {
      await edgeMesh.detener();
    }
  });

  it("should initialize components", () => {
    expect(edgeMesh.nodo).toBeDefined();
    expect(edgeMesh.presence).toBeDefined();
    expect(edgeMesh.governance).toBeDefined();
    expect(edgeMesh.yjsAdapter).toBeDefined();
    expect(edgeMesh.identity).toBeDefined();
  });

  it("should handle lifecycle", async () => {
    await edgeMesh.iniciar();
    expect(edgeMesh.nodo.estado).toBe("online");

    await edgeMesh.detener();
    expect(edgeMesh.nodo.estado).toBe("offline");
  });

  it("should wire events correctly", async () => {
    const spy = vi.fn();
    edgeMesh.on("mensajeRecibido", spy);

    // Mock incoming message
    const env = {
      id: "msg-1",
      tipo: TIPO_MENSAJE.HEARTBEAT,
      origen: "other-node",
      destino: nodoId,
      timestamp: Date.now(),
      payload: {
        nodoId: "other-node",
        timestamp: Date.now(),
        secuencia: 1
      },
      version: 1,
      nonce: "abc"
    };

    // Accessing private method for testing purpose
    await (edgeMesh as any).procesarMensaje(env);

    expect(spy).toHaveBeenCalled();
  });

  it("should integrate with Presence", async () => {
    await edgeMesh.iniciar();

    const hb = {
      nodoId: "remote-1" as NodoId,
      timestamp: Date.now(),
      secuencia: 1
    };

    const env = {
      id: "msg-hb",
      tipo: TIPO_MENSAJE.HEARTBEAT,
      origen: "remote-1",
      destino: nodoId,
      timestamp: Date.now(),
      payload: hb,
      version: 1,
      nonce: "nonce1"
    };

    await (edgeMesh as any).procesarMensaje(env);
    expect(edgeMesh.presence.obtenerNodosConocidos()).toContain("remote-1");
  });
});
