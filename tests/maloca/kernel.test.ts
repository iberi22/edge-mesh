import { describe, it, expect, beforeEach } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import type { NodoId } from "../../src/types/index.js";

describe("MalocaKernel", () => {
  let kernel: MalocaKernel;

  beforeEach(async () => {
    kernel = new MalocaKernel({
      nodoId: "node1" as NodoId,
      storageBackend: "mem",
    });
    await kernel.iniciar();
  });

  it("should register human node", async () => {
    await kernel.registerNode("humano", new Uint8Array([1]), { alias: "Jules" });

    const profile = kernel.getProfile("node1" as NodoId);
    expect(profile).toBeDefined();
    expect(profile!.alias).toBe("Jules");
  });

  it("should get network status", async () => {
    kernel.connectProject("test-project", {} as any);

    const status = kernel.getNetworkStatus();
    expect(status.nodoId).toBe("node1");
    expect(status.proyectosConectados).toContain("test-project");
  });
});
