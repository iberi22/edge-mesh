import { describe, it, expect, beforeEach } from "vitest";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import type { NodoId } from "../../src/types/index.js";

describe("MalocaKernel", () => {
  let kernel: MalocaKernel;

  beforeEach(() => {
    kernel = new MalocaKernel({
      nodoId: "node1" as NodoId,
      storageBackend: "mem",
    });
  });

  it("should register human node", async () => {
    await kernel.iniciar();
    await kernel.registerNode("humano", new Uint8Array([1]), { alias: "Jules" });

    const profile = kernel.getProfile("node1" as NodoId);
    expect(profile).toBeDefined();
    expect((profile as any).alias).toBe("Jules");
  });

  it("should get network status", async () => {
    await kernel.iniciar();
    kernel.connectProject("test-project", {});

    const status = kernel.getNetworkStatus();
    expect(status.nodoId).toBe("node1");
    expect(status.proyectosConectados).toContain("test-project");
  });
});
