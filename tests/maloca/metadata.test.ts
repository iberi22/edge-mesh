import { describe, it, expect, beforeEach } from "vitest";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import type { NodoId } from "../../src/types/index.js";

describe("MetadataManager", () => {
  let kernel: MalocaKernel;

  beforeEach(async () => {
    kernel = new MalocaKernel({
      nodoId: "test-node" as NodoId,
      storageBackend: "mem",
    });
    await kernel.iniciar();
  });

  it("should get network status", () => {
    const status = kernel.getNetworkStatus();
    expect(status).toHaveProperty("nodoId");
    expect(status).toHaveProperty("proyectosConectados");
  });

  it("should sync and retrieve shared metadata", async () => {
    await kernel.registerNode("humano", new Uint8Array([1]), { alias: "Alice" });
    const shared = kernel.getNetworkStatus();
    expect(shared.perfilesRegistrados).toBeGreaterThanOrEqual(1);
  });

  it("should provide profile cache", async () => {
    await kernel.registerNode("humano", new Uint8Array([1]), { alias: "Alice" });
    const profile = kernel.getProfile("test-node" as NodoId);
    expect(profile).toBeDefined();
    expect(profile!.alias).toBe("Alice");
  });
});
