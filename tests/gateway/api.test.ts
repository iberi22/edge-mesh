import { describe, it, expect, beforeEach, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MalocaGatewayAPI } from "../../src/maloca/gateway/api.js";
import type { NodoId } from "../../src/types/index.js";

describe("MalocaGatewayAPI", () => {
  let mesh: EdgeMesh;
  let api: MalocaGatewayAPI;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "test-node" as NodoId,
      storageBackend: "mem",
    });
    api = new MalocaGatewayAPI(mesh);
  });

  it("should return mesh status", async () => {
    const status = await api.getMeshStatus();
    expect(status.status).toBe("online");
    expect(status.config.nodoId).toBe("test-node");
  });

  it("should return profile data", async () => {
    const profile = await api.getProfile("node-1");
    expect(profile.id).toBe("node-1");
    expect(profile).toHaveProperty("alias");
  });

  it("should return karma data", async () => {
    const karma = await api.getKarma("node-1");
    expect(karma.nodoId).toBe("node-1");
    expect(karma.karma).toBeGreaterThan(0);
  });

  it("should list active plugins", async () => {
    const plugins = await api.getPlugins();
    expect(Array.isArray(plugins)).toBe(true);
    expect(plugins.length).toBeGreaterThan(0);
  });

  it("should notarize documents", async () => {
    const result = await api.notarizeDocument({ hash: "abc", metadata: {} });
    expect(result.notarized).toBe(true);
    expect(result.hash).toBe("abc");
  });
});
