import { describe, it, expect, beforeEach, vi } from "vitest";
import { ProfileManager } from "../../src/maloca/perfil.js";
import { OpLog } from "../../src/op-log/index.js";
import { InMemoryStorage } from "../../src/storage/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("ProfileManager", () => {
  let profileManager: ProfileManager;
  let opLog: OpLog;

  beforeEach(() => {
    opLog = new OpLog({ docId: "test_profiles", storage: new InMemoryStorage() });
    profileManager = new ProfileManager(opLog);
  });

  it("should upsert and get a human profile", async () => {
    const perfil = {
      id: "node1",
      identidad: new Uint8Array([1, 2, 3]),
      alias: "Test User",
      nodos: ["node1" as NodoId],
      proyectos: [],
      karma: 0,
      metadatos: {},
    };

    await profileManager.upsertProfile(perfil, "node1" as NodoId);
    const retrieved = profileManager.getProfile("node1");
    expect(retrieved).toEqual(perfil);
  });

  it("should list profiles", async () => {
    const p1 = { id: "n1", alias: "u1" } as any;
    const p2 = { id: "n2", alias: "u2" } as any;

    await profileManager.upsertProfile(p1, "n1" as NodoId);
    await profileManager.upsertProfile(p2, "n1" as NodoId);

    expect(profileManager.listProfiles()).toHaveLength(2);
  });

  it("should sync with OpLog events", async () => {
    const p1 = { id: "n1", alias: "u1" } as any;

    // Simulate remote update via OpLog
    await opLog.append("perfil_update", p1, "n2" as NodoId);

    // ProfileManager should have updated via event listener
    expect(profileManager.getProfile("n1")).toEqual(p1);
  });
});
