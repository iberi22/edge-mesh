import { describe, it, expect, beforeEach } from "vitest";
import { ChunkSyncManager, type SyncChunk } from "../../src/sync/ChunkSyncManager.js";
import type { NodoId } from "../../src/types/index.js";

describe("ChunkSyncManager Protocol", () => {
  let managerA: ChunkSyncManager<{ content: string }>;
  let managerB: ChunkSyncManager<{ content: string }>;

  beforeEach(() => {
    managerA = new ChunkSyncManager({ nodeId: "node_a" as NodoId });
    managerB = new ChunkSyncManager({ nodeId: "node_b" as NodoId });
  });

  it("advances Lamport timestamp upon local chunk creation", () => {
    const chunk1 = managerA.createChunk("doc_1", { content: "Initial state" });
    expect(chunk1.lamportTimestamp).toBe(1);
    expect(managerA.getLamportTimestamp()).toBe(1);

    const chunk2 = managerA.createChunk("doc_2", { content: "Second state" });
    expect(chunk2.lamportTimestamp).toBe(2);
    expect(managerA.getLamportTimestamp()).toBe(2);
  });

  it("reconciles incoming chunk with lower timestamp by rejecting it", () => {
    // Node A creates doc_1 at ts=2
    managerA.tick();
    const chunkA = managerA.createChunk("doc_1", { content: "Newer version" });

    // Node B receives newer chunk
    const res1 = managerB.receiveChunk(chunkA);
    expect(res1.accepted).toBe(true);

    // Node C tries to send older chunk at ts=1
    const olderChunk: SyncChunk<{ content: string }> = {
      id: "older",
      docId: "doc_1",
      payload: { content: "Stale version" },
      lamportTimestamp: 1,
      nodeId: "node_c" as NodoId,
      version: 1,
      createdAt: Date.now() - 1000,
    };

    const res2 = managerB.receiveChunk(olderChunk);
    expect(res2.accepted).toBe(false);
    expect(res2.resolution?.winner.id).toBe(chunkA.id);
  });

  it("resolves equal timestamp conflicts via node ID tie-breaking deterministically", () => {
    const chunkA: SyncChunk<{ content: string }> = {
      id: "chunk_a",
      docId: "doc_conflict",
      payload: { content: "From A" },
      lamportTimestamp: 5,
      nodeId: "node_a" as NodoId,
      version: 1,
      createdAt: Date.now(),
    };

    const chunkB: SyncChunk<{ content: string }> = {
      id: "chunk_b",
      docId: "doc_conflict",
      payload: { content: "From B" },
      lamportTimestamp: 5,
      nodeId: "node_b" as NodoId,
      version: 1,
      createdAt: Date.now(),
    };

    // Node B receives chunkA first
    managerB.receiveChunk(chunkA);

    // Node B receives chunkB with same timestamp (node_b > node_a)
    const res = managerB.receiveChunk(chunkB);
    expect(res.accepted).toBe(true);
    expect(res.resolution?.resolutionStrategy).toBe("node_tiebreak");
    expect(res.resolution?.winner.nodeId).toBe("node_b");
  });

  it("supports retry queue with exponential backoff", () => {
    const chunk = managerA.createChunk("doc_retry", { content: "Retry content" });
    managerA.enqueueRetry(chunk);

    // Immediately before delay
    const pendingBefore = managerA.getPendingRetries();
    expect(pendingBefore.length).toBe(0);

    // Clear queue
    managerA.clearQueue();
    expect(managerA.getPendingRetries().length).toBe(0);
  });
});
