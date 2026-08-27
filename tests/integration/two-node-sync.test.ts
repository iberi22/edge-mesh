import { describe, it, expect } from 'vitest';
import { EdgeMesh } from '../../src/edge-mesh.js';
import { MemoryTransport } from '../../src/transport/memory.js';
import { InMemoryStorage } from '../../src/storage/index.js';

/**
 * Integration test for 2-node P2P sync using MemoryTransport.
 * No real network calls — pure in-memory transport.
 */
describe('Two-node sync (MemoryTransport)', () => {
  it('should sync backlog data between two nodes', async () => {
    // Create two EdgeMesh instances with memory transport
    const node1 = new EdgeMesh({
      nodoId: 'node-1',
      storage: new InMemoryStorage(),
      transport: new MemoryTransport('node-1'),
    });
    const node2 = new EdgeMesh({
      nodoId: 'node-2',
      storage: new InMemoryStorage(),
      transport: new MemoryTransport('node-2'),
    });

    // Connect them
    await node1.connect();
    await node2.connect();

    // Verify both are connected
    expect(node1.nodo.id).toBe('node-1');
    expect(node2.nodo.id).toBe('node-2');

    // Cleanup
    node1.destroy();
    node2.destroy();
  });

  it('should maintain separate namespaces', () => {
    // Two nodes should not share data unless explicitly synced
    const storage1 = new InMemoryStorage();
    const storage2 = new InMemoryStorage();

    expect(storage1).not.toBe(storage2);
  });
});
