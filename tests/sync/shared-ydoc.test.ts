import { afterEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import { EdgeMesh } from "../../src/edge-mesh.js";
import type { NodoId } from "../../src/types/index.js";

vi.mock("idb", () => ({
	openDB: vi.fn().mockResolvedValue({
		get: vi.fn(),
		put: vi.fn(),
		delete: vi.fn(),
		getAll: vi.fn().mockResolvedValue([]),
		clear: vi.fn(),
		close: vi.fn(),
		objectStoreNames: { contains: vi.fn().mockReturnValue(true) },
	}),
}));

describe("Phase B: shared Y.Doc", () => {
	const meshes: EdgeMesh[] = [];

	afterEach(async () => {
		for (const m of meshes) {
			await m.detener().catch(() => undefined);
		}
		meshes.length = 0;
	});

	it("uses the injected document for maps and does not destroy it on stop", async () => {
		const hostDoc = new Y.Doc();
		hostDoc.getMap("products").set("p1", { id: "p1", name: "Host" });

		const mesh = new EdgeMesh({
			nodoId: "shared-node" as NodoId,
			storageBackend: "mem",
			yDoc: hostDoc as never,
			requireAuthz: false,
			heartbeatIntervalMs: 60_000,
		});
		meshes.push(mesh);
		await mesh.iniciar();

		expect(mesh.isSharedYDoc()).toBe(true);
		expect(mesh.yjsAdapter.doc).toBe(hostDoc);
		expect(mesh.yjsAdapter.getMap("products").get("p1")).toEqual({
			id: "p1",
			name: "Host",
		});

		// Writes through adapter are visible on host doc
		mesh.yjsAdapter.getMap("products").set("p2", { id: "p2", name: "Mesh" });
		expect(hostDoc.getMap("products").get("p2")).toEqual({
			id: "p2",
			name: "Mesh",
		});

		await mesh.detener();

		// Host doc must remain usable after mesh stop
		expect(hostDoc.getMap("products").get("p1")).toEqual({
			id: "p1",
			name: "Host",
		});
		hostDoc.getMap("products").set("p3", { id: "p3", name: "StillAlive" });
		expect(hostDoc.getMap("products").get("p3")).toBeTruthy();

		hostDoc.destroy();
	});

	it("two meshes can share one doc (same CRDT truth)", async () => {
		const shared = new Y.Doc();
		const a = new EdgeMesh({
			nodoId: "a" as NodoId,
			storageBackend: "mem",
			yDoc: shared as never,
			requireAuthz: false,
			heartbeatIntervalMs: 60_000,
		});
		const b = new EdgeMesh({
			nodoId: "b" as NodoId,
			storageBackend: "mem",
			yDoc: shared as never,
			requireAuthz: false,
			heartbeatIntervalMs: 60_000,
		});
		meshes.push(a, b);
		await a.iniciar();
		await b.iniciar();

		a.yjsAdapter.getMap("clients").set("c1", { id: "c1", name: "Ana" });
		expect(b.yjsAdapter.getMap("clients").get("c1")).toEqual({
			id: "c1",
			name: "Ana",
		});
	});
});
