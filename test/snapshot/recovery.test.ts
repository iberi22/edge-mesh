import { describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import { MerkleTree } from "../../src/maloca/evidentia.js";
import { generateKeypair } from "../../src/identity/index.js";
import type { NodoId } from "../../src/types/index.js";
import type { Snapshot } from "../../src/snapshot/index.js";

describe("Snapshot Automatic Recovery & OpLog Compaction", () => {
	const node1Id = "node1" as NodoId;

	// Helper to generate a consistent identitySecret Uint8Array
	function createPersistentIdentitySecret(): Uint8Array {
		const kp = generateKeypair("maestra");
		const privLen = kp.parPrivado.length;
		const pubLen = kp.parPublico.length;
		const identitySecret = new Uint8Array(8 + privLen + pubLen);
		const view = new DataView(identitySecret.buffer);
		view.setUint32(0, privLen, true);
		view.setUint32(4, pubLen, true);
		identitySecret.set(kp.parPrivado, 8);
		identitySecret.set(kp.parPublico, 8 + privLen);
		return identitySecret;
	}

	it("should automatically generate snapshots periodically", async () => {
		vi.useFakeTimers();
		try {
			const mesh = new MalocaKernel({
				nodoId: node1Id,
				storageBackend: "mem",
				snapshotConfig: {
					intervalMs: 1000, // 1 second
					maxSnapshots: 3,
					include: ["global"],
				},
			});

			await mesh.iniciar();

			// Add some initial state
			mesh.authorizer.concederCapacidad("global", "peer2" as NodoId, "write");
			mesh.authorizer.updateRole("peer2" as NodoId, "editor");
			await mesh.profiles.upsertProfile(
				{
					id: "peer2",
					identidad: new Uint8Array([1, 2, 3]),
					alias: "Bob",
					nodos: ["peer2" as NodoId],
					proyectos: [],
					metadatos: {},
				},
				"node1",
			);

			// Advance time to trigger snapshot
			await vi.advanceTimersByTimeAsync(1100);

			// Check snapshot saved in storage
			const latest = await mesh.storage.get<Snapshot>("storage:snapshot:latest");
			expect(latest).not.toBeNull();
			const snapshot = latest!.valor;

			expect(snapshot.id).toBeDefined();
			expect(snapshot.timestamp).toBeGreaterThan(0);
			expect(snapshot.state.grants.length).toBeGreaterThan(0);
			expect(snapshot.state.roleAssignments.length).toBeGreaterThan(0);
			expect(snapshot.state.profiles.length).toBeGreaterThan(0);

			await mesh.detener();
		} finally {
			vi.useRealTimers();
		}
	});

	it("should recover full state from snapshot + incremental OpLog upon starting", async () => {
		const storage = new (await import("../../src/storage/index.js")).InMemoryStorage();
		const identitySecret = createPersistentIdentitySecret();

		// 1. First run: Start, modify state, manually trigger snapshot, and then add extra operations
		const mesh1 = new MalocaKernel({
			nodoId: node1Id,
			identitySecret,
			storageBackend: "mem",
			snapshotConfig: {
				intervalMs: 10000,
				maxSnapshots: 3,
				include: ["global"],
			},
		});
		(mesh1 as any).storage = storage;
		(mesh1.authorizer as any).storage = storage;
		for (const log of (mesh1 as any).logsDoc.values()) {
			(log as any).storage = storage;
		}

		await mesh1.iniciar();

		mesh1.authorizer.concederCapacidad("global", "peer2" as NodoId, "write");
		mesh1.authorizer.updateRole("peer2" as NodoId, "editor");
		await mesh1.profiles.upsertProfile(
			{
				id: "peer2",
				identidad: new Uint8Array([1, 2, 3]),
				alias: "Bob",
				nodos: ["peer2" as NodoId],
				proyectos: [],
				metadatos: {},
			},
			"node1",
		);

		// Manually trigger snapshot
		const s = await mesh1.generarSnapshotAutomatico();
		expect(s).not.toBeNull();

		// Add incremental operations AFTER snapshot
		await mesh1.profiles.upsertProfile(
			{
				id: "peer3",
				identidad: new Uint8Array([4, 5, 6]),
				alias: "Charlie",
				nodos: ["peer3" as NodoId],
				proyectos: [],
				metadatos: {},
			},
			"node1",
		);

		await mesh1.detener();

		// 2. Second run: Restore state using the same storage (recovery)
		const mesh2 = new MalocaKernel({
			nodoId: node1Id,
			identitySecret,
			storageBackend: "mem",
			snapshotConfig: {
				intervalMs: 10000,
				maxSnapshots: 3,
				include: ["global"],
			},
		});
		(mesh2 as any).storage = storage;
		(mesh2.authorizer as any).storage = storage;
		for (const log of (mesh2 as any).logsDoc.values()) {
			(log as any).storage = storage;
		}

		await mesh2.iniciar();

		// Check if grants were restored
		const allowed = mesh2.authorizer.verificarCapacidad("global", "peer2" as NodoId, "write");
		expect(allowed).toBe(true);

		// Check if role assignments were restored
		const role = mesh2.authorizer.obtenerRoles().get("peer2" as NodoId)?.rol;
		expect(role).toBe("editor");

		// Check if Bob (from snapshot) is restored
		const bobProfile = mesh2.profiles.getProfile("peer2");
		expect(bobProfile).toBeDefined();
		expect(bobProfile?.alias).toBe("Bob");

		// Check if Charlie (from incremental OpLog) is restored
		const charlieProfile = mesh2.profiles.getProfile("peer3");
		expect(charlieProfile).toBeDefined();
		expect(charlieProfile?.alias).toBe("Charlie");

		await mesh2.detener();
	});

	it("should compact OpLog by removing operations older than snapshot", async () => {
		const mesh = new MalocaKernel({
			nodoId: node1Id,
			storageBackend: "mem",
			snapshotConfig: {
				intervalMs: 10000,
				maxSnapshots: 3,
				include: ["global"],
			},
		});

		await mesh.iniciar();

		// Add operation
		await mesh.profiles.upsertProfile(
			{
				id: "peer2",
				identidad: new Uint8Array([1, 2, 3]),
				alias: "Bob",
				nodos: ["peer2" as NodoId],
				proyectos: [],
				metadatos: {},
			},
			"node1",
		);

		const opLog = mesh.obtenerOLog("maloca_profiles");
		const sequenceBefore = opLog.obtenerUltimaSecuencia();
		expect(sequenceBefore).toBeGreaterThan(0);

		// Trigger snapshot manually
		await mesh.generarSnapshotAutomatico();

		// After snapshot, the OpLog is compacted.
		// All operations <= sequenceBefore should be deleted.
		const remainingOps = await opLog.obtenerTodas();
		expect(remainingOps.length).toBe(0);

		await mesh.detener();
	});

	it("should fall back to full OpLog recovery if the snapshot signature/data is corrupt", async () => {
		const storage = new (await import("../../src/storage/index.js")).InMemoryStorage();
		const identitySecret = createPersistentIdentitySecret();

		// 1. Create a clean run to save state
		const mesh1 = new MalocaKernel({
			nodoId: node1Id,
			identitySecret,
			storageBackend: "mem",
			snapshotConfig: {
				intervalMs: 10000,
				maxSnapshots: 3,
				include: ["global"],
			},
		});
		(mesh1 as any).storage = storage;
		(mesh1.authorizer as any).storage = storage;
		for (const log of (mesh1 as any).logsDoc.values()) {
			(log as any).storage = storage;
		}

		await mesh1.iniciar();

		mesh1.authorizer.concederCapacidad("global", "peer2" as NodoId, "write");

		// Trigger snapshot manually (will be empty except authorizer)
		await mesh1.generarSnapshotAutomatico();

		// Add Bob's profile AFTER generating the snapshot so Bob's op remains in the OpLog (and is not compacted!)
		await mesh1.profiles.upsertProfile(
			{
				id: "peer2",
				identidad: new Uint8Array([1, 2, 3]),
				alias: "Bob",
				nodos: ["peer2" as NodoId],
				proyectos: [],
				metadatos: {},
			},
			"node1",
		);

		await mesh1.detener();

		// 2. Corrupt the saved snapshot in storage
		const latestEntry = await storage.get<Snapshot>("storage:snapshot:latest");
		expect(latestEntry).not.toBeNull();
		const corruptSnapshot = {
			...latestEntry!.valor,
			signature: "00".repeat(64), // Invalid signature
		};
		await storage.set("storage:snapshot:latest", corruptSnapshot);

		// 3. Second run: Start up. Recovery should fail because of signature and fall back to rebuilding from OpLog.
		const mesh2 = new MalocaKernel({
			nodoId: node1Id,
			identitySecret,
			storageBackend: "mem",
			snapshotConfig: {
				intervalMs: 10000,
				maxSnapshots: 3,
				include: ["global"],
			},
		});
		(mesh2 as any).storage = storage;
		(mesh2.authorizer as any).storage = storage;
		for (const log of (mesh2 as any).logsDoc.values()) {
			(log as any).storage = storage;
		}

		// Listen for recovery error event
		let errorTriggered = false;
		mesh2.on("error", (ev) => {
			if (ev.detail.mensaje && ev.detail.mensaje.includes("Recuperacion desde snapshot fallida")) {
				errorTriggered = true;
			}
		});

		await mesh2.iniciar();

		expect(errorTriggered).toBe(true);

		// Check if Bob profile is still recovered via full OpLog playback fallback
		const bobProfile = mesh2.profiles.getProfile("peer2");
		expect(bobProfile).toBeDefined();
		expect(bobProfile?.alias).toBe("Bob");

		await mesh2.detener();
	});

	it("should maintain a chain of at most 3 snapshots", async () => {
		const mesh = new MalocaKernel({
			nodoId: node1Id,
			storageBackend: "mem",
			snapshotConfig: {
				intervalMs: 10000,
				maxSnapshots: 3,
				include: ["global"],
			},
		});

		await mesh.iniciar();

		// Let's manually trigger snapshot generation 5 times to check history count and chain linkage.
		const s1 = await mesh.generarSnapshotAutomatico();
		expect(s1?.prevSnapshotId).toBeUndefined();

		const s2 = await mesh.generarSnapshotAutomatico();
		expect(s2?.prevSnapshotId).toBe(s1?.id);

		const s3 = await mesh.generarSnapshotAutomatico();
		expect(s3?.prevSnapshotId).toBe(s2?.id);

		const s4 = await mesh.generarSnapshotAutomatico();
		expect(s4?.prevSnapshotId).toBe(s3?.id);

		const s5 = await mesh.generarSnapshotAutomatico();
		expect(s5?.prevSnapshotId).toBe(s4?.id);

		// Verify that storage history contains at most 3 snapshots (s3, s4, s5)
		const historyEntry = await mesh.storage.get<any[]>("storage:snapshot:history");
		expect(historyEntry).not.toBeNull();
		const history = historyEntry!.valor;
		expect(history.length).toBe(3);

		// It should be the last 3 snapshots
		const ids = history.map((s) => s.id);
		expect(ids).toContain(s3?.id);
		expect(ids).toContain(s4?.id);
		expect(ids).toContain(s5?.id);
		expect(ids).not.toContain(s1?.id);
		expect(ids).not.toContain(s2?.id);

		await mesh.detener();
	});
});
