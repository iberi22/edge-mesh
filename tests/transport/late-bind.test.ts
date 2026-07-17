import { afterEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MemoryTransport } from "../../src/transport/memory.js";
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

describe("Phase C: late-bind ITransport", () => {
	const meshes: EdgeMesh[] = [];

	afterEach(async () => {
		MemoryTransport.resetAll();
		for (const m of meshes) await m.detener().catch(() => undefined);
		meshes.length = 0;
	});

	it("accepts transport after iniciar() and delivers messages", async () => {
		const room = "late-bind-room";
		const a = new EdgeMesh({
			nodoId: "late-a" as NodoId,
			storageBackend: "mem",
			requireAuthz: false,
			relayLocalYjs: false,
			heartbeatIntervalMs: 60_000,
		});
		const b = new EdgeMesh({
			nodoId: "late-b" as NodoId,
			storageBackend: "mem",
			requireAuthz: false,
			relayLocalYjs: false,
			heartbeatIntervalMs: 60_000,
		});
		meshes.push(a, b);

		// Start without transport
		await a.iniciar();
		await b.iniciar();
		expect(a.obtenerTransport()).toBeNull();

		// Late-bind MemoryTransport (simulates P2PManagerTransport attach)
		const ta = new MemoryTransport("late-a" as NodoId, { roomId: room });
		const tb = new MemoryTransport("late-b" as NodoId, { roomId: room });
		a.usarTransport(ta);
		b.usarTransport(tb);
		await ta.conectar();
		await tb.conectar();

		expect(a.obtenerTransport()).toBe(ta);

		const got = new Promise<void>((resolve) => {
			b.on("mensajeRecibido", () => resolve());
		});

		await a.transmitir({ hello: "phase-c" }, "heartbeat" as never);

		await Promise.race([
			got,
			new Promise((_, reject) =>
				setTimeout(() => reject(new Error("timeout")), 2000),
			),
		]);

		// detach must not break host (memory) forever if we re-bind
		a.detachTransport();
		expect(a.obtenerTransport()).toBeNull();
	});
});
