import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CAPACIDAD_ESTANDAR } from "../../src/authz/index.js";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { createEnvelope, signEnvelope } from "../../src/protocol/index.js";
import { MemoryTransport } from "../../src/transport/memory.js";
import type { NodoId } from "../../src/types/index.js";
import { TIPO_MENSAJE } from "../../src/types/index.js";

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

describe("EdgeMesh secure sync path", () => {
	const roomId = "test-room-secure";

	beforeEach(() => {
		MemoryTransport.resetAll();
	});

	afterEach(() => {
		MemoryTransport.resetAll();
	});

	async function makeNode(id: string) {
		const mesh = new EdgeMesh({
			nodoId: id as NodoId,
			storageBackend: "mem",
			requireAuthz: true,
			requireSignedEnvelopes: false,
			heartbeatIntervalMs: 60_000,
			heartbeatTimeoutMs: 120_000,
		});
		const transport = new MemoryTransport(id as NodoId, { roomId });
		mesh.usarTransport(transport);
		await mesh.iniciar();
		return mesh;
	}

	it("rejects remote SYNC when peer lacks write capability", async () => {
		const a = await makeNode("node-a");
		const b = await makeNode("node-b");

		const errors: string[] = [];
		b.on("error", (ev) => errors.push(ev.detail.mensaje));

		a.yjsAdapter.getMap("products").set("p1", { id: "p1", name: "X" });
		const update = a.yjsAdapter.getState();

		await b.recibirEnvelope(
			createEnvelope(
				TIPO_MENSAJE.SYNC,
				"node-a" as NodoId,
				"node-b" as NodoId,
				{
					docId: "default",
					datos: Array.from(update),
					clock: 1,
				},
			),
		);

		expect(b.yjsAdapter.getMap("products").get("p1")).toBeUndefined();
		expect(errors.some((m) => m.includes("SYNC denegado"))).toBe(true);

		await a.detener();
		await b.detener();
	});

	it("applies remote SYNC when peer has write capability", async () => {
		const a = await makeNode("node-a2");
		const b = await makeNode("node-b2");

		b.authorizer.concederCapacidad(
			"global",
			"node-a2" as NodoId,
			CAPACIDAD_ESTANDAR.ESCRIBIR,
		);

		a.yjsAdapter.getMap("products").set("p1", { id: "p1", name: "Allowed" });
		const update = a.yjsAdapter.getState();

		await b.recibirEnvelope(
			createEnvelope(
				TIPO_MENSAJE.SYNC,
				"node-a2" as NodoId,
				"node-b2" as NodoId,
				{
					docId: "default",
					datos: Array.from(update),
					clock: 1,
				},
			),
		);

		expect(b.yjsAdapter.getMap("products").get("p1")).toEqual({
			id: "p1",
			name: "Allowed",
		});

		await a.detener();
		await b.detener();
	});

	it("rejects remote AUTHZ grant from non-admin peer", async () => {
		const victim = await makeNode("victim");
		const attacker = await makeNode("attacker");

		const errors: string[] = [];
		victim.on("error", (ev) => errors.push(ev.detail.mensaje));

		await victim.recibirEnvelope(
			createEnvelope(
				TIPO_MENSAJE.AUTHZ,
				"attacker" as NodoId,
				"victim" as NodoId,
				{
					accion: "conceder",
					espacio: "global",
					sujeto: "attacker",
					capacidad: "admin",
				},
			),
		);

		expect(
			victim.authorizer.verificarCapacidad(
				"global",
				"attacker" as NodoId,
				"admin",
			),
		).toBe(false);
		expect(errors.some((m) => m.includes("AUTHZ denegado"))).toBe(true);

		await victim.detener();
		await attacker.detener();
	});

	it("accepts signed SYNC when requireSignedEnvelopes is on", async () => {
		const a = new EdgeMesh({
			nodoId: "signer-a" as NodoId,
			storageBackend: "mem",
			requireAuthz: true,
			requireSignedEnvelopes: true,
			heartbeatIntervalMs: 60_000,
		});
		const b = new EdgeMesh({
			nodoId: "signer-b" as NodoId,
			storageBackend: "mem",
			requireAuthz: true,
			requireSignedEnvelopes: true,
			heartbeatIntervalMs: 60_000,
		});

		await a.iniciar();
		await b.iniciar();

		b.registrarClavePublica("signer-a" as NodoId, a.identity.exportarPublico());
		b.authorizer.concederCapacidad(
			"global",
			"signer-a" as NodoId,
			CAPACIDAD_ESTANDAR.ESCRIBIR,
		);

		a.yjsAdapter.getMap("m").set("k", 1);
		const update = a.yjsAdapter.getState();
		const unsigned = createEnvelope(
			TIPO_MENSAJE.SYNC,
			"signer-a" as NodoId,
			"signer-b" as NodoId,
			{ docId: "default", datos: Array.from(update), clock: 1 },
		);
		const signed = await signEnvelope(unsigned, a.identity);

		await b.recibirEnvelope(signed);
		expect(b.yjsAdapter.getMap("m").get("k")).toBe(1);

		await a.detener();
		await b.detener();
	});

	it("MemoryTransport relays messages between two nodes", async () => {
		const a = await makeNode("mem-a");
		const b = await makeNode("mem-b");

		b.authorizer.concederCapacidad(
			"global",
			"mem-a" as NodoId,
			CAPACIDAD_ESTANDAR.ESCRIBIR,
		);

		const received = new Promise<void>((resolve) => {
			b.on("syncCompletado", () => resolve());
		});

		a.yjsAdapter.getMap("t").set("x", 42);
		// Manual broadcast (auto path uses origin filter)
		await a.broadcastYjsUpdate(a.yjsAdapter.getState());

		await Promise.race([
			received,
			new Promise((_, reject) =>
				setTimeout(() => reject(new Error("timeout")), 2000),
			),
		]);

		expect(b.yjsAdapter.getMap("t").get("x")).toBe(42);

		await a.detener();
		await b.detener();
	});
});
