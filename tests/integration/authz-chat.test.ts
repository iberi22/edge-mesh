import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChatChannel, TIPO_CANAL } from "../../src/chat/index.js";
import { CAPACIDAD_ESTANDAR } from "../../src/authz/index.js";
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

describe("Integration: Authz + Chat", () => {
	const roomId = "authz-chat-room";

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

	it("should initialize ChatChannel correctly on separate nodes", async () => {
		const nodeA = await makeNode("node-a");
		const channel = new ChatChannel(nodeA.config.nodoId, "general", nodeA.yjsAdapter, TIPO_CANAL.PUBLICO);

		expect(channel.nodoId).toBe("node-a");
		expect(channel.nombreCanal).toBe("general");
		expect(channel.tipoCanal).toBe(TIPO_CANAL.PUBLICO);

		await nodeA.detener();
	});

	it("should share chat message between authorized nodes", async () => {
		const nodeA = await makeNode("node-a");
		const nodeB = await makeNode("node-b");

		// Node B grants Node A write capabilities
		nodeB.authorizer.concederCapacidad(
			"global",
			nodeA.config.nodoId,
			CAPACIDAD_ESTANDAR.ESCRIBIR,
		);

		const channelA = new ChatChannel(nodeA.config.nodoId, "general", nodeA.yjsAdapter);
		const channelB = new ChatChannel(nodeB.config.nodoId, "general", nodeB.yjsAdapter);

		await channelA.unirseAlCanal();
		await channelB.unirseAlCanal();

		const messageReceivedPromise = new Promise<void>((resolve) => {
			channelB.addEventListener("mensaje", () => {
				resolve();
			});
		});

		await channelA.enviarMensaje("Hello Node B!");

		// Manually trigger broadcast since YJS Adapter broadcast is verified via update triggers
		await nodeA.broadcastYjsUpdate(nodeA.yjsAdapter.getState());

		await Promise.race([
			messageReceivedPromise,
			new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout waiting for message sync")), 1500)),
		]);

		const historyB = await channelB.obtenerHistorial();
		expect(historyB.length).toBe(1);
		expect(historyB[0].text).toBe("Hello Node B!");
		expect(historyB[0].sender).toBe("node-a");

		await nodeA.detener();
		await nodeB.detener();
	});

	it("should block message synchronization if sender lacks write capability", async () => {
		const nodeA = await makeNode("node-a");
		const nodeB = await makeNode("node-b");

		// Node B DOES NOT grant Node A write capabilities
		const channelA = new ChatChannel(nodeA.config.nodoId, "general", nodeA.yjsAdapter);
		const channelB = new ChatChannel(nodeB.config.nodoId, "general", nodeB.yjsAdapter);

		await channelA.unirseAlCanal();
		await channelB.unirseAlCanal();

		const errors: string[] = [];
		nodeB.on("error", (ev) => {
			errors.push(ev.detail.mensaje);
		});

		await channelA.enviarMensaje("Unpermitted hello");
		await nodeA.broadcastYjsUpdate(nodeA.yjsAdapter.getState());

		// Wait briefly to allow processing
		await new Promise((resolve) => setTimeout(resolve, 300));

		const historyB = await channelB.obtenerHistorial();
		expect(historyB.length).toBe(0);
		expect(errors.some((m) => m.includes("SYNC denegado"))).toBe(true);

		await nodeA.detener();
		await nodeB.detener();
	});

	it("should allow chat message synchronization when sender has admin capability", async () => {
		const nodeA = await makeNode("node-a");
		const nodeB = await makeNode("node-b");

		// Node B grants Node A admin capabilities, which includes write
		nodeB.authorizer.concederCapacidad(
			"global",
			nodeA.config.nodoId,
			CAPACIDAD_ESTANDAR.ADMIN,
		);

		const channelA = new ChatChannel(nodeA.config.nodoId, "general", nodeA.yjsAdapter);
		const channelB = new ChatChannel(nodeB.config.nodoId, "general", nodeB.yjsAdapter);

		await channelA.unirseAlCanal();
		await channelB.unirseAlCanal();

		const messageReceivedPromise = new Promise<void>((resolve) => {
			channelB.addEventListener("mensaje", () => {
				resolve();
			});
		});

		await channelA.enviarMensaje("Admin greetings");
		await nodeA.broadcastYjsUpdate(nodeA.yjsAdapter.getState());

		await Promise.race([
			messageReceivedPromise,
			new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 1000)),
		]);

		const historyB = await channelB.obtenerHistorial();
		expect(historyB.length).toBe(1);
		expect(historyB[0].text).toBe("Admin greetings");

		await nodeA.detener();
		await nodeB.detener();
	});

	it("should block message synchronization once capabilities are revoked", async () => {
		const nodeA = await makeNode("node-a");
		const nodeB = await makeNode("node-b");

		// Grant permission
		nodeB.authorizer.concederCapacidad(
			"global",
			nodeA.config.nodoId,
			CAPACIDAD_ESTANDAR.ESCRIBIR,
		);

		const channelA = new ChatChannel(nodeA.config.nodoId, "general", nodeA.yjsAdapter);
		const channelB = new ChatChannel(nodeB.config.nodoId, "general", nodeB.yjsAdapter);

		await channelA.unirseAlCanal();
		await channelB.unirseAlCanal();

		// Send first permitted message
		await channelA.enviarMensaje("Allowed message");
		await nodeA.broadcastYjsUpdate(nodeA.yjsAdapter.getState());
		await new Promise((resolve) => setTimeout(resolve, 300));

		// Revoke permission
		nodeB.authorizer.revocarCapacidad(
			"global",
			nodeA.config.nodoId,
			CAPACIDAD_ESTANDAR.ESCRIBIR,
		);

		// Send second message, should be blocked
		await channelA.enviarMensaje("Revoked message");
		await nodeA.broadcastYjsUpdate(nodeA.yjsAdapter.getState());
		await new Promise((resolve) => setTimeout(resolve, 300));

		const historyB = await channelB.obtenerHistorial();
		// Only the first message should be synchronized
		expect(historyB.length).toBe(1);
		expect(historyB[0].text).toBe("Allowed message");

		await nodeA.detener();
		await nodeB.detener();
	});
});
