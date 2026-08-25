import { describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MeshGossip, type GossipMessage } from "../../src/mesh/index.js";
import { createEnvelope } from "../../src/protocol/index.js";
import { MemoryTransport } from "../../src/transport/memory.js";
import { type NodoId, TIPO_MENSAJE } from "../../src/types/index.js";

describe("Mesh Gossip Integration in EdgeMesh", () => {
	it("processes incoming GOSSIP envelopes and emits gossipRecibido event", async () => {
		const nodeA = "nodo-a" as NodoId;
		const nodeB = "nodo-b" as NodoId;

		const mesh = new EdgeMesh({
			nodoId: nodeA,
			storageBackend: "mem",
		});

		const receivedGossip: GossipMessage[] = [];
		mesh.on("gossipRecibido" as any, (ev: any) => {
			receivedGossip.push(ev.detail.mensaje);
		});

		const gossipMsg: GossipMessage = {
			id: "gossip-uuid-1",
			namespace: "global",
			ttl: 5,
			payload: { topic: "discovery", data: "peer-info" },
			origen: nodeB,
			timestamp: Date.now(),
			ruta: [nodeB],
		};

		const env = createEnvelope(
			TIPO_MENSAJE.GOSSIP,
			nodeB,
			nodeA,
			{ tipo: "gossip", mensaje: gossipMsg },
		);

		await (mesh as any).procesarMensaje(env);

		expect(receivedGossip.length).toBe(1);
		expect(receivedGossip[0].id).toBe("gossip-uuid-1");
		expect(receivedGossip[0].payload).toEqual({ topic: "discovery", data: "peer-info" });

		await mesh.detener();
	});

	it("does not re-propagate gossip when TTL is 0 or negative", async () => {
		const nodeA = "nodo-a" as NodoId;
		const nodeB = "nodo-b" as NodoId;

		const mesh = new EdgeMesh({
			nodoId: nodeA,
			storageBackend: "mem",
		});

		const receivedGossip: GossipMessage[] = [];
		mesh.on("gossipRecibido" as any, (ev: any) => {
			receivedGossip.push(ev.detail.mensaje);
		});

		const expiredGossip: GossipMessage = {
			id: "expired-gossip-1",
			namespace: "global",
			ttl: 0,
			payload: { data: "old" },
			origen: nodeB,
			timestamp: Date.now(),
			ruta: [nodeB],
		};

		const env = createEnvelope(
			TIPO_MENSAJE.GOSSIP,
			nodeB,
			nodeA,
			{ tipo: "gossip", mensaje: expiredGossip },
		);

		await (mesh as any).procesarMensaje(env);

		expect(receivedGossip.length).toBe(0);

		await mesh.detener();
	});

	it("deduplicates identical gossip messages arriving multiple times", async () => {
		const nodeA = "nodo-a" as NodoId;
		const nodeB = "nodo-b" as NodoId;

		const mesh = new EdgeMesh({
			nodoId: nodeA,
			storageBackend: "mem",
		});

		let receiveCount = 0;
		mesh.on("gossipRecibido" as any, () => {
			receiveCount++;
		});

		const duplicateGossip: GossipMessage = {
			id: "duplicate-uuid-99",
			namespace: "global",
			ttl: 3,
			payload: { value: 42 },
			origen: nodeB,
			timestamp: Date.now(),
			ruta: [nodeB],
		};

		const env = createEnvelope(
			TIPO_MENSAJE.GOSSIP,
			nodeB,
			nodeA,
			{ tipo: "gossip", mensaje: duplicateGossip },
		);

		// First delivery
		await (mesh as any).procesarMensaje(env);
		expect(receiveCount).toBe(1);

		// Duplicate delivery
		await (mesh as any).procesarMensaje(env);
		expect(receiveCount).toBe(1);

		await mesh.detener();
	});

	it("publishes gossip to peers via publicarGossip()", async () => {
		const nodeA = "nodo-a" as NodoId;

		const mesh = new EdgeMesh({
			nodoId: nodeA,
			storageBackend: "mem",
		});

		const propagarSpy = vi.spyOn(mesh.meshGossip, "propagarGossip");

		await mesh.publicarGossip({ greeting: "hello mesh" }, "chat", 4);

		expect(propagarSpy).toHaveBeenCalledTimes(1);
		const calledArg = propagarSpy.mock.calls[0][0];
		expect(calledArg.namespace).toBe("chat");
		expect(calledArg.ttl).toBe(4);
		expect(calledArg.origen).toBe(nodeA);
		expect(calledArg.payload).toEqual({ greeting: "hello mesh" });
		expect(typeof calledArg.id).toBe("string");

		await mesh.detener();
	});
});
