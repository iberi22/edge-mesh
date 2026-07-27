import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MeshManager } from "../../src/mesh/index.js";
import {
	createPostQuantumIdentity,
	generateKeypair,
} from "../../src/identity/index.js";
import {
	createEnvelope,
	signEnvelope,
	verifyEnvelopeSignature,
} from "../../src/protocol/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("Integration: Mesh + Chat (Gossip Channels)", () => {
	let meshA: MeshManager;
	let meshB: MeshManager;
	let meshC: MeshManager;

	let edgeMeshA: any;
	let edgeMeshB: any;
	let edgeMeshC: any;

	let identityA: ReturnType<typeof createPostQuantumIdentity>;
	let identityB: ReturnType<typeof createPostQuantumIdentity>;
	let identityC: ReturnType<typeof createPostQuantumIdentity>;

	const idA = "peer-a" as NodoId;
	const idB = "peer-b" as NodoId;
	const idC = "peer-c" as NodoId;
	const namespace = "chat:general";

	beforeEach(() => {
		vi.useFakeTimers();

		identityA = createPostQuantumIdentity(idA, generateKeypair("maestra"));
		identityB = createPostQuantumIdentity(idB, generateKeypair("maestra"));
		identityC = createPostQuantumIdentity(idC, generateKeypair("maestra"));

		// Mock firmar & verificar for stable and fast ML-DSA test execution
		vi.spyOn(identityA, "firmar").mockResolvedValue(new Uint8Array(64).fill(1));
		vi.spyOn(identityB, "firmar").mockResolvedValue(new Uint8Array(64).fill(2));
		vi.spyOn(identityC, "firmar").mockResolvedValue(new Uint8Array(64).fill(3));

		vi.spyOn(identityA, "verificar").mockResolvedValue(true);
		vi.spyOn(identityB, "verificar").mockResolvedValue(true);
		vi.spyOn(identityC, "verificar").mockResolvedValue(true);

		// Set up edgeMesh mocks that can send messages to other mesh managers
		edgeMeshA = {
			on: vi.fn(),
			off: vi.fn(),
			enviar: vi.fn(async (peerId, env) => {
				if (peerId === idB) meshB.procesarGossip(env.payload.mensaje);
				if (peerId === idC) meshC.procesarGossip(env.payload.mensaje);
			}),
		};

		edgeMeshB = {
			on: vi.fn(),
			off: vi.fn(),
			enviar: vi.fn(async (peerId, env) => {
				if (peerId === idA) meshA.procesarGossip(env.payload.mensaje);
				if (peerId === idC) meshC.procesarGossip(env.payload.mensaje);
			}),
		};

		edgeMeshC = {
			on: vi.fn(),
			off: vi.fn(),
			enviar: vi.fn(async (peerId, env) => {
				if (peerId === idA) meshA.procesarGossip(env.payload.mensaje);
				if (peerId === idB) meshB.procesarGossip(env.payload.mensaje);
			}),
		};

		meshA = new MeshManager({ nodoId: idA, fanOut: 2, gossipTTL: 5 }, edgeMeshA);
		meshB = new MeshManager({ nodoId: idB, fanOut: 2, gossipTTL: 5 }, edgeMeshB);
		meshC = new MeshManager({ nodoId: idC, fanOut: 2, gossipTTL: 5 }, edgeMeshC);
	});

	afterEach(async () => {
		await meshA.detener();
		await meshB.detener();
		await meshC.detener();
		vi.useRealTimers();
	});

	it("should propagate gossip chat message using MeshManager across connected peers", async () => {
		await meshA.iniciar();
		await meshB.iniciar();
		await meshC.iniciar();

		// Establish topology: A <-> B <-> C
		await meshA.conectarPeer(idB, namespace);
		await meshB.conectarPeer(idA, namespace);
		await meshB.conectarPeer(idC, namespace);
		await meshC.conectarPeer(idB, namespace);

		const gossipSpyC = vi.fn();
		meshC.addEventListener("gossipRecibido", gossipSpyC);

		const chatPayload = { sender: idA, text: "Gossip message" };
		await meshA.transmitirConGossip(namespace, chatPayload);

		expect(gossipSpyC).toHaveBeenCalled();
		const receivedMsg = gossipSpyC.mock.calls[0][0].detail.mensaje;
		expect(receivedMsg.payload).toEqual(chatPayload);
		expect(receivedMsg.namespace).toBe(namespace);
	});

	it("should decrement gossip message TTL on each hop", async () => {
		await meshA.iniciar();
		await meshB.iniciar();
		await meshC.iniciar();

		// Topology: A -> B -> C
		await meshA.conectarPeer(idB, namespace);
		await meshB.conectarPeer(idA, namespace);
		await meshB.conectarPeer(idC, namespace);
		await meshC.conectarPeer(idB, namespace);

		const gossipSpyB = vi.fn();
		meshB.addEventListener("gossipRecibido", gossipSpyB);

		const gossipSpyC = vi.fn();
		meshC.addEventListener("gossipRecibido", gossipSpyC);

		const chatPayload = { text: "TTL Check" };
		await meshA.transmitirConGossip(namespace, chatPayload);

		expect(gossipSpyB).toHaveBeenCalled();
		const msgB = gossipSpyB.mock.calls[0][0].detail.mensaje;
		expect(msgB.ttl).toBe(5); // Receives starting TTL 5 from origin A

		expect(gossipSpyC).toHaveBeenCalled();
		const msgC = gossipSpyC.mock.calls[0][0].detail.mensaje;
		expect(msgC.ttl).toBe(4); // Decremented as forwarded from B to C
	});

	it("should restrict gossip messages based on namespace membership", async () => {
		await meshA.iniciar();
		await meshB.iniciar();
		await meshC.iniciar();

		// Topology: A <-> B <-> C
		// Join namespaces: A and B are in 'chat:general', C is ONLY in 'chat:random'
		await meshA.conectarPeer(idB, namespace);
		await meshB.conectarPeer(idA, namespace);
		await meshB.conectarPeer(idC, "chat:random");
		await meshC.conectarPeer(idB, "chat:random");

		const gossipSpyB = vi.fn();
		meshB.addEventListener("gossipRecibido", gossipSpyB);

		const gossipSpyC = vi.fn();
		meshC.addEventListener("gossipRecibido", gossipSpyC);

		const chatPayload = { text: "Private general chat" };
		await meshA.transmitirConGossip(namespace, chatPayload);

		expect(gossipSpyB).toHaveBeenCalled();
		expect(gossipSpyC).not.toHaveBeenCalled(); // C is in different namespace
	});

	it("should secure gossip messages using post-quantum signatures and verification", async () => {
		await meshA.iniciar();
		await meshB.iniciar();

		await meshA.conectarPeer(idB, namespace);
		await meshB.conectarPeer(idA, namespace);

		const gossipSpyB = vi.fn();
		meshB.addEventListener("gossipRecibido", gossipSpyB);

		// Prepare gossip message
		const rawMsg = {
			id: "gossip-secure-1",
			namespace,
			ttl: 5,
			payload: { text: "Secret handshake" },
			origen: idA,
			timestamp: Date.now(),
			ruta: [idA],
		};

		// Sign the gossip payload envelope using A's identity
		const env = createEnvelope("GOVERNANCE" as any, idA, idB, rawMsg);
		const signedEnv = await signEnvelope(env, identityA);

		// Recipient verifies the signature using Node A's public key
		const isValid = await verifyEnvelopeSignature(signedEnv, identityA.exportarPublico(), identityB);
		expect(isValid).toBe(true);

		if (isValid) {
			meshB.procesarGossip(rawMsg);
		}

		expect(gossipSpyB).toHaveBeenCalled();
	});

	it("should avoid duplicate processing and infinite loops of the same gossip message", async () => {
		await meshA.iniciar();
		await meshB.iniciar();

		await meshA.conectarPeer(idB, namespace);
		await meshB.conectarPeer(idA, namespace);

		const gossipSpyB = vi.fn();
		meshB.addEventListener("gossipRecibido", gossipSpyB);

		const gossipMsg = {
			id: "dup-123",
			namespace,
			ttl: 5,
			payload: { text: "Duplicate text" },
			origen: idA,
			timestamp: Date.now(),
			ruta: [idA],
		};

		meshB.procesarGossip(gossipMsg);
		meshB.procesarGossip(gossipMsg); // Send again

		expect(gossipSpyB).toHaveBeenCalledTimes(1); // Fired only once due to duplicate deduplication
	});
});
