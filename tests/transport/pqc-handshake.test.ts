import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MemoryTransport } from "../../src/transport/memory.js";
import type { NodoId, Envolvente } from "../../src/types/index.js";
import { TIPO_MENSAJE } from "../../src/types/index.js";
import { bytesAHex, hexABytes } from "../../src/protocol/utils.js";

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

describe("PQC Handshake and Dual-Ready SYNC Encryption", () => {
	const roomId = "pqc-handshake-test-room";

	beforeEach(() => {
		MemoryTransport.resetAll();
	});

	afterEach(() => {
		MemoryTransport.resetAll();
	});

	it("Handshake exitoso entre 2 peers y envio de SYNC cifrado", async () => {
		const nodeA = new EdgeMesh({
			nodoId: "nodeA" as NodoId,
			storageBackend: "mem",
			enablePqcEncryption: true,
			requireAuthz: false,
			heartbeatIntervalMs: 100,
			heartbeatTimeoutMs: 500,
		});

		const nodeB = new EdgeMesh({
			nodoId: "nodeB" as NodoId,
			storageBackend: "mem",
			enablePqcEncryption: true,
			requireAuthz: false,
			heartbeatIntervalMs: 100,
			heartbeatTimeoutMs: 500,
		});

		nodeA.registrarClavePublica("nodeB" as NodoId, nodeB.identity.exportarPublico());
		nodeB.registrarClavePublica("nodeA" as NodoId, nodeA.identity.exportarPublico());

		const transportA = new MemoryTransport("nodeA" as NodoId, { roomId });
		const transportB = new MemoryTransport("nodeB" as NodoId, { roomId });

		nodeA.usarTransport(transportA);
		nodeB.usarTransport(transportB);

		let handshakesCompletados = 0;
		nodeA.on("handshakeCompletado" as any, () => {
			handshakesCompletados++;
		});
		nodeB.on("handshakeCompletado" as any, () => {
			handshakesCompletados++;
		});

		const capturedEnvelopes: Envolvente[] = [];
		const originalEnviar = transportA.enviar.bind(transportA);
		transportA.enviar = async (destino, payload, tipoMensaje) => {
			if (payload && (payload as any).id) {
				capturedEnvelopes.push(payload as Envolvente);
			}
			return originalEnviar(destino, payload, tipoMensaje);
		};

		await nodeA.iniciar();
		await nodeB.iniciar();

		// Manually exchange heartbeats to force immediate discovery
		await nodeA.presence.sendHeartbeat(nodeA.identity);
		await nodeB.presence.sendHeartbeat(nodeB.identity);

		await vi.waitFor(
			() => {
				expect(handshakesCompletados).toBe(2);
			},
			{ timeout: 3000 },
		);

		const syncPromise = new Promise<void>((resolve) => {
			nodeB.on("syncCompletado", () => {
				resolve();
			});
		});

		nodeA.yjsAdapter.getMap("test").set("clave", "valor_secreto_cifrado");

		await syncPromise;

		expect(nodeB.yjsAdapter.getMap("test").get("clave")).toBe("valor_secreto_cifrado");

		const syncEnvelopes = capturedEnvelopes.filter((e) => e.tipo === TIPO_MENSAJE.SYNC);
		expect(syncEnvelopes.length).toBeGreaterThan(0);

		// At least one sync envelope (the delta) must be encrypted and hide cleartext
		let foundEncryptedDelta = false;
		for (const env of syncEnvelopes) {
			const payload = env.payload as any;
			if (payload.encrypted === true) {
				foundEncryptedDelta = true;
				expect(payload.ciphertext).toBeDefined();
				expect(payload.iv).toBeDefined();
				expect(payload.tag).toBeDefined();
				expect(JSON.stringify(env)).not.toContain("valor_secreto_cifrado");
			}
		}
		expect(foundEncryptedDelta).toBe(true);

		await nodeA.detener();
		await nodeB.detener();
	});

	it("Fallback a texto claro cuando un peer no soporta cifrado (enablePqcEncryption = false)", async () => {
		const nodeA = new EdgeMesh({
			nodoId: "nodeA" as NodoId,
			storageBackend: "mem",
			enablePqcEncryption: true,
			requireAuthz: false,
			heartbeatIntervalMs: 100,
			heartbeatTimeoutMs: 500,
		});

		const nodeLegacy = new EdgeMesh({
			nodoId: "nodeLegacy" as NodoId,
			storageBackend: "mem",
			enablePqcEncryption: false,
			requireAuthz: false,
			heartbeatIntervalMs: 100,
			heartbeatTimeoutMs: 500,
		});

		nodeA.registrarClavePublica("nodeLegacy" as NodoId, nodeLegacy.identity.exportarPublico());
		nodeLegacy.registrarClavePublica("nodeA" as NodoId, nodeA.identity.exportarPublico());

		const transportA = new MemoryTransport("nodeA" as NodoId, { roomId });
		const transportLegacy = new MemoryTransport("nodeLegacy" as NodoId, { roomId });

		nodeA.usarTransport(transportA);
		nodeLegacy.usarTransport(transportLegacy);

		const capturedEnvelopes: Envolvente[] = [];
		const originalEnviar = transportA.enviar.bind(transportA);
		transportA.enviar = async (destino, payload, tipoMensaje) => {
			if (payload && (payload as any).id) {
				capturedEnvelopes.push(payload as Envolvente);
			}
			return originalEnviar(destino, payload, tipoMensaje);
		};

		await nodeA.iniciar();
		await nodeLegacy.iniciar();

		await nodeA.presence.sendHeartbeat(nodeA.identity);
		await nodeLegacy.presence.sendHeartbeat(nodeLegacy.identity);

		await new Promise((resolve) => setTimeout(resolve, 300));

		const syncPromise = new Promise<void>((resolve) => {
			nodeLegacy.on("syncCompletado", () => {
				resolve();
			});
		});

		nodeA.yjsAdapter.getMap("test").set("clave", "valor_en_claro");

		await syncPromise;

		expect(nodeLegacy.yjsAdapter.getMap("test").get("clave")).toBe("valor_en_claro");

		const syncEnvelopes = capturedEnvelopes.filter((e) => e.tipo === TIPO_MENSAJE.SYNC);
		expect(syncEnvelopes.length).toBeGreaterThan(0);

		let foundPlaintextDelta = false;
		for (const env of syncEnvelopes) {
			const payload = env.payload as any;
			if (payload.encrypted !== true && payload.tipoSync === "delta") {
				foundPlaintextDelta = true;
			}
		}
		expect(foundPlaintextDelta).toBe(true);

		await nodeA.detener();
		await nodeLegacy.detener();
	});

	it("Un adversario sin claves de sesion interceptando el trafico no puede descifrar o suplantar", async () => {
		const nodeA = new EdgeMesh({
			nodoId: "nodeA" as NodoId,
			storageBackend: "mem",
			enablePqcEncryption: true,
			requireAuthz: false,
			heartbeatIntervalMs: 100,
			heartbeatTimeoutMs: 500,
		});

		const nodeB = new EdgeMesh({
			nodoId: "nodeB" as NodoId,
			storageBackend: "mem",
			enablePqcEncryption: true,
			requireAuthz: false,
			heartbeatIntervalMs: 100,
			heartbeatTimeoutMs: 500,
		});

		nodeA.registrarClavePublica("nodeB" as NodoId, nodeB.identity.exportarPublico());
		nodeB.registrarClavePublica("nodeA" as NodoId, nodeA.identity.exportarPublico());

		const transportA = new MemoryTransport("nodeA" as NodoId, { roomId });
		const transportB = new MemoryTransport("nodeB" as NodoId, { roomId });

		nodeA.usarTransport(transportA);
		nodeB.usarTransport(transportB);

		let handshakesCompletados = 0;
		nodeA.on("handshakeCompletado" as any, () => {
			handshakesCompletados++;
		});
		nodeB.on("handshakeCompletado" as any, () => {
			handshakesCompletados++;
		});

		await nodeA.iniciar();
		await nodeB.iniciar();

		await nodeA.presence.sendHeartbeat(nodeA.identity);
		await nodeB.presence.sendHeartbeat(nodeB.identity);

		await vi.waitFor(() => {
			expect(handshakesCompletados).toBe(2);
		});

		let capturedEnvelope: Envolvente | null = null;
		const originalEnviar = transportA.enviar.bind(transportA);
		transportA.enviar = async (destino, payload, tipoMensaje) => {
			if (payload && (payload as any).id) {
				capturedEnvelope = payload as Envolvente;
			}
			return originalEnviar(destino, payload, tipoMensaje);
		};

		nodeA.yjsAdapter.getMap("test").set("clave", "secreto_maximo");

		await vi.waitFor(() => {
			expect(capturedEnvelope).not.toBeNull();
		});

		const env = capturedEnvelope!;
		const encPayload = env.payload as any;
		expect(encPayload.encrypted).toBe(true);

		const randomSecret = new Uint8Array(32);
		const badChannel = new (nodeA.peerSecureChannels.get("nodeB" as NodoId)!.channel!.constructor as any)(randomSecret);

		expect(() => {
			badChannel.decrypt(
				hexABytes(encPayload.ciphertext),
				hexABytes(encPayload.iv),
				hexABytes(encPayload.tag),
			);
		}).toThrow();

		const tamperedPayload = {
			...encPayload,
			ciphertext: bytesAHex(new Uint8Array(1088)),
		};
		const tamperedEnvelope: Envolvente = {
			...env,
			id: "adversary-tampered-id-bypass-deduplication",
			payload: tamperedPayload,
		};

		let errorTriggered = false;
		nodeB.on("error", (ev) => {
			if (ev.detail.mensaje.includes("Error descifrando SYNC")) {
				errorTriggered = true;
			}
		});

		await nodeB.recibirEnvelope(tamperedEnvelope);

		expect(errorTriggered).toBe(true);

		await nodeA.detener();
		await nodeB.detener();
	});
});
