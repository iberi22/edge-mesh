import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPostQuantumIdentity, generateKeypair } from "../../src/identity/index.js";
import { EvidentiaManager } from "../../src/maloca/evidentia.js";
import { PolygonBridgeImpl } from "../../src/maloca/polygon-bridge.js";
import { MeshManager } from "../../src/mesh/index.js";
import type { NodoId } from "../../src/types/index.js";
import type { EdgeMesh } from "../../src/edge-mesh.js";

// Mock global crypto for environment where it might be missing
if (global.crypto === undefined) {
	const { crypto } = await import("node:crypto");
	// @ts-expect-error
	global.crypto = crypto;
}

describe("PolygonBridge", () => {
	let bridge: PolygonBridgeImpl;
	let mockContract: any;
	let mockProvider: any;

	beforeEach(() => {
		mockContract = {
			submitAnchor: vi.fn(),
			submitAnchors: vi.fn(),
			verifyProof: vi.fn(),
		};

		mockProvider = {
			getTransaction: vi.fn(),
			getTransactionReceipt: vi.fn(),
			getBlockNumber: vi.fn(),
		};

		bridge = new PolygonBridgeImpl({
			rpcUrl: "http://dummy-rpc-url",
			contractAddress: "0x1234567890123456789012345678901234567890",
			privateKey: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		});

		// Overwrite the internal ethers contract and provider with our mocks
		(bridge as any).contract = mockContract;
		(bridge as any).provider = mockProvider;
	});

	it("debería realizar un submit de anchor exitoso", async () => {
		const mockTx = {
			wait: vi.fn().mockResolvedValue({
				hash: "0xmockedtxhash",
			}),
		};
		mockContract.submitAnchor.mockResolvedValue(mockTx);

		const anchor = {
			merkleRoot: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
			cid: "QmSomeCID",
		};

		const txHash = await bridge.submitAnchor(anchor);

		expect(txHash).toBe("0xmockedtxhash");
		expect(mockContract.submitAnchor).toHaveBeenCalledWith(anchor.merkleRoot, anchor.cid);
	});

	it("debería verificar un proof on-chain exitosamente", async () => {
		mockContract.verifyProof.mockResolvedValue(true);

		const merkleRoot = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
		const leaf = "0xleafhash1234567890abcdef1234567890abcdef1234567890abcdef123456";
		const proof = ["0xproof1", "0xproof2"];

		const isValid = await bridge.verifyOnChain(merkleRoot, proof, leaf);

		expect(isValid).toBe(true);
		expect(mockContract.verifyProof).toHaveBeenCalledWith(merkleRoot, leaf, proof);
	});

	it("debería encolar el anchor localmente si Polygon no está disponible", async () => {
		// Simular desconexión quitando el contrato
		(bridge as any).contract = null;

		const anchor = {
			merkleRoot: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
			cid: "QmSomeCIDOffline",
		};

		await expect(bridge.submitAnchor(anchor)).rejects.toThrow();

		const queue = bridge.getQueue();
		expect(queue).toHaveLength(1);
		expect(queue[0]).toEqual(anchor);
	});

	it("debería soportar batch submission de múltiples anchors en una tx", async () => {
		const anchor1 = { merkleRoot: "0xroot1", cid: "cid1" };
		const anchor2 = { merkleRoot: "0xroot2", cid: "cid2" };

		// Encolarlos simulando modo offline
		(bridge as any).contract = null;
		await expect(bridge.submitAnchor(anchor1)).rejects.toThrow();
		await expect(bridge.submitAnchor(anchor2)).rejects.toThrow();

		expect(bridge.getQueue()).toHaveLength(2);

		// Volver a configurar el contrato
		(bridge as any).contract = mockContract;
		const mockTx = {
			wait: vi.fn().mockResolvedValue({
				hash: "0xbatchtxhash",
			}),
		};
		mockContract.submitAnchors.mockResolvedValue(mockTx);

		const batchTxHash = await bridge.flushQueue();

		expect(batchTxHash).toBe("0xbatchtxhash");
		expect(mockContract.submitAnchors).toHaveBeenCalledWith(
			["0xroot1", "0xroot2"],
			["cid1", "cid2"],
		);
		expect(bridge.getQueue()).toHaveLength(0);
	});

	it("debería integrarse correctamente con EvidentiaManager", async () => {
		const mesh = new MeshManager({ nodoId: "nodo-test" as NodoId }, {} as EdgeMesh);
		vi.spyOn(mesh, "transmitirConGossip").mockResolvedValue(undefined);

		const keypair = generateKeypair();
		const identity = createPostQuantumIdentity("nodo-test" as NodoId, keypair);
		vi.spyOn(identity, "firmar").mockResolvedValue(new Uint8Array(64).fill(1));

		const manager = new EvidentiaManager(identity, mesh, bridge);

		const mockTx = {
			wait: vi.fn().mockResolvedValue({
				hash: "0xintegrationtxhash",
			}),
		};
		mockContract.submitAnchor.mockResolvedValue(mockTx);

		const contenido = { docId: "d1", texto: "Prueba de integración" };
		const evidentia = await manager.notarize(contenido, "TEST_INTEGRATION");

		expect(evidentia.red).toBe("polygon-testnet");
		expect(mockContract.submitAnchor).toHaveBeenCalledWith(
			expect.stringMatching(/^0x/),
			evidentia.contenidoHash,
		);
	});
});
