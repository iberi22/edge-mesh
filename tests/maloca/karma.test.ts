import { beforeEach, describe, expect, it } from "vitest";
import { generateKeypair } from "../../src/identity/index.js";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import type { NodoId } from "../../src/types/index.js";

describe("KarmaManager", () => {
	let kernel: MalocaKernel;

	beforeEach(async () => {
		const kp = generateKeypair("maestra");

		kernel = new MalocaKernel({
			nodoId: "test-node" as NodoId,
			storageBackend: "mem",
			identitySecret: kp.parPrivado,
		});
		await kernel.iniciar();
	});

	it("should emit and retrieve karma score", async () => {
		const id = kernel.config.nodoId as NodoId;

		await kernel.karma.emit({
			tipo: "contribution",
			proyecto: "maloca",
			sujeto: id,
			delta: 10,
			razon: "feature implementation",
			emisor: id,
		});

		const score = kernel.karma.getScore(id);
		expect(score).toBe(10);
	});

	it("should track scores and history", async () => {
		const id = kernel.config.nodoId as NodoId;

		await kernel.karma.emit({
			tipo: "contribution",
			proyecto: "maloca",
			sujeto: id,
			delta: 5,
			razon: "bug fix",
			emisor: id,
		});

		await kernel.karma.emit({
			tipo: "contribution",
			proyecto: "maloca",
			sujeto: id,
			delta: 3,
			razon: "docs",
			emisor: id,
		});

		expect(kernel.karma.getScore(id)).toBe(8);
		expect(kernel.karma.getHistory(id)).toHaveLength(2);
	});

	it("should apply decay", async () => {
		const id = kernel.config.nodoId as NodoId;

		await kernel.karma.emit({
			tipo: "initial",
			proyecto: "maloca",
			sujeto: id,
			delta: 100,
			razon: "setup",
			emisor: id,
		});

		await kernel.karma.applyDecay(id, 0.9);
		expect(kernel.karma.getScore(id)).toBe(90);
	});

	it("should apply global/cache-wide decay when no nodeId is specified", async () => {
		const id1 = kernel.config.nodoId as NodoId;
		const id2 = "other-node" as NodoId;

		await kernel.karma.emit({
			tipo: "initial",
			proyecto: "maloca",
			sujeto: id1,
			delta: 100,
			razon: "setup 1",
			emisor: id1,
		});

		await kernel.karma.emit({
			tipo: "initial",
			proyecto: "maloca",
			sujeto: id2,
			delta: 200,
			razon: "setup 2",
			emisor: id1,
		});

		// Decay everyone by 10% (factor 0.9)
		await kernel.karma.applyDecay(undefined, 0.9);

		expect(kernel.karma.getScore(id1)).toBe(90);
		expect(kernel.karma.getScore(id2)).toBe(180);
	});

	it("should support pre-defined tx metadata and verify signature with automatic public key lookup", async () => {
		const id = kernel.config.nodoId as NodoId;

		const tx = await kernel.karma.emit({
			tipo: "contribution",
			proyecto: "maloca",
			sujeto: id,
			delta: 15,
			razon: "feature",
			emisor: id,
			id: "custom-id-123",
			timestamp: 123456789,
		});

		expect(tx.id).toBe("custom-id-123");
		expect(tx.timestamp).toBe(123456789);
		expect(tx.firma).toBeDefined();

		// Verify using automatic public key lookup (since getPublicKey was passed to KarmaManager constructor in MalocaKernel)
		const isValid = await kernel.karma.verify(tx);
		expect(isValid).toBe(true);
	});
});
