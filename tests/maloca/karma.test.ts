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

	it("should query project specific karma score", async () => {
		const id = kernel.config.nodoId as NodoId;

		await kernel.karma.emit({
			tipo: "contribution",
			proyecto: "veeduria",
			sujeto: id,
			delta: 50,
			razon: "bridge dev",
			emisor: id,
		});

		await kernel.karma.emit({
			tipo: "contribution",
			proyecto: "xavier",
			sujeto: id,
			delta: 30,
			razon: "ai integration",
			emisor: id,
		});

		expect(kernel.karma.getScore(id)).toBe(80);
		expect(kernel.karma.getScore(id, "veeduria")).toBe(50);
		expect(kernel.karma.getScore(id, "xavier")).toBe(30);
		expect(kernel.karma.getScore(id, "unknown")).toBe(0);
	});

	it("should apply decay globally to all cached nodes", async () => {
		const id1 = "node-alice" as NodoId;
		const id2 = "node-bob" as NodoId;

		await kernel.karma.emit({
			tipo: "initial",
			proyecto: "maloca",
			sujeto: id1,
			delta: 100,
			razon: "setup alice",
			emisor: id1,
		});

		await kernel.karma.emit({
			tipo: "initial",
			proyecto: "maloca",
			sujeto: id2,
			delta: 50,
			razon: "setup bob",
			emisor: id2,
		});

		await kernel.karma.applyDecay(undefined, 0.8);
		expect(kernel.karma.getScore(id1)).toBe(80);
		expect(kernel.karma.getScore(id2)).toBe(40);
	});

	it("should verify transaction signature via verifySignature", async () => {
		const id = kernel.config.nodoId as NodoId;

		const tx = await kernel.karma.emit({
			tipo: "contribution",
			proyecto: "maloca",
			sujeto: id,
			delta: 25,
			razon: "docs update",
			emisor: id,
		});

		const isValid = await kernel.karma.verifySignature(tx);
		expect(isValid).toBe(true);

		const isInvalid = await kernel.karma.verifySignature({
			...tx,
			delta: 9999, // tampered delta
		});
		expect(isInvalid).toBe(false);
	});
});
