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
});
