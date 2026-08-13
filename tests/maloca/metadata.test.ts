import { beforeEach, describe, expect, it } from "vitest";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import type { NodoId } from "../../src/types/index.js";

describe("MetadataManager", () => {
	let kernel: MalocaKernel;

	beforeEach(async () => {
		kernel = new MalocaKernel({
			nodoId: "test-node" as NodoId,
			storageBackend: "mem",
		});
		await kernel.iniciar();
	});

	it("should get network status", () => {
		const status = kernel.getNetworkStatus();
		expect(status).toHaveProperty("nodoId");
		expect(status).toHaveProperty("proyectosConectados");
	});

	it("should sync and retrieve shared metadata", async () => {
		await kernel.registerNode("humano", new Uint8Array([1]), {
			alias: "Alice",
		});
		const shared = kernel.getNetworkStatus();
		expect(shared.perfilesRegistrados).toBeGreaterThanOrEqual(1);
	});

	it("should provide profile cache", async () => {
		await kernel.registerNode("humano", new Uint8Array([1]), {
			alias: "Alice",
		});
		const profile = kernel.getProfile("test-node" as NodoId);
		expect(profile).toBeDefined();
		expect(profile!.alias).toBe("Alice");
	});

	it("should verify specialized MetadataManager methods and OpLog syncing", async () => {
		// 1. getNetworkStatus
		const status = kernel.metadata.getNetworkStatus();
		expect(status.topologia).toBe("mesh-p2p");
		expect(status.latenciaPromedio).toBeDefined();

		// 2. getProfileCache
		const profileCache = kernel.metadata.getProfileCache();
		expect(profileCache).toHaveProperty("count");

		// 3. syncMetadata with key and value
		await kernel.metadata.syncMetadata("repositorios", ["repo1", "repo2"]);

		const shared = kernel.metadata.getSharedMetadata();
		expect(shared.repositorios).toContain("repo1");

		// 4. syncMetadata (OpLog replay check)
		// We can trigger an implicit sync via OpLog
		await kernel.metadata.syncMetadata();
		const sharedAfter = kernel.metadata.getSharedMetadata();
		expect(sharedAfter.repositorios).toContain("repo1");
	});
});
