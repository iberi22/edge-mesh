import { beforeEach, describe, expect, it } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import type { NodoId } from "../../src/types/index.js";

describe("MalocaKernel", () => {
	let kernel: MalocaKernel;

	beforeEach(async () => {
		kernel = new MalocaKernel({
			nodoId: "node1" as NodoId,
			storageBackend: "mem",
		});
		await kernel.iniciar();
	});

	it("should register human node", async () => {
		await kernel.registerNode("humano", new Uint8Array([1]), {
			alias: "Jules",
			karma: 150,
			proyectos: ["swal-core"],
		});

		const profile = kernel.getProfile("node1" as NodoId);
		expect(profile).toBeDefined();
		expect(profile!.alias).toBe("Jules");
		expect(profile!.karma).toBe(150);
		expect(profile!.proyectos).toContain("swal-core");
	});

	it("should register project/service/agent nodes", async () => {
		await kernel.registerNode("servicio", new Uint8Array([2]), {
			id: "service-node",
			tipo: "veeduria-verifier",
			version: "2.1.0",
			endpoint: "https://api.veeduria.mesh",
			capabilidades: ["sign", "verify-contracts"],
		});

		const profile = kernel.getProfile("service-node" as NodoId);
		expect(profile).toBeDefined();
		expect(profile!.tipo).toBe("veeduria-verifier");
		expect(profile!.version).toBe("2.1.0");
		expect(profile!.endpoint).toBe("https://api.veeduria.mesh");
		expect(profile!.capacidades).toContain("sign");
		expect(profile!.capabilidades).toContain("verify-contracts");
	});

	it("should get network status", async () => {
		kernel.connectProject("test-project", {} as any);

		const status = kernel.getNetworkStatus();
		expect(status.nodoId).toBe("node1");
		expect(status.proyectosConectados).toContain("test-project");
	});
});
