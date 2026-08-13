import { beforeEach, describe, expect, it } from "vitest";
import { MalocaKernel } from "../../src/maloca/kernel.js";
import type { NodoId } from "../../src/types/index.js";

describe("ProfileManager", () => {
	let kernel: MalocaKernel;

	beforeEach(async () => {
		kernel = new MalocaKernel({
			nodoId: "node-alice" as NodoId,
			storageBackend: "mem",
		});
		await kernel.iniciar();
	});

	it("should register and get a human profile", async () => {
		await kernel.registerNode("humano", new Uint8Array([1, 2, 3]), {
			alias: "Alice",
		});

		const retrieved = kernel.getProfile("node-alice" as NodoId);
		expect(retrieved).toBeDefined();
		expect(retrieved!.alias).toBe("Alice");
	});

	it("should update a profile", async () => {
		await kernel.registerNode("humano", new Uint8Array([1, 2, 3]), {
			alias: "Alice",
		});

		await kernel.profiles.upsertProfile(
			{
				id: "node-alice" as NodoId,
				alias: "Alice Updated",
				identidad: new Uint8Array([1, 2, 3]),
				nodos: ["node-alice" as NodoId],
				proyectos: [],
				metadatos: {},
			},
			"node-alice" as NodoId,
		);

		const retrieved = kernel.getProfile("node-alice" as NodoId);
		expect(retrieved).toBeDefined();
		expect(retrieved!.alias).toBe("Alice Updated");
	});

	it("should search for profiles", async () => {
		await kernel.profiles.upsertProfile(
			{
				id: "p1" as NodoId,
				alias: "Alice",
				identidad: new Uint8Array([1]),
				nodos: ["p1" as NodoId],
				proyectos: [],
				metadatos: {},
			},
			"p1",
		);

		await kernel.profiles.upsertProfile(
			{
				id: "p2" as NodoId,
				alias: "Bob",
				identidad: new Uint8Array([2]),
				nodos: ["p2" as NodoId],
				proyectos: [],
				metadatos: {},
			},
			"p2",
		);

		const all = kernel.profiles.listProfiles();
		expect(all.length).toBe(2);

		const results = kernel.profiles.searchProfiles("Ali");
		expect(results).toHaveLength(1);
		expect(results[0].alias).toBe("Alice");
	});

	it("should link a profile to a project", async () => {
		await kernel.registerNode("humano", new Uint8Array([1, 2, 3]), {
			alias: "Alice",
		});

		await kernel.profiles.linkToProject("node-alice" as NodoId, "proj-2");

		const retrieved = kernel.getProfile("node-alice" as NodoId);
		expect(retrieved!.proyectos).toContain("proj-2");
	});

	it("should register, get, update, and search profiles using new ProfileManager methods", async () => {
		const newProfile = {
			id: "node-bob" as NodoId,
			alias: "Bob",
			identidad: new Uint8Array([4, 5, 6]),
			nodos: ["node-bob" as NodoId],
			proyectos: [],
			karma: 50,
			metadatos: {},
		};

		// 1. register
		await kernel.profiles.register(newProfile);

		// 2. get
		const fetched = await kernel.profiles.get("node-bob");
		expect(fetched).toBeDefined();
		expect(fetched!.alias).toBe("Bob");
		expect((fetched as any).karma).toBe(50);

		// 3. update
		await kernel.profiles.update("node-bob", { alias: "Bob Builder", karma: 60 });
		const updated = await kernel.profiles.get("node-bob");
		expect(updated!.alias).toBe("Bob Builder");
		expect((updated as any).karma).toBe(60);

		// 4. search
		const searchResults = await kernel.profiles.search("Build");
		expect(searchResults).toHaveLength(1);
		expect(searchResults[0].id).toBe("node-bob");
	});
});
