import { beforeEach, describe, expect, it, vi } from "vitest";
import { AgentProfileAdapter } from "../../../src/adapters/maloca-xavier/agent-profile.js";
import { LLMRouterAdapter } from "../../../src/adapters/maloca-xavier/llm-router.js";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import type { NodoId } from "../../../src/types/index.js";

vi.mock("../../../src/transport/peerjs.js");
vi.mock("idb", () => ({
	openDB: vi.fn().mockResolvedValue({
		get: vi.fn(),
		put: vi.fn(),
		delete: vi.fn(),
		getAll: vi.fn().mockResolvedValue([]),
		clear: vi.fn(),
		close: vi.fn(),
		objectStoreNames: {
			contains: vi.fn().mockReturnValue(true),
		},
	}),
}));

describe("LLMRouterAdapter", () => {
	let edgeMesh: EdgeMesh;
	let profileAdapter: AgentProfileAdapter;
	let routerAdapter: LLMRouterAdapter;
	const nodoId = "router-node" as NodoId;

	beforeEach(() => {
		edgeMesh = new EdgeMesh({
			nodoId,
			storageBackend: "mem",
		});
		profileAdapter = new AgentProfileAdapter(edgeMesh);
		routerAdapter = new LLMRouterAdapter(edgeMesh);
	});

	it("should route prompt to the best available provider", async () => {
		const provider1 = "provider-1" as NodoId;
		const provider2 = "provider-2" as NodoId;

		await profileAdapter.registerAgent({
			id: provider1,
			nombre: "GPT-4 Provider Fast",
			capacidades: ["gpt-4"],
			metadatos: {},
		});

		await profileAdapter.registerAgent({
			id: provider2,
			nombre: "GPT-4 Provider Slow",
			capacidades: ["gpt-4"],
			metadatos: {},
		});

		// Mock presence health
		vi.spyOn(edgeMesh.presence, "obtenerSalud").mockImplementation((id) => {
			if (id === provider1) {
				return {
					nodoId: provider1,
					estado: "saludable",
					ultimoHeartbeat: Date.now(),
					latenciaMs: 50,
					fallosConsecutivos: 0,
				};
			}
			if (id === provider2) {
				return {
					nodoId: provider2,
					estado: "saludable",
					ultimoHeartbeat: Date.now(),
					latenciaMs: 200,
					fallosConsecutivos: 0,
				};
			}
			return null;
		});

		const enviarSpy = vi.spyOn(edgeMesh, "enviar").mockResolvedValue(undefined);

		const result = await routerAdapter.routePrompt("Hola Xavier", "gpt-4");

		expect(result).toBeDefined();
		expect(result?.providerId).toBe(provider1);
		expect(result?.latencyMs).toBe(50);
		expect(enviarSpy).toHaveBeenCalledWith(
			provider1,
			expect.objectContaining({
				tipo: "xavier:prompt",
				prompt: "Hola Xavier",
				model: "gpt-4",
			}),
		);
	});

	it("should return null if no provider supports the model", async () => {
		const result = await routerAdapter.routePrompt(
			"Hola",
			"non-existent-model",
		);
		expect(result).toBeNull();
	});

	it("should share context with multiple agents", async () => {
		const agentIds = ["agent-1" as NodoId, "agent-2" as NodoId];
		const enviarSpy = vi.spyOn(edgeMesh, "enviar").mockResolvedValue(undefined);

		await routerAdapter.shareContext({ memory: "shared data" }, agentIds);

		expect(enviarSpy).toHaveBeenCalledTimes(2);
		expect(enviarSpy).toHaveBeenCalledWith(
			"agent-1",
			expect.objectContaining({
				tipo: "xavier:context",
				contexto: { memory: "shared data" },
			}),
		);
	});
});
