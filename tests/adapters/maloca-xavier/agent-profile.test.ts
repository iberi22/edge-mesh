import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	type AgentProfile,
	AgentProfileAdapter,
} from "../../../src/adapters/maloca-xavier/agent-profile.js";
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

describe("AgentProfileAdapter", () => {
	let edgeMesh: EdgeMesh;
	let adapter: AgentProfileAdapter;
	const nodoId = "test-agent" as NodoId;

	beforeEach(() => {
		edgeMesh = new EdgeMesh({
			nodoId,
			storageBackend: "mem",
		});
		adapter = new AgentProfileAdapter(edgeMesh);
	});

	it("should register an agent profile", async () => {
		const profile: AgentProfile = {
			id: nodoId,
			nombre: "Xavier Agent 1",
			capacidades: ["gpt-4", "code-generation"],
			metadatos: { version: "1.0.0" },
		};

		await adapter.registerAgent(profile);

		const profiles = adapter.getAllProfiles();
		expect(profiles).toHaveLength(1);
		expect(profiles[0].id).toBe(nodoId);
		expect(profiles[0].nombre).toBe("Xavier Agent 1");

		const ns = edgeMesh.namespaces.obtenerEspacioPorNombre("xavier:agents");
		expect(ns).toBeDefined();
		expect(ns?.nodos).toContain(nodoId);
	});

	it("should discover agents by capacity", async () => {
		const profile1: AgentProfile = {
			id: "agent-1" as NodoId,
			nombre: "Agent 1",
			capacidades: ["llm", "vision"],
			metadatos: {},
		};
		const profile2: AgentProfile = {
			id: "agent-2" as NodoId,
			nombre: "Agent 2",
			capacidades: ["llm", "speech"],
			metadatos: {},
		};

		await adapter.registerAgent(profile1);
		await adapter.registerAgent(profile2);

		const llmAgents = adapter.discoverAgents("llm");
		expect(llmAgents).toHaveLength(2);

		const visionAgents = adapter.discoverAgents("vision");
		expect(visionAgents).toHaveLength(1);
		expect(visionAgents[0].id).toBe("agent-1");
	});

	it("should get agent status from presence manager", () => {
		const agentId = "other-agent" as NodoId;
		// Simular que el presence manager tiene info del nodo
		vi.spyOn(edgeMesh.presence, "obtenerSalud").mockReturnValue({
			nodoId: agentId,
			estado: "saludable",
			ultimoHeartbeat: Date.now(),
			latenciaMs: 10,
			fallosConsecutivos: 0,
		});

		const status = adapter.getAgentStatus(agentId);
		expect(status).toBeDefined();
		expect(status?.estado).toBe("saludable");
	});
});
