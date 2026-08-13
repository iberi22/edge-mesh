import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MalocaBackoffice } from "../../src/maloca/backoffice.js";
import type { MemoryRecord } from "../../src/node-memory/types.js";

describe("MalocaBackoffice", () => {
	const instanceId = "maloca-instance-123";
	let meshMock: any;
	let fetchMock: any;

	beforeEach(() => {
		// Mock minimal EdgeMesh methods and managers
		const mockNamespace = {
			id: "ns-123",
			nombre: `swal/maloca/${instanceId}`,
		};

		const mockNamespacesManager = {
			obtenerEspacioPorNombre: vi.fn().mockReturnValue(mockNamespace),
			crearEspacio: vi.fn().mockReturnValue(mockNamespace),
			unirNodo: vi.fn(),
		};

		const mockPresenceManager = {
			addOnlineListener: vi.fn(),
		};

		meshMock = {
			config: {
				nodoId: "node-1",
			},
			namespaces: mockNamespacesManager,
			presence: mockPresenceManager,
			on: vi.fn(),
			broadcastYjsUpdate: vi.fn().mockResolvedValue(undefined),
		};

		fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => [],
		});
		vi.stubGlobal("fetch", fetchMock);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("should initialize MalocaBackoffice and wire the P2P mesh namespace", () => {
		const backoffice = new MalocaBackoffice({
			mesh: meshMock,
			instanceId,
			xavierUrl: "http://127.0.0.1:8006",
			xavierToken: "xavier-key",
		});

		expect(backoffice.mesh).toBe(meshMock);
		expect(backoffice.instanceId).toBe(instanceId);
		expect(backoffice.nodeMemory).toBeDefined();

		// Check if it obtained/created and joined the correct namespace: swal/maloca/{instanceId}
		expect(meshMock.namespaces.obtenerEspacioPorNombre).toHaveBeenCalledWith(
			`swal/maloca/${instanceId}`,
		);
		expect(meshMock.namespaces.unirNodo).toHaveBeenCalledWith(
			"ns-123",
			"node-1",
		);
	});

	it("should register a session (persist Y.Doc) and broadcast updates over the mesh", async () => {
		const backoffice = new MalocaBackoffice({
			mesh: meshMock,
			instanceId,
			xavierUrl: "http://127.0.0.1:8006",
			xavierToken: "xavier-key",
		});

		const doc = new Y.Doc();
		const map = doc.getMap("session-data");
		map.set("user", "test-user");

		await backoffice.registrarSesion(doc, "user-session");

		// Should broadcast the YJS update
		expect(meshMock.broadcastYjsUpdate).toHaveBeenCalled();
		const callArgs = meshMock.broadcastYjsUpdate.mock.calls[0];
		expect(callArgs[1]).toBe(`swal/maloca/${instanceId}`);

		// Should also try to post to Xavier
		expect(fetchMock).toHaveBeenCalled();
		const fetchCall = fetchMock.mock.calls[0];
		expect(fetchCall[0]).toBe(
			`http://127.0.0.1:8006/app/maloca/instance/${instanceId}`,
		);
		expect(fetchCall[1].method).toBe("POST");
		expect(fetchCall[1].headers["X-Xavier-Token"]).toBe("xavier-key");
	});

	it("should save decision and post to Xavier semantic memory", async () => {
		const backoffice = new MalocaBackoffice({
			mesh: meshMock,
			instanceId,
			xavierUrl: "http://127.0.0.1:8006",
		});

		await backoffice.registrarDecision("Decision description", "Decision Title");

		// Should try to post to Xavier
		expect(fetchMock).toHaveBeenCalled();
		const fetchCall = fetchMock.mock.calls[0];
		expect(fetchCall[0]).toBe(
			`http://127.0.0.1:8006/app/maloca/instance/${instanceId}`,
		);
		const body = JSON.parse(fetchCall[1].body);
		expect(body.title).toBe("Decision Title");
		expect(body.content).toBe("Decision description");
		expect(body.kind).toBe("decisiones");
	});

	it("should retrieve decisions from Xavier", async () => {
		const backoffice = new MalocaBackoffice({
			mesh: meshMock,
			instanceId,
			xavierUrl: "http://127.0.0.1:8006",
		});

		const mockRecord: MemoryRecord = {
			id: "id-123",
			appId: "maloca",
			instanceId,
			kind: "decisiones",
			content: "Decision content",
			contentHash: "hash-123",
			timestamp: Date.now(),
			synced: true,
		};

		fetchMock.mockResolvedValue({
			ok: true,
			json: async () => [mockRecord],
		});

		const result = await backoffice.buscarDecisiones("test query", 5);

		expect(result).toHaveLength(1);
		expect(result[0].id).toBe("id-123");
		expect(result[0].content).toBe("Decision content");

		expect(fetchMock).toHaveBeenCalled();
		const fetchCall = fetchMock.mock.calls[0];
		expect(fetchCall[0]).toContain(
			`http://127.0.0.1:8006/app/maloca/instance/${instanceId}`,
		);
		const urlObj = new URL(fetchCall[0]);
		expect(urlObj.searchParams.get("query")).toBe("test query");
		expect(urlObj.searchParams.get("limit")).toBe("5");
	});
});
