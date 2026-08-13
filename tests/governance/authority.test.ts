import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createAuthorityManager,
	type AuthorityManager,
} from "../../src/governance/authority.js";
import { PresenceManager } from "../../src/presence/index.js";
import { type NodoId } from "../../src/types/index.js";

// Mock idb as required by the task setup
vi.mock("idb", () => ({
	openDB: vi.fn(),
}));

describe("AuthorityManager", () => {
	let localNodeId: NodoId;
	let presence: PresenceManager;
	let authority: AuthorityManager;

	beforeEach(() => {
		vi.useFakeTimers();
		localNodeId = "nodo-local" as NodoId;
		presence = new PresenceManager();
		authority = createAuthorityManager(localNodeId, presence);
	});

	afterEach(() => {
		authority.detener();
		presence.detener();
		vi.useRealTimers();
	});

	describe("Initialization and Basic Promotion", () => {
		it("should initialize with custom initial master", () => {
			const initialMaster = "nodo-master" as NodoId;
			const auth = createAuthorityManager(localNodeId, presence, {
				initialMaster,
			});
			expect(auth.obtenerMaster()).toBe(initialMaster);
		});

		it("should support promoteSuccessor and emit correct events", () => {
			const failoverSpy = vi.fn();
			const promocionadoSpy = vi.fn();
			const degradadoSpy = vi.fn();

			authority.on("failover", failoverSpy);
			authority.on("promocionado", promocionadoSpy);
			authority.on("degradado", degradadoSpy);

			// Promote a remote node to master
			const remoteMaster = "nodo-A" as NodoId;
			authority.promoteSuccessor(remoteMaster, "manual");

			expect(authority.obtenerMaster()).toBe(remoteMaster);
			expect(failoverSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: {
						antiguoMaster: null,
						nuevoMaster: remoteMaster,
						razon: "manual",
					},
				}),
			);
			expect(promocionadoSpy).not.toHaveBeenCalled();
			expect(degradadoSpy).not.toHaveBeenCalled();

			// Promote local node to master
			authority.promoteSuccessor(localNodeId, "manual");
			expect(authority.obtenerMaster()).toBe(localNodeId);
			expect(promocionadoSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: { nodoId: localNodeId },
				}),
			);

			// Demote local node by promoting a remote node
			authority.promoteSuccessor(remoteMaster, "manual");
			expect(authority.obtenerMaster()).toBe(remoteMaster);
			expect(degradadoSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: { nodoId: localNodeId },
				}),
			);
		});
	});

	describe("Deterministic Successor Election (Seniority)", () => {
		it("should select the successor with the lexicographically smallest NodeId", () => {
			// Candidates list containing our local node and some remote nodes
			const activeNodes = [
				"nodo-Z" as NodoId,
				"nodo-C" as NodoId,
				"nodo-A" as NodoId,
				"nodo-B" as NodoId,
			];

			// If current master is nodo-A, it should exclude nodo-A and select the remaining smallest (nodo-B)
			const successor = authority.selectSuccessor(activeNodes, "nodo-A" as NodoId);
			expect(successor).toBe("nodo-B");
		});

		it("should select first alphabetically if current master is not in list", () => {
			const activeNodes = [
				"nodo-C" as NodoId,
				"nodo-A" as NodoId,
				"nodo-B" as NodoId,
			];
			const successor = authority.selectSuccessor(activeNodes, "nodo-X" as NodoId);
			expect(successor).toBe("nodo-A");
		});

		it("should return null if no candidates are left", () => {
			const activeNodes = ["nodo-A" as NodoId];
			const successor = authority.selectSuccessor(activeNodes, "nodo-A" as NodoId);
			expect(successor).toBeNull();
		});
	});

	describe("checkHostHealth", () => {
		it("should return true for local node as host", () => {
			expect(authority.checkHostHealth(localNodeId)).toBe(true);
		});

		it("should return true if host is in active presence nodes, false otherwise", () => {
			const remoteNode = "nodo-remote" as NodoId;
			expect(authority.checkHostHealth(remoteNode)).toBe(false);

			// Simulate remote node being active in PresenceManager
			vi.spyOn(presence, "obtenerNodosActivos").mockReturnValue([remoteNode]);
			expect(authority.checkHostHealth(remoteNode)).toBe(true);
		});
	});

	describe("Network Partition and Failover Scenario", () => {
		it("should trigger failover automatically on master timeout / disappearing", async () => {
			const masterId = "nodo-master-A" as NodoId;
			const auth = createAuthorityManager(localNodeId, presence, {
				initialMaster: masterId,
			});

			const failoverSpy = vi.fn();
			auth.on("failover", failoverSpy);

			auth.iniciar();

			// Mock active nodes in PresenceManager (excluding failed master)
			// Suppose other active nodes in our partition are localNodeId and nodo-B
			vi.spyOn(presence, "obtenerNodosActivos").mockReturnValue(["nodo-B" as NodoId]);

			// Simulate presence emitting "nodoDesaparecio" for the current master
			presence.eventTarget.dispatchEvent(
				new CustomEvent("nodoDesaparecio", { detail: { nodoId: masterId } }),
			);

			// Since "nodo-B" is active, and "nodo-local" (us) is active,
			// active candidates = ["nodo-B", "nodo-local"].
			// Alphabetically, "nodo-B" < "nodo-local". So successor should be "nodo-B".
			expect(auth.obtenerMaster()).toBe("nodo-B");
			expect(failoverSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: {
						antiguoMaster: masterId,
						nuevoMaster: "nodo-B" as NodoId,
						razon: "timeout",
					},
				}),
			);
		});

		it("should trigger failover immediately via forceHostFailover", () => {
			const masterId = "nodo-master-A" as NodoId;
			const auth = createAuthorityManager(localNodeId, presence, {
				initialMaster: masterId,
			});

			const failoverSpy = vi.fn();
			auth.on("failover", failoverSpy);

			// Let's mock active nodes so that "nodo-local" is the only one left
			vi.spyOn(presence, "obtenerNodosActivos").mockReturnValue([]);

			auth.forceHostFailover();

			// Since we are the only active node left, we promote ourselves
			expect(auth.obtenerMaster()).toBe(localNodeId);
			expect(failoverSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: {
						antiguoMaster: masterId,
						nuevoMaster: localNodeId,
						razon: "forced",
					},
				}),
			);
		});

		it("should perform periodic check and trigger timeout failover", () => {
			const masterId = "nodo-master-A" as NodoId;
			const auth = createAuthorityManager(localNodeId, presence, {
				initialMaster: masterId,
			});

			const failoverSpy = vi.fn();
			auth.on("failover", failoverSpy);

			auth.iniciar();

			// Initially healthy
			vi.spyOn(presence, "obtenerNodosActivos").mockReturnValue([masterId]);

			// Advance time, health check should pass
			vi.advanceTimersByTime(1100);
			expect(auth.obtenerMaster()).toBe(masterId);

			// Now simulate masterId becomes unhealthy (not active anymore)
			vi.spyOn(presence, "obtenerNodosActivos").mockReturnValue(["nodo-B" as NodoId]);

			// Next periodic check (every 1000ms) will see it's unhealthy and failover
			vi.advanceTimersByTime(1100);

			// Successor from ["nodo-B", "nodo-local"] is "nodo-B"
			expect(auth.obtenerMaster()).toBe("nodo-B");
			expect(failoverSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: {
						antiguoMaster: masterId,
						nuevoMaster: "nodo-B" as NodoId,
						razon: "timeout",
					},
				}),
			);
		});
	});
});
