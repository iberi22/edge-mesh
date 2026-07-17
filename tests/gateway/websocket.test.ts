import { beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MalocaWSGateway } from "../../src/maloca/gateway/websocket.js";
import type { NodoId } from "../../src/types/index.js";

describe("MalocaWSGateway", () => {
	let mesh: EdgeMesh;
	let wsGateway: MalocaWSGateway;

	beforeEach(() => {
		mesh = new EdgeMesh({
			nodoId: "test-node" as NodoId,
			storageBackend: "mem",
		});
		wsGateway = new MalocaWSGateway(mesh);
	});

	it("should connect a client", async () => {
		const result = await wsGateway.connectWS("profile-1");
		expect(result.profileId).toBe("profile-1");
		expect(result.connectionId).toBeDefined();
	});

	it("should allow subscriptions", () => {
		// Basic test to ensure it doesn't throw
		wsGateway.subscribeToEvents("profile-1", ["sync", "chat"]);
	});

	it("should emit messages to mesh", async () => {
		const transmitirSpy = vi
			.spyOn(mesh, "transmitir")
			.mockResolvedValue(undefined);

		await wsGateway.emitMessage({ type: "test", payload: { hello: "world" } });

		expect(transmitirSpy).toHaveBeenCalled();
	});
});
