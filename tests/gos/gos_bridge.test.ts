import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { GosBridge } from "../../src/gos/GosBridge.js";
import { PresenceManager } from "../../src/presence/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("GosBridge", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should initialize telemetry with correct defaults for nodeId string", () => {
		const bridge = new GosBridge("node-1");
		const telemetry = bridge.getTelemetry();

		expect(telemetry.nodeId).toBe("node-1");
		expect(telemetry.status).toBe("online");
		expect(telemetry.activePeers).toBe(0);
		expect(telemetry.bandwidth.bytesSent).toBe(0);
		expect(telemetry.bandwidth.bytesReceived).toBe(0);
		expect(telemetry.bandwidth.txRateBytesPerSec).toBe(0);
		expect(telemetry.bandwidth.rxRateBytesPerSec).toBe(0);
	});

	it("should record bandwidth and calculate rates", () => {
		const bridge = new GosBridge("node-2");

		bridge.recordBytesSent(1000);
		bridge.recordBytesReceived(2000);

		vi.advanceTimersByTime(2000); // 2 seconds

		const telemetry = bridge.getTelemetry();

		expect(telemetry.bandwidth.bytesSent).toBe(1000);
		expect(telemetry.bandwidth.bytesReceived).toBe(2000);
		expect(telemetry.bandwidth.txRateBytesPerSec).toBe(500); // 1000 bytes / 2 sec
		expect(telemetry.bandwidth.rxRateBytesPerSec).toBe(1000); // 2000 bytes / 2 sec
	});

	it("should integrate with PresenceManager to report active peer count", () => {
		const presence = new PresenceManager();
		presence.healthChecker.recibirHeartbeat("peer-1" as NodoId, Date.now());
		presence.healthChecker.recibirHeartbeat("peer-2" as NodoId, Date.now());

		const bridge = new GosBridge("node-3", { presence });
		const telemetry = bridge.getTelemetry();

		expect(telemetry.activePeers).toBe(2);
	});

	it("should stream telemetry via callback and events when started", () => {
		const onTelemetry = vi.fn();
		const bridge = new GosBridge("node-4", {
			intervalMs: 1000,
			onTelemetry,
		});

		const eventCallback = vi.fn();
		bridge.onTelemetry(eventCallback);

		bridge.start();
		expect(bridge.isStreaming()).toBe(true);

		bridge.recordBytesSent(500);

		vi.advanceTimersByTime(1000);

		expect(onTelemetry).toHaveBeenCalledTimes(1);
		expect(eventCallback).toHaveBeenCalledTimes(1);

		const telemetry = onTelemetry.mock.calls[0][0];
		expect(telemetry.nodeId).toBe("node-4");
		expect(telemetry.bandwidth.bytesSent).toBe(500);

		bridge.stop();
		expect(bridge.isStreaming()).toBe(false);

		vi.advanceTimersByTime(1000);
		expect(onTelemetry).toHaveBeenCalledTimes(1);
	});

	it("should construct cleanly from EdgeMesh instance", () => {
		const mesh = new EdgeMesh({
			nodoId: "mesh-node-1" as NodoId,
			storageBackend: "mem",
		});

		const bridge = new GosBridge(mesh);
		expect(bridge.nodeId).toBe("mesh-node-1");

		const telemetry = bridge.getTelemetry();
		expect(telemetry.nodeId).toBe("mesh-node-1");
	});
});
