import { describe, expect, it } from "vitest";
import {
	createPeerHealthMonitor,
	getReconnectDelay,
} from "../../src/presence/peer-health.js";

describe("createPeerHealthMonitor", () => {
	it("tracks healthy → stale → offline", () => {
		let now = 1_000;
		const health = createPeerHealthMonitor({
			now: () => now,
			staleAfterMs: 100,
			offlineAfterMs: 200,
		});

		health.markConnected("p1");
		expect(health.get("p1")?.status).toBe("healthy");

		now = 1_150;
		const stale = health.sweep();
		expect(stale[0]?.status).toBe("stale");
		expect(health.get("p1")?.status).toBe("stale");

		now = 1_300;
		const offline = health.sweep();
		expect(offline[0]?.status).toBe("offline");
	});

	it("emits peer:healthy on pong", () => {
		const health = createPeerHealthMonitor();
		const events: string[] = [];
		health.on("peer:healthy", () => events.push("healthy"));
		health.markPong("p1");
		expect(events).toContain("healthy");
	});
});

describe("getReconnectDelay", () => {
	it("exponential backoff capped at max", () => {
		expect(
			getReconnectDelay(0, { initialDelayMs: 1000, maxDelayMs: 8000 }),
		).toBe(1000);
		expect(
			getReconnectDelay(1, { initialDelayMs: 1000, maxDelayMs: 8000 }),
		).toBe(2000);
		expect(
			getReconnectDelay(10, { initialDelayMs: 1000, maxDelayMs: 8000 }),
		).toBe(8000);
	});
});
