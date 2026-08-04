import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import { createNodeMemory } from "./index.js";
import type { MemoryRecord } from "./types.js";

describe("NodeMemory", () => {
	const appId = "test-app";
	const instanceId = "test-instance";
	let fetchMock: any;

	beforeEach(() => {
		fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => [],
		});
		vi.stubGlobal("fetch", fetchMock);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("should persist Y.Doc offline-first and sync to Xavier when online", async () => {
		const memory = createNodeMemory({
			appId,
			instanceId,
			xavierUrl: "http://localhost:8006",
			xavierToken: "token-123",
		});

		const events: any[] = [];
		memory.subscribeChanges((ev) => {
			events.push(ev);
		});

		const doc = new Y.Doc();
		const text = doc.getText("test");
		text.insert(0, "Hello World");

		await memory.persistYDoc(doc, "ydoc");

		// Saved and synced events should be triggered
		expect(events).toHaveLength(2);
		expect(events[0].type).toBe("saved");
		expect(events[0].record.synced).toBe(false);
		expect(events[0].record.kind).toBe("ydoc");

		expect(events[1].type).toBe("synced");
		expect(events[1].record.synced).toBe(true);

		// Xavier fetch mock should have been called
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const callArgs = fetchMock.mock.calls[0];
		expect(callArgs[0]).toBe(
			"http://localhost:8006/app/test-app/instance/test-instance",
		);
		expect(callArgs[1].method).toBe("POST");
		expect(callArgs[1].headers["X-Xavier-Token"]).toBe("token-123");
	});

	it("should deduplicate by contentHash", async () => {
		const memory = createNodeMemory({
			appId,
			instanceId,
		});

		const events: any[] = [];
		memory.subscribeChanges((ev) => {
			events.push(ev);
		});

		// Save once
		await memory.saveMemory(
			"some semantic context",
			"context title",
			"semantic",
		);
		expect(events).toHaveLength(2); // saved & synced

		// Save again with same content
		await memory.saveMemory(
			"some semantic context",
			"context title",
			"semantic",
		);
		expect(events).toHaveLength(2); // no new events triggered, deduplicated!
	});

	it("should queue offline and flush when connection is restored", async () => {
		const memory = createNodeMemory({
			appId,
			instanceId,
		});

		// Simulate offline (fetch fails)
		fetchMock.mockRejectedValue(new Error("Network Error"));

		const events: any[] = [];
		memory.subscribeChanges((ev) => {
			events.push(ev);
		});

		await memory.saveMemory("offline message", "offline title", "agent");

		// Only saved event triggered, not synced
		expect(events).toHaveLength(1);
		expect(events[0].type).toBe("saved");
		expect(events[0].record.synced).toBe(false);

		// Switch back to online (fetch succeeds)
		fetchMock.mockResolvedValue({
			ok: true,
			json: async () => ({}),
		});

		const flushedCount = await memory.flushOffline();
		expect(flushedCount).toBe(1);

		expect(events).toHaveLength(2);
		expect(events[1].type).toBe("synced");
		expect(events[1].record.synced).toBe(true);
	});

	it("should load records from Xavier and trigger loaded events", async () => {
		const memory = createNodeMemory({
			appId,
			instanceId,
		});

		const mockRecord: MemoryRecord = {
			id: "hash123",
			appId,
			instanceId,
			kind: "semantic",
			content: "loaded content",
			contentHash: "hash123",
			timestamp: Date.now(),
			synced: true,
		};

		fetchMock.mockResolvedValue({
			ok: true,
			json: async () => [mockRecord],
		});

		const events: any[] = [];
		memory.subscribeChanges((ev) => {
			events.push(ev);
		});

		const result = await memory.loadFromXavier(
			"app/test-app/instance/test-instance",
			"some query",
			10,
		);
		expect(result).toHaveLength(1);
		expect(result[0].id).toBe("hash123");

		expect(events).toHaveLength(1);
		expect(events[0].type).toBe("loaded");
		expect(events[0].record.content).toBe("loaded content");
	});

	it("should clean expired records on save according to TTL", async () => {
		// Use a short/negative TTL to expire immediately on next save
		const memory = createNodeMemory({
			appId,
			instanceId,
			ttlMs: -1000, // expires in past
		});

		const events: any[] = [];
		memory.subscribeChanges((ev) => {
			events.push(ev);
		});

		await memory.saveMemory("old content", "old title", "semantic");
		expect(events).toHaveLength(2); // saved and synced

		// Save new content, which should trigger cleanup of the old one
		await memory.saveMemory("new content", "new title", "semantic");

		// The old record (which has hash of "old content") should be deleted, so we can save "old content" again!
		events.length = 0;
		await memory.saveMemory("old content", "old title", "semantic");
		// If it was deleted, it will trigger saved & synced again (otherwise deduplicated and 0 events)
		expect(events).toHaveLength(2);
	});
});
