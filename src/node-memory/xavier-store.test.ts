import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryRecord } from "./types.js";
import { XavierStore } from "./xavier-store.js";

describe("XavierStore", () => {
	const appId = "test-app";
	const instanceId = "test-instance";
	// biome-ignore lint/suspicious/noExplicitAny: Required for mocking global fetch
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

	describe("postRecord", () => {
		const mockRecord: MemoryRecord = {
			id: "hash123",
			appId,
			instanceId,
			kind: "semantic",
			content: "test content",
			contentHash: "hash123",
			timestamp: Date.now(),
			synced: false,
		};

		// This path is the client's contract, not a route in Xavier origin/main. See the PR body.
		it("should send POST, exact URL, Content-Type and JSON body", async () => {
			const store = new XavierStore({ appId, instanceId });
			await store.postRecord(mockRecord);

			expect(fetchMock).toHaveBeenCalledTimes(1);
			const callArgs = fetchMock.mock.calls[0];
			expect(callArgs[0]).toBe(
				"http://127.0.0.1:8006/app/test-app/instance/test-instance",
			);
			expect(callArgs[1].method).toBe("POST");
			expect(callArgs[1].headers["Content-Type"]).toBe("application/json");
			expect(callArgs[1].body).toBe(JSON.stringify(mockRecord));
		});

		it("should send X-Xavier-Token when set", async () => {
			const store = new XavierStore({
				appId,
				instanceId,
				xavierToken: "my-token",
			});
			await store.postRecord(mockRecord);

			const callArgs = fetchMock.mock.calls[0];
			expect(callArgs[1].headers["X-Xavier-Token"]).toBe("my-token");
		});

		it("should not send X-Xavier-Token when absent", async () => {
			const store = new XavierStore({ appId, instanceId });
			await store.postRecord(mockRecord);

			const callArgs = fetchMock.mock.calls[0];
			expect(callArgs[1].headers["X-Xavier-Token"]).toBeUndefined();
		});

		it("should normalize xavierUrl with or without trailing slash", async () => {
			const store1 = new XavierStore({
				appId,
				instanceId,
				xavierUrl: "http://example.com",
			});
			await store1.postRecord(mockRecord);
			expect(fetchMock.mock.calls[0][0]).toBe(
				"http://example.com/app/test-app/instance/test-instance",
			);

			const store2 = new XavierStore({
				appId,
				instanceId,
				xavierUrl: "http://example.com/",
			});
			await store2.postRecord(mockRecord);
			expect(fetchMock.mock.calls[1][0]).toBe(
				"http://example.com/app/test-app/instance/test-instance",
			);
		});

		it("should return false on res.ok === false", async () => {
			fetchMock.mockResolvedValueOnce({ ok: false });
			const store = new XavierStore({ appId, instanceId });
			const result = await store.postRecord(mockRecord);

			expect(result).toBe(false);
		});

		it("should return false and warn when fetch throws", async () => {
			fetchMock.mockRejectedValueOnce(new Error("Network Error"));
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			const store = new XavierStore({ appId, instanceId });
			const result = await store.postRecord(mockRecord);

			expect(result).toBe(false);
			expect(warnSpy).toHaveBeenCalled();
		});
	});

	describe("loadRecords", () => {
		const mockRecord: MemoryRecord = {
			id: "hash123",
			appId,
			instanceId,
			kind: "semantic",
			content: "test content",
			contentHash: "hash123",
			timestamp: Date.now(),
			synced: true,
		};

		it("should send GET with query and limit search params", async () => {
			fetchMock.mockResolvedValueOnce({
				ok: true,
				json: async () => [mockRecord],
			});
			const store = new XavierStore({ appId, instanceId });
			await store.loadRecords("api/records", "test query", 10);

			expect(fetchMock).toHaveBeenCalledTimes(1);
			const callUrl = new URL(fetchMock.mock.calls[0][0]);
			expect(callUrl.searchParams.get("query")).toBe("test query");
			expect(callUrl.searchParams.get("limit")).toBe("10");
			expect(fetchMock.mock.calls[0][1].method).toBe("GET");
		});

		it("should omit limit when it is undefined", async () => {
			fetchMock.mockResolvedValueOnce({ ok: true, json: async () => [] });
			const store = new XavierStore({ appId, instanceId });
			await store.loadRecords("api/records", "test query");

			const callUrl = new URL(fetchMock.mock.calls[0][0]);
			expect(callUrl.searchParams.get("query")).toBe("test query");
			expect(callUrl.searchParams.has("limit")).toBe(false);
		});

		it("should return [] on a non-OK status", async () => {
			fetchMock.mockResolvedValueOnce({ ok: false });
			const store = new XavierStore({ appId, instanceId });
			const result = await store.loadRecords("api/records", "test query");

			expect(result).toEqual([]);
		});

		it("should return [] on a non-array body", async () => {
			fetchMock.mockResolvedValueOnce({
				ok: true,
				json: async () => ({ notAnArray: true }),
			});
			const store = new XavierStore({ appId, instanceId });
			const result = await store.loadRecords("api/records", "test query");

			expect(result).toEqual([]);
		});

		it("should return [] and warn when fetch throws", async () => {
			fetchMock.mockRejectedValueOnce(new Error("Network error"));
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			const store = new XavierStore({ appId, instanceId });
			const result = await store.loadRecords("api/records", "test query");

			expect(result).toEqual([]);
			expect(warnSpy).toHaveBeenCalled();
		});

		it("should use absolute http:// or https:// path as the full URL", async () => {
			const store = new XavierStore({ appId, instanceId });

			await store.loadRecords("http://external.com/path", "query");
			expect(
				fetchMock.mock.calls[0][0].startsWith("http://external.com/path"),
			).toBe(true);

			await store.loadRecords("https://secure.com/data", "query");
			expect(
				fetchMock.mock.calls[1][0].startsWith("https://secure.com/data"),
			).toBe(true);
		});
	});
});
