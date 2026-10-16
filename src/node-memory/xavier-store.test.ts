import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { XavierStore } from "./xavier-store.js";
import type { MemoryRecord } from "./types.js";

describe("XavierStore", () => {
	const appId = "test-app";
	const instanceId = "test-instance";
	let fetchMock: any;
	let consoleWarnSpy: any;

	beforeEach(() => {
		fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => [],
		});
		vi.stubGlobal("fetch", fetchMock);
		consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	const mockRecord: MemoryRecord = {
		id: "hash123",
		appId,
		instanceId,
		kind: "semantic",
		content: "test",
		contentHash: "hash123",
		timestamp: 12345,
		synced: true,
	};

	describe("postRecord", () => {
		// This path is the client's contract, not a route in Xavier origin/main. See the PR body.
		it("sends POST, exact URL app/<appId>/instance/<instanceId>, Content-Type, and body", async () => {
			const store = new XavierStore({ appId, instanceId });
			await store.postRecord(mockRecord);

			expect(fetchMock).toHaveBeenCalledTimes(1);
			const url = fetchMock.mock.calls[0][0];
			const opts = fetchMock.mock.calls[0][1];

			expect(url).toBe("http://127.0.0.1:8006/app/test-app/instance/test-instance");
			expect(opts.method).toBe("POST");
			expect(opts.headers["Content-Type"]).toBe("application/json");
			expect(opts.body).toBe(JSON.stringify(mockRecord));
		});

		it("sends X-Xavier-Token only when xavierToken is set", async () => {
			const storeWithToken = new XavierStore({ appId, instanceId, xavierToken: "token-123" });
			await storeWithToken.postRecord(mockRecord);

			expect(fetchMock.mock.calls[0][1].headers["X-Xavier-Token"]).toBe("token-123");

			fetchMock.mockClear();

			const storeWithoutToken = new XavierStore({ appId, instanceId });
			await storeWithoutToken.postRecord(mockRecord);

			expect(fetchMock.mock.calls[0][1].headers["X-Xavier-Token"]).toBeUndefined();
		});

		it("produces the same URL with and without a trailing slash on xavierUrl", async () => {
			const storeWithoutSlash = new XavierStore({ appId, instanceId, xavierUrl: "http://example.com" });
			await storeWithoutSlash.postRecord(mockRecord);
			const url1 = fetchMock.mock.calls[0][0];

			fetchMock.mockClear();

			const storeWithSlash = new XavierStore({ appId, instanceId, xavierUrl: "http://example.com/" });
			await storeWithSlash.postRecord(mockRecord);
			const url2 = fetchMock.mock.calls[0][0];

			expect(url1).toBe("http://example.com/app/test-app/instance/test-instance");
			expect(url1).toBe(url2);
		});

		it("returns false on non-OK status", async () => {
			fetchMock.mockResolvedValueOnce({ ok: false });
			const store = new XavierStore({ appId, instanceId });
			const result = await store.postRecord(mockRecord);

			expect(result).toBe(false);
		});

		it("returns false and warns when fetch throws", async () => {
			fetchMock.mockRejectedValueOnce(new Error("Network fail"));
			const store = new XavierStore({ appId, instanceId });
			const result = await store.postRecord(mockRecord);

			expect(result).toBe(false);
			expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
		});
	});

	describe("loadRecords", () => {
		it("sends GET with query and limit search params", async () => {
			const store = new XavierStore({ appId, instanceId });
			await store.loadRecords("test-path", "search query", 10);

			expect(fetchMock).toHaveBeenCalledTimes(1);
			const url = fetchMock.mock.calls[0][0];
			const opts = fetchMock.mock.calls[0][1];

			const urlObj = new URL(url);
			expect(urlObj.searchParams.get("query")).toBe("search query");
			expect(urlObj.searchParams.get("limit")).toBe("10");
			expect(opts.method).toBe("GET");
		});

		it("omits limit when it is undefined", async () => {
			const store = new XavierStore({ appId, instanceId });
			await store.loadRecords("test-path", "search query");

			const url = fetchMock.mock.calls[0][0];
			const urlObj = new URL(url);

			expect(urlObj.searchParams.get("query")).toBe("search query");
			expect(urlObj.searchParams.has("limit")).toBe(false);
		});

		it("returns [] on a non-OK status", async () => {
			fetchMock.mockResolvedValueOnce({ ok: false });
			const store = new XavierStore({ appId, instanceId });
			const result = await store.loadRecords("test-path", "search query");

			expect(result).toEqual([]);
		});

		it("returns [] on a non-array body", async () => {
			fetchMock.mockResolvedValueOnce({ ok: true, json: async () => ({ not: "array" }) });
			const store = new XavierStore({ appId, instanceId });
			const result = await store.loadRecords("test-path", "search query");

			expect(result).toEqual([]);
		});

		it("returns [] and warns on a thrown error", async () => {
			fetchMock.mockRejectedValueOnce(new Error("Network error"));
			const store = new XavierStore({ appId, instanceId });
			const result = await store.loadRecords("test-path", "search query");

			expect(result).toEqual([]);
			expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
		});

		it("uses absolute http:// or https:// path as the full URL", async () => {
			const store = new XavierStore({ appId, instanceId });

			await store.loadRecords("https://other.domain.com/path", "search");
			let url = fetchMock.mock.calls[0][0];
			expect(url).toContain("https://other.domain.com/path");

			fetchMock.mockClear();

			await store.loadRecords("http://other.domain.com/path", "search");
			url = fetchMock.mock.calls[0][0];
			expect(url).toContain("http://other.domain.com/path");
		});
	});
});
