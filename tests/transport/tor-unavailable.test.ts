import { EventEmitter } from "node:events";
import net from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TorTransportAdapter } from "../../src/transport/TorTransportAdapter.js";
import { TorUnavailableError } from "../../src/transport/tor-errors.js";

vi.mock("node:net");

describe("TorTransportAdapter - SOCKS verification", () => {
	afterEach(() => {
		vi.clearAllMocks();
	});

	it("should throw TorUnavailableError if proxy is unreachable when verifySocks is true", async () => {
		const mockSocket = new EventEmitter() as any;
		mockSocket.setTimeout = vi.fn();
		mockSocket.destroy = vi.fn();

		(net.createConnection as any).mockImplementation((options: any, cb: any) => {
			// Simulate error after connection attempt
			setTimeout(() => mockSocket.emit("error", new Error("ECONNREFUSED")), 10);
			return mockSocket;
		});

		const adapter = new TorTransportAdapter("node-1", {
			verifySocks: true,
			socksHost: "127.0.0.1",
			socksPort: 9050,
			socksConnectTimeoutMs: 100,
		});

		await expect(adapter.conectar()).rejects.toThrowError(TorUnavailableError);
		expect(adapter.estaConectado()).toBe(false);
	});

	it("should connect successfully if proxy is reachable when verifySocks is true", async () => {
		const mockSocket = new EventEmitter() as any;
		mockSocket.setTimeout = vi.fn();
		mockSocket.destroy = vi.fn();

		(net.createConnection as any).mockImplementation((options: any, cb: any) => {
			// Simulate successful connection
			setTimeout(() => cb(), 10);
			return mockSocket;
		});

		const adapter = new TorTransportAdapter("node-1", {
			verifySocks: true,
			socksHost: "127.0.0.1",
			socksPort: 9050,
			socksConnectTimeoutMs: 100,
		});

		await expect(adapter.conectar()).resolves.toBeUndefined();
		expect(adapter.estaConectado()).toBe(true);
		expect(mockSocket.destroy).toHaveBeenCalled();
	});

	it("should throw TorUnavailableError on enviar() before connect if verifySocks is true", async () => {
		const adapter = new TorTransportAdapter("node-1", {
			verifySocks: true,
			socksHost: "127.0.0.1",
			socksPort: 9050,
		});

		await expect(adapter.enviar("node-2", "data")).rejects.toThrowError(TorUnavailableError);
	});

	it("should connect successfully without socket check if verifySocks is false (default)", async () => {
		const adapter = new TorTransportAdapter("node-1");

		await expect(adapter.conectar()).resolves.toBeUndefined();
		expect(adapter.estaConectado()).toBe(true);
		expect(net.createConnection).not.toHaveBeenCalled();
	});
});
