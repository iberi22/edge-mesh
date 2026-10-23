import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import * as net from "node:net";
import { TorTransportAdapter } from "../../src/transport/TorTransportAdapter.js";
import { TorUnavailableError } from "../../src/transport/tor-errors.js";
import type { NodoId } from "../../src/types/index.js";

vi.mock("node:net", () => {
	return {
		createConnection: vi.fn(),
	};
});

describe("TorTransportAdapter - SOCKS Verify", () => {
	const node1Id = "node-1" as NodoId;
	const node2Id = "node-2" as NodoId;

	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("should not connect socket when verifySocks is false (default behavior)", async () => {
		const adapter = new TorTransportAdapter(node1Id, { verifySocks: false });
		await adapter.conectar();
		expect(adapter.estaConectado()).toBe(true);
		expect(net.createConnection).not.toHaveBeenCalled();
	});

	it("should connect socket and resolve when proxy is reachable and verifySocks is true", async () => {
		const mockSocket = {
			setTimeout: vi.fn(),
			on: vi.fn(),
			destroy: vi.fn(),
		};
		vi.mocked(net.createConnection).mockReturnValue(mockSocket as any);

		const adapter = new TorTransportAdapter(node1Id, { verifySocks: true });

		const conectarPromise = adapter.conectar();

		// Find the connect handler and trigger it
		const connectHandler = mockSocket.on.mock.calls.find(c => c[0] === "connect")?.[1];
		expect(connectHandler).toBeDefined();
		connectHandler();

		await conectarPromise;

		expect(net.createConnection).toHaveBeenCalledWith({ host: "127.0.0.1", port: 9050 });
		expect(mockSocket.destroy).toHaveBeenCalled();
		expect(adapter.estaConectado()).toBe(true);
	});

	it("should throw TorUnavailableError when proxy is unreachable and verifySocks is true", async () => {
		const mockSocket = {
			setTimeout: vi.fn(),
			on: vi.fn(),
			destroy: vi.fn(),
		};
		vi.mocked(net.createConnection).mockReturnValue(mockSocket as any);

		const adapter = new TorTransportAdapter(node1Id, { verifySocks: true });

		const conectarPromise = adapter.conectar();

		// Find the error handler and trigger it
		const errorHandler = mockSocket.on.mock.calls.find(c => c[0] === "error")?.[1];
		expect(errorHandler).toBeDefined();
		errorHandler(new Error("ECONNREFUSED"));

		await expect(conectarPromise).rejects.toThrow(TorUnavailableError);

		expect(net.createConnection).toHaveBeenCalledWith({ host: "127.0.0.1", port: 9050 });
		expect(mockSocket.destroy).toHaveBeenCalled();
		expect(adapter.estaConectado()).toBe(false);
	});

	it("should throw TorUnavailableError on timeout when verifySocks is true", async () => {
		const mockSocket = {
			setTimeout: vi.fn(),
			on: vi.fn(),
			destroy: vi.fn(),
		};
		vi.mocked(net.createConnection).mockReturnValue(mockSocket as any);

		const adapter = new TorTransportAdapter(node1Id, { verifySocks: true });

		const conectarPromise = adapter.conectar();

		// Find the timeout handler and trigger it
		const timeoutHandler = mockSocket.on.mock.calls.find(c => c[0] === "timeout")?.[1];
		expect(timeoutHandler).toBeDefined();
		timeoutHandler();

		await expect(conectarPromise).rejects.toThrow(TorUnavailableError);

		expect(mockSocket.destroy).toHaveBeenCalled();
		expect(adapter.estaConectado()).toBe(false);
	});

	it("should throw TorUnavailableError when sending before connect and verifySocks is true", async () => {
		const adapter = new TorTransportAdapter(node1Id, { verifySocks: true });
		await expect(adapter.enviar(node2Id, new Uint8Array())).rejects.toThrow(TorUnavailableError);
	});

	it("should emit error when autoConnect fails", async () => {
		const mockSocket = {
			setTimeout: vi.fn(),
			on: vi.fn(),
			destroy: vi.fn(),
		};
		vi.mocked(net.createConnection).mockReturnValue(mockSocket as any);

		// Need a new adapter, and we wait for the error event
		const errorSpy = vi.fn();
		const adapter = new TorTransportAdapter(node1Id, { verifySocks: true, autoConnect: true });
		adapter.on("error", errorSpy);

		const errorHandler = mockSocket.on.mock.calls.find(c => c[0] === "error")?.[1];
		expect(errorHandler).toBeDefined();
		errorHandler(new Error("ECONNREFUSED"));

		// Allow event loop to process promise rejection
		await new Promise(resolve => setTimeout(resolve, 10));

		expect(errorSpy).toHaveBeenCalledTimes(1);
		const emittedError = errorSpy.mock.calls[0][0].detail.error;
		expect(emittedError).toBeInstanceOf(TorUnavailableError);
	});
});
