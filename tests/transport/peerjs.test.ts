import Peer from "peerjs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { PeerJSTransport } from "../../src/transport/peerjs.js";
import type { NodoId } from "../../src/types/index.js";

// Mock PeerJS
vi.mock("peerjs", () => {
	class MockPeer {
		on = vi.fn();
		connect = vi.fn();
		destroy = vi.fn();
		disconnect = vi.fn();
		constructor(id: string, options: any) {}
	}
	return {
		default: MockPeer,
	};
});

// Mock idb
vi.mock("idb", () => ({
	openDB: vi.fn(),
}));

describe("PeerJSTransport", () => {
	const mockNodoId = "nodo-1" as NodoId;
	const mockOptions = {
		peerId: "peer-1",
		host: "localhost",
		port: 9000,
	};

	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("should initialize with correct parameters", () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		expect(transport.nodoId).toBe(mockNodoId);
		// Since we can't easily check constructor calls on the class mock without vi.fn wrapper
		// but the constructor itself is called.
	});

	it("should forward PeerJS events", () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		// @ts-expect-error
		const peerInstance = transport.peer;

		const conectadoSpy = vi.fn();
		const errorSpy = vi.fn();

		transport.on("conectado", conectadoSpy);
		transport.on("error", errorSpy);

		// Find the 'open' handler and call it
		const openHandler = peerInstance.on.mock.calls.find(
			(call: any) => call[0] === "open",
		)[1];
		openHandler("peer-1");

		expect(conectadoSpy).toHaveBeenCalled();
		expect(transport.estaConectado()).toBe(true);

		// Find the 'error' handler and call it
		const errorHandler = peerInstance.on.mock.calls.find(
			(call: any) => call[0] === "error",
		)[1];
		const mockError = new Error("peer error");
		errorHandler(mockError);

		expect(errorSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { mensaje: "peer error", error: mockError },
			}),
		);
	});

	it("should handle incoming connections", () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		// @ts-expect-error
		const peerInstance = transport.peer;

		const conectadoSpy = vi.fn();
		transport.on("conectado", conectadoSpy);

		const mockConn = {
			peer: "remote-peer",
			on: vi.fn(),
			send: vi.fn(),
			close: vi.fn(),
		};

		const connectionHandler = peerInstance.on.mock.calls.find(
			(call: any) => call[0] === "connection",
		)[1];
		connectionHandler(mockConn);

		expect(conectadoSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: "remote-peer" },
			}),
		);
		expect(transport.obtenerConexiones()).toContain("remote-peer");
	});
});
