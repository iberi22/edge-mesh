import Peer from "peerjs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PeerJSTransport } from "../../src/transport/peerjs.js";
import type { NodoId } from "../../src/types/index.js";

// Store peer instances to access them in tests
let peerInstances: any[] = [];

// Mock PeerJS
vi.mock("peerjs", () => {
	class MockPeer {
		on = vi.fn((event, cb) => {
			this.listeners[event] = cb;
			return this;
		});
		connect = vi.fn((peerId, options) => {
			const conn = {
				peer: peerId,
				open: false,
				on: vi.fn((ev, cb) => {
					this.connListeners[ev] = cb;
					return this;
				}),
				once: vi.fn((ev, cb) => {
					this.connListeners[ev] = cb;
					return this;
				}),
				send: vi.fn(),
				close: vi.fn(),
			};
			this.connectionsCreated.push(conn);
			return conn;
		});
		destroy = vi.fn();
		reconnect = vi.fn();

		listeners: Record<string, Function> = {};
		connListeners: Record<string, Function> = {};
		connectionsCreated: any[] = [];
		destroyed = false;
		disconnected = false;

		constructor(public id: string, public options: any) {
			peerInstances.push(this);
		}
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
		peerInstances = [];
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should initialize with correct parameters", () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		expect(transport.nodoId).toBe(mockNodoId);
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
			open: true,
			on: vi.fn(),
			once: vi.fn(),
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

	it("should attempt to reconnect using backoff when disconnected", async () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		expect(peerInstances).toHaveLength(1);
		const peer = peerInstances[0];

		// Trigger 'open' to connect
		peer.listeners["open"]("peer-1");
		expect(transport.estaConectado()).toBe(true);

		// Trigger 'disconnected'
		peer.disconnected = true;
		peer.listeners["disconnected"]();
		expect(transport.estaConectado()).toBe(false);

		// Should schedule reconnect. Let's advance timers.
		// Since we used initialDelayMs = 100 for backoff inside the transport:
		await vi.advanceTimersByTimeAsync(150);

		// Reconnect should have been called on peer
		expect(peer.reconnect).toHaveBeenCalled();
	});

	it("should re-initialize with the same ID on unavailable-id error", async () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		expect(peerInstances).toHaveLength(1);
		const peer = peerInstances[0];

		// Trigger 'unavailable-id' error
		const err = new Error("unavailable-id");
		(err as any).type = "unavailable-id";
		peer.listeners["error"](err);

		// Peer should be marked offline
		expect(transport.estaConectado()).toBe(false);

		// Wait for the re-init delay
		await vi.advanceTimersByTimeAsync(150);

		// A new peer instance should be created
		expect(peerInstances).toHaveLength(2);
		expect(peerInstances[1].id).toBe(mockOptions.peerId);
	});

	it("should queue pending connection requests when offline and flush them on open", async () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		const peer = peerInstances[0];

		// We are offline initially (before open)
		expect(transport.estaConectado()).toBe(false);

		// Try connecting to peer-2
		await transport.conectarRemoto("peer-2");

		// Should not call connect yet because we are offline
		expect(peer.connect).not.toHaveBeenCalled();

		// Now trigger open
		peer.listeners["open"]("peer-1");
		expect(transport.estaConectado()).toBe(true);

		// The queued connection should have been initiated
		expect(peer.connect).toHaveBeenCalledWith("peer-2", expect.any(Object));
	});

	it("should broadcast PEER_LIST_UPDATE when a new connection opens and when closed", async () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		const peer = peerInstances[0];

		// Open transport
		peer.listeners["open"]("peer-1");

		// Mock a remote connection being received
		const mockConn = {
			peer: "peer-2",
			open: false,
			on: vi.fn(),
			once: vi.fn(),
			send: vi.fn(),
			close: vi.fn(),
		};

		peer.listeners["connection"](mockConn);

		// Get the open callback registered on mockConn
		expect(mockConn.once).toHaveBeenCalledWith("open", expect.any(Function));
		const openCallback = mockConn.once.mock.calls.find((call: any) => call[0] === "open")[1];

		// Now invoke the open callback
		mockConn.open = true;
		openCallback();

		// Expect that we broadcast our peer list (which includes peer-1 and peer-2)
		expect(mockConn.send).toHaveBeenCalledWith(
			expect.objectContaining({
				tipo: "peer_list_update",
				payload: { peers: ["peer-1", "peer-2"] },
			}),
		);
	});

	it("should automatically connect to discovered peers from PEER_LIST_UPDATE", async () => {
		const transport = new PeerJSTransport(mockNodoId, mockOptions);
		const peer = peerInstances[0];

		peer.listeners["open"]("peer-1");

		// Mock connection to peer-2
		const mockConn = {
			peer: "peer-2",
			open: true,
			on: vi.fn(),
			once: vi.fn(),
			send: vi.fn(),
			close: vi.fn(),
		};
		peer.listeners["connection"](mockConn);

		// Get the data callback registered on mockConn
		const dataCallback = mockConn.on.mock.calls.find((call: any) => call[0] === "data")[1];

		// Send a PEER_LIST_UPDATE envelope containing a new peer 'peer-3'
		const envelope = {
			id: "msg-1",
			tipo: "peer_list_update",
			origen: "peer-2",
			destino: "*",
			timestamp: Date.now(),
			payload: { peers: ["peer-2", "peer-3"] },
			version: 1,
			nonce: "nonce-1",
		};

		dataCallback(envelope);

		// Since we didn't know peer-3, we should automatically connect to it!
		expect(peer.connect).toHaveBeenCalledWith("peer-3", expect.any(Object));
	});
});
