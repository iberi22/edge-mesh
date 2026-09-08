import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	DEFAULT_DISCONNECT_THRESHOLD_MS,
	DEFAULT_HEARTBEAT_INTERVAL_MS,
	ReconnectManager,
} from "../src/transport/reconnect-manager.js";
import { WebRTCTransport } from "../src/transport/webrtc-transport.js";
import type { NodoId } from "../src/types/index.js";

function createMockDataChannel() {
	const listeners: Record<string, Function[]> = {};
	return {
		readyState: "open",
		send: vi.fn(),
		close: vi.fn(function (this: any) {
			this.readyState = "closed";
			if (listeners["close"]) {
				listeners["close"].forEach((fn) => fn());
			}
		}),
		addEventListener: vi.fn((event: string, fn: Function) => {
			if (!listeners[event]) listeners[event] = [];
			listeners[event].push(fn);
		}),
		removeEventListener: vi.fn((event: string, fn: Function) => {
			if (listeners[event]) {
				listeners[event] = listeners[event].filter((cb) => cb !== fn);
			}
		}),
		emit: (event: string, data?: any) => {
			if (listeners[event]) {
				listeners[event].forEach((fn) => fn(data));
			}
		},
		listeners,
	};
}

function createMockPeerConnection(initialState = "connected") {
	const listeners: Record<string, Function[]> = {};
	return {
		iceConnectionState: initialState,
		restartIce: vi.fn(),
		createOffer: vi.fn().mockResolvedValue({ sdp: "mock-offer-sdp", type: "offer" }),
		setLocalDescription: vi.fn().mockResolvedValue(undefined),
		close: vi.fn(function (this: any) {
			this.iceConnectionState = "closed";
		}),
		addEventListener: vi.fn((event: string, fn: Function) => {
			if (!listeners[event]) listeners[event] = [];
			listeners[event].push(fn);
		}),
		emitIceStateChange: function (this: any, newState: string) {
			this.iceConnectionState = newState;
			if (listeners["iceconnectionstatechange"]) {
				listeners["iceconnectionstatechange"].forEach((fn) => fn());
			}
			if (typeof this.oniceconnectionstatechange === "function") {
				this.oniceconnectionstatechange();
			}
		},
		oniceconnectionstatechange: null as Function | null,
		listeners,
	};
}

describe("ReconnectManager & WebRTC Transport Resilience (Issue 7)", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	describe("ReconnectManager Keep-Alive Heartbeats", () => {
		it("should execute ping/pong heartbeat timer at default 15s interval", async () => {
			const sendPing = vi.fn();
			const sendPong = vi.fn();
			const onDisconnect = vi.fn();

			const manager = new ReconnectManager({
				heartbeatIntervalMs: DEFAULT_HEARTBEAT_INTERVAL_MS, // 15000ms
				disconnectThresholdMs: DEFAULT_DISCONNECT_THRESHOLD_MS, // 30000ms
				sendPing,
				sendPong,
				onDisconnect,
			});

			const peerId = "peer-mobile-1";
			manager.trackPeer(peerId);

			// Initially no pings sent
			expect(sendPing).not.toHaveBeenCalled();

			// Advance by 15s (1 interval)
			await vi.advanceTimersByTimeAsync(15000);
			expect(sendPing).toHaveBeenCalledTimes(1);
			expect(sendPing).toHaveBeenLastCalledWith(peerId);

			// Advance another 15s
			await vi.advanceTimersByTimeAsync(15000);
			expect(sendPing).toHaveBeenCalledTimes(2);

			// Simulate receiving pong response
			manager.recordPong(peerId);
			expect(manager.isPeerAlive(peerId)).toBe(true);

			manager.destroy();
		});

		it("should handle ping message and send pong response", () => {
			const sendPong = vi.fn();
			const manager = new ReconnectManager({ sendPong });

			const peerId = "peer-mobile-2";
			manager.trackPeer(peerId);

			// Process incoming ping payload
			const handled = manager.processIncomingMessage(peerId, {
				type: "__ping__",
				timestamp: Date.now(),
			});

			expect(handled).toBe(true);
			expect(sendPong).toHaveBeenCalledWith(peerId);

			manager.destroy();
		});

		it("should trigger disconnect callback when disconnect threshold (30s) is exceeded without pongs", async () => {
			const sendPing = vi.fn();
			const onDisconnect = vi.fn();

			const manager = new ReconnectManager({
				heartbeatIntervalMs: 15000,
				disconnectThresholdMs: 30000,
				sendPing,
				onDisconnect,
			});

			const peerId = "peer-mobile-loss";
			manager.trackPeer(peerId);

			// Advance by 15s -> first ping sent
			await vi.advanceTimersByTimeAsync(15000);
			expect(sendPing).toHaveBeenCalledTimes(1);
			expect(onDisconnect).not.toHaveBeenCalled();

			// Advance past 30s threshold without receiving pong
			await vi.advanceTimersByTimeAsync(16000); // total 31s
			expect(onDisconnect).toHaveBeenCalledWith(peerId);

			expect(manager.isPeerAlive(peerId)).toBe(false);

			manager.destroy();
		});
	});

	describe("Auto ICE Candidate Renegotiation on Disconnected State", () => {
		it("should auto-renegotiate PeerConnection on iceConnectionState == 'disconnected' without tearing down channel session", async () => {
			const onRenegotiate = vi.fn().mockResolvedValue(undefined);
			const manager = new ReconnectManager({ onRenegotiate });

			const mockPc = createMockPeerConnection("connected");
			const peerId = "peer-renegotiate-1";

			manager.trackPeer(peerId, mockPc);

			// Simulate mobile network transition: Wi-Fi -> 4G/5G causing ICE state 'disconnected'
			mockPc.emitIceStateChange("disconnected");

			// Wait for async state handling
			await vi.waitFor(() => {
				expect(onRenegotiate).toHaveBeenCalledWith(peerId, mockPc);
			});

			// Peer state should indicate renegotiating/handled, without tearing down peer
			const state = manager.getPeerState(peerId);
			expect(state).toBeDefined();
			expect(state?.iceConnectionState).toBe("disconnected");

			// Simulate ICE reconnection recovery
			mockPc.emitIceStateChange("connected");
			expect(manager.getPeerState(peerId)?.iceConnectionState).toBe("connected");

			manager.destroy();
		});

		it("should invoke pc.restartIce or createOffer({ iceRestart: true }) if no onRenegotiate callback provided", async () => {
			const manager = new ReconnectManager();
			const mockPc = createMockPeerConnection("connected");
			const peerId = "peer-renegotiate-2";

			manager.trackPeer(peerId, mockPc);

			// Trigger 'disconnected'
			mockPc.emitIceStateChange("disconnected");

			await vi.waitFor(() => {
				expect(mockPc.restartIce).toHaveBeenCalled();
			});

			manager.destroy();
		});
	});

	describe("WebRTCTransport Connection Pooling & Network Resilience", () => {
		it("should integrate ReconnectManager and handle messages and keep-alives in WebRTCTransport", async () => {
			const nodoId = "nodo-local" as NodoId;
			const transport = new WebRTCTransport(nodoId, {
				heartbeatIntervalMs: 15000,
				disconnectThresholdMs: 30000,
			});

			const mockPc = createMockPeerConnection("connected");
			const mockChannel = createMockDataChannel();
			const remotePeerId = "nodo-remoto-1";

			const conectadoSpy = vi.fn();
			const mensajeSpy = vi.fn();
			const desconectadoSpy = vi.fn();

			transport.on("conectado", conectadoSpy);
			transport.on("mensaje", mensajeSpy);
			transport.on("desconectado", desconectadoSpy);

			transport.addPeerConnection(remotePeerId, mockPc, mockChannel);

			expect(transport.estaConectado()).toBe(true);
			expect(transport.obtenerConexiones()).toContain(remotePeerId);

			// Advance time by 15s to verify ping sent over channel
			await vi.advanceTimersByTimeAsync(15000);
			expect(mockChannel.send).toHaveBeenCalled();
			const lastCallArg = mockChannel.send.mock.calls[0][0];
			const parsedPing = JSON.parse(lastCallArg);
			expect(parsedPing.type).toBe("__ping__");

			// Receive ping from remote peer
			mockChannel.emit("message", {
				data: JSON.stringify({ type: "__ping__", timestamp: Date.now() }),
			});

			// Transport should respond with pong over channel without emitting business message
			expect(mensajeSpy).not.toHaveBeenCalled();

			// Receive valid business envelope
			const envelope = {
				id: "env-1",
				tipo: "sync",
				origen: remotePeerId,
				destino: nodoId,
				timestamp: Date.now(),
				payload: { hello: "world" },
				version: 1,
				nonce: "n-1",
			};

			mockChannel.emit("message", { data: JSON.stringify(envelope) });
			expect(mensajeSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: expect.objectContaining({
						envolvente: expect.objectContaining({ id: "env-1" }),
					}),
				}),
			);

			// Simulate ICE disconnect event (Wi-Fi to mobile transition)
			mockPc.emitIceStateChange("disconnected");

			// Verify channel was NOT torn down
			expect(mockChannel.readyState).toBe("open");
			expect(transport.obtenerConexiones()).toContain(remotePeerId);

			// Clean up
			await transport.cerrar();
			expect(transport.estaConectado()).toBe(false);
		});
	});
});
