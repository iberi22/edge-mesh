import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryTransport } from "../../src/transport/memory.js";
import {
	TorTransportAdapter,
	type TorTransportAdapterOptions,
} from "../../src/transport/TorTransportAdapter.js";
import type { Envolvente, NodoId } from "../../src/types/index.js";
import { TIPO_MENSAJE, TIPO_TRANSPORTE } from "../../src/types/index.js";

describe("TorTransportAdapter", () => {
	const node1Id = "node-1" as NodoId;
	const node2Id = "node-2" as NodoId;

	beforeEach(() => {
		MemoryTransport.resetAll();
	});

	it("should initialize with default options and correct transport type", () => {
		const adapter = new TorTransportAdapter(node1Id);

		expect(adapter.tipo).toBe(TIPO_TRANSPORTE.TOR);
		expect(adapter.nodoId).toBe(node1Id);
		expect(adapter.estaConectado()).toBe(false);
		expect(adapter.isTunnelActive()).toBe(false);
		expect(adapter.getOnionAddress()).toContain(".onion");
	});

	it("should accept custom options and custom onion address", () => {
		const options: TorTransportAdapterOptions = {
			proxyUrl: "socks5://127.0.0.1:9050",
			onionAddress: "testservice12345.onion",
			socksPort: 9050,
			controlPort: 9051,
		};
		const adapter = new TorTransportAdapter(node1Id, options);

		expect(adapter.getOnionAddress()).toBe("testservice12345.onion");
	});

	it("should connect, emit 'conectado' event, and set tunnel status active", async () => {
		const adapter = new TorTransportAdapter(node1Id);
		const conectadoSpy = vi.fn();

		adapter.on("conectado", conectadoSpy);
		await adapter.conectar();

		expect(adapter.estaConectado()).toBe(true);
		expect(adapter.isTunnelActive()).toBe(true);
		expect(conectadoSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: node1Id },
			}),
		);
	});

	it("should register remote onion peers and track connections", () => {
		const adapter = new TorTransportAdapter(node1Id);
		adapter.registerOnionPeer("peer-2", "peer2service.onion");

		expect(adapter.obtenerConexiones()).toContain("peer-2");
	});

	it("should throw error when enviar is called while disconnected", async () => {
		const adapter = new TorTransportAdapter(node1Id);

		await expect(
			adapter.enviar(node2Id, { data: "hello" }),
		).rejects.toThrow("TorTransportAdapter no conectado");
	});

	it("should route envelope through custom tunnelHandler", async () => {
		const tunnelHandler = vi.fn().mockResolvedValue({ status: "ok" });
		const adapter = new TorTransportAdapter(node1Id, {
			tunnelHandler,
			onionAddress: "node1.onion",
		});
		adapter.registerOnionPeer("node-2", "node2.onion");

		await adapter.conectar();
		await adapter.enviar(node2Id, { ping: true }, TIPO_MENSAJE.HEARTBEAT);

		expect(tunnelHandler).toHaveBeenCalledTimes(1);
		const [sentEnv, targetOnion] = tunnelHandler.mock.calls[0];
		expect(sentEnv.origen).toBe(node1Id);
		expect(sentEnv.destino).toBe(node2Id);
		expect(sentEnv.tipo).toBe(TIPO_MENSAJE.HEARTBEAT);
		expect(targetOnion).toBe("node2.onion");
	});

	it("should route messages through fallbackTransport when configured", async () => {
		const memFallback = new MemoryTransport(node1Id, { roomId: "tor-test" });
		const adapter = new TorTransportAdapter(node1Id, {
			fallbackTransport: memFallback,
		});

		const memPeer = new MemoryTransport(node2Id, { roomId: "tor-test" });
		await memPeer.conectar();

		const messageSpy = vi.fn();
		memPeer.on("mensaje", messageSpy);

		await adapter.conectar();
		await adapter.enviar(node2Id, { payloadData: "tor-tunnel-fallback" });

		expect(messageSpy).toHaveBeenCalledTimes(1);
		expect(messageSpy.mock.calls[0][0].detail.envolvente.payload).toEqual({
			payloadData: "tor-tunnel-fallback",
		});
	});

	it("should process incoming payloads via receivePayload and deduplicate duplicate envelopes", () => {
		const adapter = new TorTransportAdapter(node1Id);
		const messageSpy = vi.fn();

		adapter.on("mensaje", messageSpy);

		const testEnvelope: Envolvente = {
			id: "env-100",
			tipo: TIPO_MENSAJE.SYNC,
			origen: node2Id,
			destino: node1Id,
			timestamp: Date.now(),
			firma: null,
			payload: { test: 123 },
			version: 1,
			nonce: "nonce-100",
		};

		adapter.receivePayload(testEnvelope, node2Id);
		expect(messageSpy).toHaveBeenCalledTimes(1);
		expect(adapter.obtenerConexiones()).toContain(node2Id);

		// Duplicate payload should be ignored by deduplicator
		adapter.receivePayload(testEnvelope, node2Id);
		expect(messageSpy).toHaveBeenCalledTimes(1);
	});

	it("should broadcast payload to registered connections using transmitir", async () => {
		const tunnelHandler = vi.fn().mockResolvedValue({});
		const adapter = new TorTransportAdapter(node1Id, { tunnelHandler });

		adapter.registerOnionPeer("peer-a", "peera.onion");
		adapter.registerOnionPeer("peer-b", "peerb.onion");

		await adapter.conectar();
		await adapter.transmitir({ broadcastMsg: "hello peers" });

		expect(tunnelHandler).toHaveBeenCalledTimes(2);
	});

	it("should handle tunnel handler errors and emit error events", async () => {
		const errorTunnel = vi.fn().mockRejectedValue(new Error("SOCKS connection refused"));
		const adapter = new TorTransportAdapter(node1Id, { tunnelHandler: errorTunnel });
		const errorSpy = vi.fn();

		adapter.on("error", errorSpy);
		await adapter.conectar();

		await expect(adapter.enviar(node2Id, "test")).rejects.toThrow("SOCKS connection refused");
		expect(errorSpy).toHaveBeenCalledTimes(1);
	});

	it("should close connection cleanly and emit 'desconectado'", async () => {
		const adapter = new TorTransportAdapter(node1Id);
		const disconnectSpy = vi.fn();

		adapter.on("desconectado", disconnectSpy);
		await adapter.conectar();
		await adapter.cerrar();

		expect(adapter.estaConectado()).toBe(false);
		expect(adapter.isTunnelActive()).toBe(false);
		expect(adapter.obtenerConexiones()).toEqual([]);
		expect(disconnectSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: node1Id },
			}),
		);
	});
});
