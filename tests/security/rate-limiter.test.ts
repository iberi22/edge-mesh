import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TokenBucketRateLimiter } from "../../src/security/rate-limiter.js";
import { ChatChannel } from "../../src/chat/index.js";
import { YjsAdapter, EdgeMesh } from "../../src/edge-mesh.js";
import { MalocaGatewayAPI } from "../../src/maloca/gateway/api.js";
import { MalocaWSGateway } from "../../src/maloca/gateway/websocket.js";
import {
	loginWithPQC,
	authRateLimiter,
} from "../../src/maloca/gateway/auth.js";
import { MeshManager } from "../../src/mesh/index.js";
import type { GossipMessage } from "../../src/mesh/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("TokenBucketRateLimiter and Security Rate Limiting", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should enforce basic TokenBucketRateLimiter behavior", () => {
		const limiter = new TokenBucketRateLimiter({
			tokensPerInterval: 5,
			intervalMs: 1000,
			maxTokens: 10,
		});

		const key = "test-client";

		// Consume all 10 burst tokens
		for (let i = 0; i < 10; i++) {
			expect(limiter.consume(key)).toBe(true);
		}

		// The 11th consume should fail
		expect(limiter.consume(key)).toBe(false);

		// Advance time by 400ms -> should refill 5 * 0.4 = 2 tokens
		vi.advanceTimersByTime(400);
		expect(limiter.consume(key)).toBe(true);
		expect(limiter.consume(key)).toBe(true);
		expect(limiter.consume(key)).toBe(false); // 3rd fails

		// Reset should clear and allow full burst again
		limiter.reset(key);
		for (let i = 0; i < 10; i++) {
			expect(limiter.consume(key)).toBe(true);
		}
		expect(limiter.consume(key)).toBe(false);
	});

	it("should rate limit chat messages in ChatChannel per peer", async () => {
		const yjsAdapter = new YjsAdapter();
		const peerId = "peer1" as NodoId;
		const channel = new ChatChannel(peerId, "lobby", yjsAdapter);

		const rateLimitedSpy = vi.fn();
		channel.addEventListener("rate_limited", rateLimitedSpy);

		// Send 20 messages (burst limit)
		for (let i = 0; i < 20; i++) {
			const id = await channel.enviarMensaje(`message ${i}`);
			expect(id).toBeDefined();
		}

		// The 21st message must fail
		await expect(channel.enviarMensaje("flood")).rejects.toThrow(
			"Rate limit exceeded",
		);
		expect(rateLimitedSpy).toHaveBeenCalledTimes(1);
		expect(rateLimitedSpy.mock.calls[0][0].detail).toEqual({
			peerId,
			resource: "chat",
		});

		// Advance 1 second to refill 10 tokens
		vi.advanceTimersByTime(1000);
		const idAfterRefill = await channel.enviarMensaje("after refill");
		expect(idAfterRefill).toBeDefined();
	});

	it("should rate limit Gateway REST API per IP/peer", async () => {
		const mesh = new EdgeMesh({
			nodoId: "test-node" as NodoId,
			storageBackend: "mem",
		});
		const api = new MalocaGatewayAPI(mesh);
		const clientIp = "192.168.1.50";

		// Gateway API allows 100 burst tokens
		for (let i = 0; i < 100; i++) {
			const status = await api.getMeshStatus(clientIp);
			expect(status.status).toBe("online");
		}

		// 101st request should be rejected
		await expect(api.getMeshStatus(clientIp)).rejects.toThrow(
			"Rate limit exceeded: 429",
		);

		// Different IP should not be blocked
		const otherIpStatus = await api.getMeshStatus("192.168.1.51");
		expect(otherIpStatus.status).toBe("online");
	});

	it("should rate limit Gateway WS Connect per IP", async () => {
		const mesh = new EdgeMesh({
			nodoId: "test-node" as NodoId,
			storageBackend: "mem",
		});
		const wsGateway = new MalocaWSGateway(mesh);
		const clientIp = "10.0.0.1";

		const rateLimitedSpy = vi.fn();
		wsGateway.addEventListener("rate_limited", rateLimitedSpy);

		// Gateway WS connect allows 10 burst tokens
		for (let i = 0; i < 10; i++) {
			const result = await wsGateway.connectWS(`profile-${i}`, clientIp);
			expect(result.connectionId).toBeDefined();
		}

		// 11th connection should throw and emit event
		await expect(wsGateway.connectWS("profile-11", clientIp)).rejects.toThrow(
			"Rate limit exceeded: 429",
		);
		expect(rateLimitedSpy).toHaveBeenCalledTimes(1);
		expect(rateLimitedSpy.mock.calls[0][0].detail).toEqual({
			peerId: clientIp,
			resource: "websocket",
		});
	});

	it("should rate limit Auth Login per IP", async () => {
		const clientIp = "172.16.0.10";
		authRateLimiter.reset(clientIp);

		const fakeFirma = new Uint8Array(3309).fill(0);
		const fakePublicKey = new Uint8Array(1760).fill(0);

		// Auth login allows 5 burst tokens.
		// Note: since fake credentials will fail authentication, loginWithPQC returns null,
		// but the rate limit check comes BEFORE validation. So first 5 will run and return null,
		// and the 6th will throw the 429 error.
		for (let i = 0; i < 5; i++) {
			const token = await loginWithPQC(
				fakeFirma,
				fakePublicKey,
				undefined,
				clientIp,
			);
			expect(token).toBeNull();
		}

		await expect(
			loginWithPQC(fakeFirma, fakePublicKey, undefined, clientIp),
		).rejects.toThrow("Rate limit exceeded: 429");
	});

	it("should rate limit Gossip receive per peer", async () => {
		const mockEdgeMesh = {
			on: vi.fn(),
			off: vi.fn(),
			enviar: vi.fn().mockResolvedValue(undefined),
			transmitir: vi.fn().mockResolvedValue(undefined),
		};
		const meshManager = new MeshManager(
			{ nodoId: "node1" as NodoId },
			mockEdgeMesh as any,
		);
		await meshManager.iniciar();

		const peerId = "peer-spammer" as NodoId;
		const rateLimitedSpy = vi.fn();
		meshManager.addEventListener("rate_limited", rateLimitedSpy);

		const gossipReceivedSpy = vi.fn();
		meshManager.addEventListener("gossipRecibido", gossipReceivedSpy);

		// Gossip receive has 200 burst tokens.
		// Send 200 unique gossip messages from the same peer (by adding peer to the end of the route)
		for (let i = 0; i < 200; i++) {
			const gossipMsg: GossipMessage = {
				id: `gossip-msg-${i}`,
				namespace: "lobby",
				ttl: 3,
				payload: { msg: `hello-${i}` },
				origen: peerId,
				timestamp: Date.now(),
				ruta: [peerId],
			};
			meshManager.procesarGossip(gossipMsg);
		}

		expect(gossipReceivedSpy).toHaveBeenCalledTimes(200);
		expect(rateLimitedSpy).not.toHaveBeenCalled();

		// The 201st gossip from the same peer should be ignored (not trigger gossipRecibido)
		const extraGossipMsg: GossipMessage = {
			id: "gossip-msg-extra",
			namespace: "lobby",
			ttl: 3,
			payload: { msg: "extra" },
			origen: peerId,
			timestamp: Date.now(),
			ruta: [peerId],
		};
		meshManager.procesarGossip(extraGossipMsg);

		expect(gossipReceivedSpy).toHaveBeenCalledTimes(200); // Count should not increase
		expect(rateLimitedSpy).toHaveBeenCalledTimes(1);
		expect(rateLimitedSpy.mock.calls[0][0].detail).toEqual({
			peerId,
			resource: "gossip",
		});

		await meshManager.detener();
	});
});
