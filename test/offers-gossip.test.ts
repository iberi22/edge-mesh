import { describe, expect, it } from "vitest";
import { createPostQuantumIdentity } from "../src/identity/index.js";
import { OffersGossip, OFFERS_TOPIC, SWAL_DATA_COMMONS_OFFERS } from "../src/namespaces/offers-gossip.js";
import type { NodoId } from "../src/types/index.js";

describe("OffersGossip - Market Offers Gossip Namespace", () => {
	it("should have correct swal/data-commons/offers topic constant", () => {
		expect(OFFERS_TOPIC).toBe("swal/data-commons/offers");
		expect(SWAL_DATA_COMMONS_OFFERS).toBe("swal/data-commons/offers");
		const gossip = new OffersGossip();
		expect(gossip.topic).toBe("swal/data-commons/offers");
	});

	it("should publish an offer with ML-DSA-65 signature wrapped in Envolvente", async () => {
		const sellerIdentity = createPostQuantumIdentity("node-seller-1" as NodoId);
		const gossip = new OffersGossip({ identity: sellerIdentity });

		const { offer, envelope } = await gossip.publishOffer({
			id: "offer-101",
			app_id: "data-commons",
			title: "Decentralized Climate Dataset 2026",
			tags: ["climate", "p2p", "dataset"],
			price: "10 SWAL",
			license: "CC-BY-4.0",
			size: 1048576,
			content_hash: "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
			active: true,
		});

		expect(offer.id).toBe("offer-101");
		expect(offer.seller_node).toBe("node-seller-1");
		expect(offer.signature).toBeDefined();
		expect(typeof offer.signature).toBe("string");
		expect(offer.signature.length).toBeGreaterThan(0);

		expect(envelope.origen).toBe("node-seller-1");
		expect(envelope.firma).not.toBeNull();
		expect(envelope.payload).toEqual({
			topic: "swal/data-commons/offers",
			offer,
		});

		expect(gossip.getOffer("offer-101")).toEqual(offer);
		expect(gossip.listOffers()).toHaveLength(1);
	});

	it("should receive, verify signature, and store valid offer envelope from peer", async () => {
		const sellerIdentity = createPostQuantumIdentity("seller-peer-99" as NodoId);
		const buyerIdentity = createPostQuantumIdentity("buyer-peer-01" as NodoId);

		const sellerGossip = new OffersGossip({ identity: sellerIdentity });
		const buyerGossip = new OffersGossip({ identity: buyerIdentity });

		const { offer, envelope } = await sellerGossip.publishOffer({
			id: "offer-202",
			app_id: "salud-p2p",
			title: "Anonymized Health Metrics",
			tags: ["health", "research"],
			price: 5,
			license: "MIT",
			size: 2048,
			content_hash: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
			active: true,
		});

		let receivedOfferInCallback = false;
		buyerGossip.onOffer((recOffer, recEnv) => {
			expect(recOffer.id).toBe("offer-202");
			expect(recEnv.id).toBe(envelope.id);
			receivedOfferInCallback = true;
		});

		const result = await buyerGossip.receiveOfferEnvelope(
			envelope,
			sellerIdentity.exportarPublico(),
			buyerIdentity,
		);

		expect(result.success).toBe(true);
		expect(result.offer).toEqual(offer);
		expect(receivedOfferInCallback).toBe(true);
		expect(buyerGossip.getOffer("offer-202")).toEqual(offer);
	});

	it("should reject offer envelope with invalid ML-DSA-65 signature", async () => {
		const sellerIdentity = createPostQuantumIdentity("seller-node" as NodoId);
		const buyerIdentity = createPostQuantumIdentity("buyer-node" as NodoId);
		const wrongIdentity = createPostQuantumIdentity("wrong-node" as NodoId);

		const sellerGossip = new OffersGossip({ identity: sellerIdentity });
		const buyerGossip = new OffersGossip({ identity: buyerIdentity });

		const { offer, envelope } = await sellerGossip.publishOffer({
			id: "offer-bad-sig",
			app_id: "market-app",
			title: "Tampered Offer",
			tags: ["test"],
			price: 100,
			license: "PROPRIETARY",
			size: 512,
			content_hash: "hash123",
			active: true,
		});

		// Corrupt offer title in payload
		const corruptedPayload = {
			topic: OFFERS_TOPIC,
			offer: { ...offer, title: "Forged Title Modifying Signature Hash" },
		};

		const corruptedEnvelope = {
			...envelope,
			payload: corruptedPayload,
		};

		const result = await buyerGossip.receiveOfferEnvelope(
			corruptedEnvelope,
			sellerIdentity.exportarPublico(),
			buyerIdentity,
		);

		expect(result.success).toBe(false);
		expect(result.reason).toContain("signature verification failed");
		expect(buyerGossip.getOffer("offer-bad-sig")).toBeUndefined();
	});

	it("should enforce per-node rate limits when receiving offer envelopes", async () => {
		const sellerIdentity = createPostQuantumIdentity("spammer-node" as NodoId);
		const buyerIdentity = createPostQuantumIdentity("receiver-node" as NodoId);

		const buyerGossip = new OffersGossip({
			identity: buyerIdentity,
			rateLimiterConfig: {
				tokensPerInterval: 2,
				intervalMs: 10000,
				maxTokens: 2,
			},
		});

		const sellerGossip = new OffersGossip({ identity: sellerIdentity });

		// Send 3 offers in rapid succession (max 2 allowed)
		for (let i = 1; i <= 3; i++) {
			const { envelope } = await sellerGossip.publishOffer({
				id: `offer-spam-${i}`,
				app_id: "spam-app",
				title: `Spam ${i}`,
				tags: ["spam"],
				price: 0,
				license: "MIT",
				size: 10,
				content_hash: `hash-${i}`,
				active: true,
			});

			const res = await buyerGossip.receiveOfferEnvelope(envelope);
			if (i <= 2) {
				expect(res.success).toBe(true);
			} else {
				expect(res.success).toBe(false);
				expect(res.reason).toBe("Rate limit exceeded for origin node");
			}
		}
	});

	it("should prune expired offers based on TTL and clock provider", async () => {
		let mockTime = 1000000;
		const clock = () => mockTime;

		const ttlMs = 24 * 60 * 60 * 1000; // 1 day
		const sellerIdentity = createPostQuantumIdentity("ttl-seller" as NodoId);
		const gossip = new OffersGossip({
			identity: sellerIdentity,
			ttlMs,
			getCurrentTime: clock,
		});

		await gossip.publishOffer({
			id: "offer-fresh",
			app_id: "app-1",
			title: "Fresh Offer",
			tags: ["fresh"],
			price: 1,
			license: "MIT",
			size: 100,
			content_hash: "hash-fresh",
			active: true,
			created_at: mockTime,
		});

		await gossip.publishOffer({
			id: "offer-old",
			app_id: "app-1",
			title: "Old Offer",
			tags: ["old"],
			price: 1,
			license: "MIT",
			size: 100,
			content_hash: "hash-old",
			active: true,
			created_at: mockTime - ttlMs - 1000, // Expired
		});

		expect(gossip.listOffers()).toHaveLength(2);
		expect(gossip.getActiveOffers(mockTime)).toHaveLength(1);
		expect(gossip.getActiveOffers(mockTime)[0].id).toBe("offer-fresh");

		// Advance mock clock past 1 day for fresh offer as well
		mockTime += ttlMs + 5000;

		const prunedCount = gossip.pruneExpiredOffers(mockTime);
		expect(prunedCount).toBe(2);
		expect(gossip.listOffers()).toHaveLength(0);
	});
});
