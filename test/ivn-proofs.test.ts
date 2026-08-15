import { describe, expect, it } from "vitest";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { createPostQuantumIdentity } from "../src/identity/index.js";
import { IvnProofs } from "../src/namespaces/ivn-proofs.js";
import { bytesAHex } from "../src/protocol/utils.js";

describe("IvnProofs — E2E Encrypted Identity Proofs", () => {
	it("supports multi-recipient encryption for 5 validators and signature verification", async () => {
		const ivnProofs = new IvnProofs();
		const applicant = createPostQuantumIdentity("applicant-node-1");

		// Generate 5 validator ML-KEM-768 keypairs
		const validators = Array.from({ length: 5 }, (_, i) => {
			const keys = ml_kem768.keygen();
			return {
				id: `validator-${i + 1}`,
				publicKey: keys.publicKey,
				secretKey: keys.secretKey,
			};
		});

		const validatorPubKeys = validators.map((v) => v.publicKey);
		const rawPayload = new TextEncoder().encode("SUPER_SECRET_PROOF_DATA_DOCUMENT_2026");
		const requestId = "req-ivn-proof-100";

		// Upload proof
		const storedProof = await ivnProofs.uploadProof(
			applicant,
			validatorPubKeys,
			rawPayload,
			requestId,
		);

		expect(storedProof.metadata.requestId).toBe(requestId);
		expect(storedProof.metadata.namespace).toBe(`swal/ivn/proofs/${requestId}`);
		expect(storedProof.metadata.validatorCount).toBe(5);
		expect(storedProof.metadata.applicantPubKey).toBe(
			bytesAHex(applicant.exportarPublico()),
		);
		expect(storedProof.metadata.payloadSize).toBe(rawPayload.length);

		// Each of the 5 validators can decrypt their copy
		for (const v of validators) {
			const decrypted = await ivnProofs.decryptProof(
				{ publicKey: v.publicKey, secretKey: v.secretKey },
				requestId,
			);
			expect(new TextDecoder().decode(decrypted)).toBe(
				"SUPER_SECRET_PROOF_DATA_DOCUMENT_2026",
			);
		}

		// Non-validators (or invalid keys) CANNOT decrypt
		const attackerKey = ml_kem768.keygen();
		await expect(
			ivnProofs.decryptProof(
				{ publicKey: attackerKey.publicKey, secretKey: attackerKey.secretKey },
				requestId,
			),
		).rejects.toThrow();

		// Metadata is public and does NOT contain raw payload content
		const metadata = ivnProofs.getProofMetadata(requestId);
		expect(metadata).not.toBeNull();
		expect(metadata?.payloadHash).toBeDefined();
		expect(metadata?.signature).toBeDefined();
		expect(JSON.stringify(metadata)).not.toContain("SUPER_SECRET_PROOF_DATA");
	});
});
