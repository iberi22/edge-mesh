/// <reference types="node" />

import crypto from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import type { PostQuantumIdentity } from "../identity/index.js";
import { bytesAHex, hexABytes } from "../protocol/utils.js";
import { EncryptedChannel } from "./encrypted-plugin.js";

export interface RecipientCiphertext {
	readonly validatorPubKey: string;
	readonly kemCipherText: string;
	readonly ciphertext: string;
	readonly iv: string;
	readonly tag: string;
}

export interface ProofMetadata {
	readonly requestId: string;
	readonly namespace: string;
	readonly payloadHash: string;
	readonly payloadSize: number;
	readonly validatorCount: number;
	readonly applicantPubKey: string;
	readonly signature: string;
	readonly timestamp: number;
}

export interface StoredProof {
	readonly metadata: ProofMetadata;
	readonly recipients: readonly RecipientCiphertext[];
}

export interface ValidatorKeyPair {
	readonly publicKey?: Uint8Array | string;
	readonly secretKey: Uint8Array | string;
}

/**
 * IvnProofs manages E2E Encrypted Identity Verification Network (IVN) proofs.
 * Multi-recipient encryption with ML-KEM-768 + AES-256-GCM under namespace `swal/ivn/proofs/{requestId}`.
 */
export class IvnProofs {
	private readonly proofs: Map<string, StoredProof> = new Map();

	/**
	 * Upload an encrypted proof for multiple validator recipients.
	 * Payload is encrypted using ML-KEM-768 per validator recipient (E2E multi-recipient).
	 * Solicitante signs payload hash with ML-DSA-65 signature.
	 */
	async uploadProof(
		applicantIdentity: PostQuantumIdentity,
		validatorPublicKeys: readonly (Uint8Array | string)[],
		payload: Uint8Array | string,
		requestId?: string,
	): Promise<StoredProof> {
		if (validatorPublicKeys.length === 0) {
			throw new Error("At least one validator public key is required");
		}

		const id = requestId ?? crypto.randomUUID();
		const namespace = `swal/ivn/proofs/${id}`;

		const payloadBytes =
			typeof payload === "string" ? new TextEncoder().encode(payload) : payload;

		// Hash payload (SHA-256)
		const payloadHashBytes = new Uint8Array(
			crypto.createHash("sha256").update(payloadBytes).digest(),
		);
		const payloadHash = bytesAHex(payloadHashBytes);

		// Solicitante signs payload hash using ML-DSA-65 identity signature
		const signatureBytes = await applicantIdentity.firmar(payloadHashBytes);
		const signature = bytesAHex(signatureBytes);

		const applicantPubKey = bytesAHex(applicantIdentity.exportarPublico());

		// Encrypt payload for each validator recipient using ML-KEM-768
		const recipients: RecipientCiphertext[] = [];

		for (const valPubKey of validatorPublicKeys) {
			const valPubKeyBytes =
				typeof valPubKey === "string" ? hexABytes(valPubKey) : valPubKey;

			const { sharedSecret, cipherText: kemCipherTextBytes } =
				ml_kem768.encapsulate(valPubKeyBytes);

			const channel = new EncryptedChannel(sharedSecret);
			const { ciphertext, iv, tag } = channel.encrypt(payloadBytes);

			recipients.push({
				validatorPubKey: bytesAHex(valPubKeyBytes),
				kemCipherText: bytesAHex(kemCipherTextBytes),
				ciphertext: bytesAHex(ciphertext),
				iv: bytesAHex(iv),
				tag: bytesAHex(tag),
			});
		}

		const metadata: ProofMetadata = {
			requestId: id,
			namespace,
			payloadHash,
			payloadSize: payloadBytes.length,
			validatorCount: validatorPublicKeys.length,
			applicantPubKey,
			signature,
			timestamp: Date.now(),
		};

		const storedProof: StoredProof = {
			metadata,
			recipients,
		};

		this.proofs.set(id, storedProof);
		return storedProof;
	}

	/**
	 * Decrypt a stored proof using a validator's ML-KEM-768 secret key.
	 * Only the matching validator can decapsulate and decrypt their copy.
	 * Also verifies applicant ML-DSA-65 signature on decrypted payload hash.
	 */
	async decryptProof(
		validatorKey: ValidatorKeyPair | Uint8Array | string,
		requestId: string,
	): Promise<Uint8Array> {
		const proof = this.proofs.get(requestId);
		if (!proof) {
			throw new Error(`Proof record with requestId '${requestId}' not found`);
		}

		let secretKeyBytes: Uint8Array;
		let pubKeyHex: string | undefined;

		if (
			typeof validatorKey === "object" &&
			!(validatorKey instanceof Uint8Array)
		) {
			secretKeyBytes =
				typeof validatorKey.secretKey === "string"
					? hexABytes(validatorKey.secretKey)
					: validatorKey.secretKey;

			if (validatorKey.publicKey) {
				pubKeyHex =
					typeof validatorKey.publicKey === "string"
						? validatorKey.publicKey
						: bytesAHex(validatorKey.publicKey);
			}
		} else {
			secretKeyBytes =
				typeof validatorKey === "string"
					? hexABytes(validatorKey)
					: validatorKey;
		}

		// Find recipient entry
		let recipient: RecipientCiphertext | undefined;
		if (pubKeyHex) {
			recipient = proof.recipients.find(
				(r) => r.validatorPubKey.toLowerCase() === pubKeyHex!.toLowerCase(),
			);
		}

		// If public key was not specified or not matched directly, try recipient entries
		if (!recipient) {
			for (const r of proof.recipients) {
				try {
					const kemCipherTextBytes = hexABytes(r.kemCipherText);
					const sharedSecret = ml_kem768.decapsulate(
						kemCipherTextBytes,
						secretKeyBytes,
					);

					const channel = new EncryptedChannel(sharedSecret);
					const decrypted = channel.decrypt(
						hexABytes(r.ciphertext),
						hexABytes(r.iv),
						hexABytes(r.tag),
					);

					// Check payload hash
					const hashBytes = new Uint8Array(
						crypto.createHash("sha256").update(decrypted).digest(),
					);
					if (bytesAHex(hashBytes) === proof.metadata.payloadHash) {
						recipient = r;
						// Verify signature
						const applicantPubKeyBytes = hexABytes(
							proof.metadata.applicantPubKey,
						);
						const signatureBytes = hexABytes(proof.metadata.signature);
						const verified = ml_dsa65.verify(
							signatureBytes,
							hashBytes,
							applicantPubKeyBytes,
						);
						if (!verified) {
							throw new Error("Applicant signature verification failed");
						}

						return decrypted;
					}
				} catch {
					// Continue to next recipient if decapsulation/decryption fails
				}
			}
			throw new Error(
				"Unable to decrypt proof: key does not match any recipient",
			);
		}

		// Decapsulate shared secret using recipient's ML-KEM-768 ciphertext & validator's secret key
		const kemCipherTextBytes = hexABytes(recipient.kemCipherText);
		const sharedSecret = ml_kem768.decapsulate(
			kemCipherTextBytes,
			secretKeyBytes,
		);

		const channel = new EncryptedChannel(sharedSecret);
		const decryptedPayload = channel.decrypt(
			hexABytes(recipient.ciphertext),
			hexABytes(recipient.iv),
			hexABytes(recipient.tag),
		);

		// Verify hash
		const hashBytes = new Uint8Array(
			crypto.createHash("sha256").update(decryptedPayload).digest(),
		);
		const hashHex = bytesAHex(hashBytes);
		if (hashHex !== proof.metadata.payloadHash) {
			throw new Error("Payload hash mismatch after decryption");
		}

		// Verify applicant ML-DSA-65 signature
		const applicantPubKeyBytes = hexABytes(proof.metadata.applicantPubKey);
		const signatureBytes = hexABytes(proof.metadata.signature);
		const verified = ml_dsa65.verify(
			signatureBytes,
			hashBytes,
			applicantPubKeyBytes,
		);
		if (!verified) {
			throw new Error("Applicant signature verification failed");
		}

		return decryptedPayload;
	}

	/**
	 * Get public metadata for a proof record without disclosing encrypted payload.
	 */
	getProofMetadata(requestId: string): ProofMetadata | null {
		const proof = this.proofs.get(requestId);
		return proof ? proof.metadata : null;
	}

	/**
	 * Clear all stored proofs in memory.
	 */
	clear(): void {
		this.proofs.clear();
	}
}
