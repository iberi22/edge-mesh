/// <reference types="node" />

import crypto from "node:crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import type { PostQuantumIdentity } from "../identity/index.js";
import { EncryptedChannel } from "../namespaces/encrypted-plugin.js";
import { bytesAHex, hexABytes } from "../protocol/utils.js";
import type { NodoId } from "../types/index.js";

export interface PqcChannelState {
	status: "initiating" | "responding" | "ready";
	readonly keysA?: {
		readonly publicKey: Uint8Array;
		readonly secretKey: Uint8Array;
	};
	readonly challengeA?: string;
	readonly challengeB?: string;
	readonly channel?: EncryptedChannel;
}

/**
 * PqcHandshake orchestrates ML-KEM-768 key exchanges with ML-DSA-65 signatures.
 */
export class PqcHandshake {
	private readonly identity: PostQuantumIdentity;
	private readonly getPeerPublicKey: (peerId: NodoId) => Uint8Array | undefined;

	constructor(
		identity: PostQuantumIdentity,
		getPeerPublicKey: (peerId: NodoId) => Uint8Array | undefined,
	) {
		this.identity = identity;
		this.getPeerPublicKey = getPeerPublicKey;
	}

	/**
	 * Step 1: Alice initiates the handshake.
	 */
	async initiate(targetPeerId: NodoId): Promise<{
		readonly payload: {
			readonly kemPubKey: string;
			readonly challenge: string;
			readonly signature: string;
		};
		readonly keysA: {
			readonly publicKey: Uint8Array;
			readonly secretKey: Uint8Array;
		};
		readonly challengeA: string;
	}> {
		const keysA = ml_kem768.keygen();
		const challengeA = crypto.randomBytes(16).toString("hex");

		const payload = {
			kemPubKey: bytesAHex(keysA.publicKey),
			challenge: challengeA,
		};

		// Sign { kemPubKey, challenge } + targetPeerId to prevent MITM/Replay
		const signData = new TextEncoder().encode(
			payload.kemPubKey + payload.challenge + targetPeerId,
		);
		const signatureBytes = await this.identity.firmar(signData);
		const signature = bytesAHex(signatureBytes);

		return {
			payload: {
				...payload,
				signature,
			},
			keysA,
			challengeA,
		};
	}

	/**
	 * Step 2: Bob responds to Alice's handshake.
	 */
	async respond(
		fromPeerId: NodoId,
		initPayload: {
			readonly kemPubKey: string;
			readonly challenge: string;
			readonly signature: string;
		},
	): Promise<{
		readonly payload: {
			readonly cipherText: string;
			readonly challenge: string;
			readonly signature: string;
		};
		readonly channel: EncryptedChannel;
		readonly challengeB: string;
	}> {
		const pubKeyA = this.getPeerPublicKey(fromPeerId);
		if (!pubKeyA) {
			throw new Error(`Public key of peer ${fromPeerId} not found in registry`);
		}

		// Verify Alice's signature
		const signData = new TextEncoder().encode(
			initPayload.kemPubKey + initPayload.challenge + this.identity.nodoId,
		);
		const verified = await this.identity.verificar(
			signData,
			hexABytes(initPayload.signature),
			pubKeyA,
		);
		if (!verified) {
			throw new Error("Handshake signature verification failed for initiator");
		}

		// Encapsulate
		const kemPubKeyBytes = hexABytes(initPayload.kemPubKey);
		const { sharedSecret, cipherText } = ml_kem768.encapsulate(kemPubKeyBytes);
		const channel = new EncryptedChannel(sharedSecret);

		const challengeB = crypto.randomBytes(16).toString("hex");

		const replyPayload = {
			cipherText: bytesAHex(cipherText),
			challenge: challengeB,
		};

		// Sign Bob's response (challengeA + challengeB + cipherText + fromPeerId)
		const replySignData = new TextEncoder().encode(
			initPayload.challenge + challengeB + replyPayload.cipherText + fromPeerId,
		);
		const replySignatureBytes = await this.identity.firmar(replySignData);
		const replySignature = bytesAHex(replySignatureBytes);

		return {
			payload: {
				...replyPayload,
				signature: replySignature,
			},
			channel,
			challengeB,
		};
	}

	/**
	 * Step 3: Alice finalizes the handshake.
	 */
	async finalize(
		fromPeerId: NodoId,
		state: PqcChannelState,
		replyPayload: {
			readonly cipherText: string;
			readonly challenge: string;
			readonly signature: string;
		},
	): Promise<{
		readonly payload: {
			readonly signature: string;
		};
		readonly channel: EncryptedChannel;
	}> {
		if (state.status !== "initiating" || !state.keysA || !state.challengeA) {
			throw new Error("Invalid handshake state for finalization");
		}

		const pubKeyB = this.getPeerPublicKey(fromPeerId);
		if (!pubKeyB) {
			throw new Error(`Public key of peer ${fromPeerId} not found in registry`);
		}

		// Verify Bob's signature
		const signData = new TextEncoder().encode(
			state.challengeA +
				replyPayload.challenge +
				replyPayload.cipherText +
				this.identity.nodoId,
		);
		const verified = await this.identity.verificar(
			signData,
			hexABytes(replyPayload.signature),
			pubKeyB,
		);
		if (!verified) {
			throw new Error("Handshake signature verification failed for responder");
		}

		// Decapsulate to get shared secret
		const cipherTextBytes = hexABytes(replyPayload.cipherText);
		const sharedSecret = ml_kem768.decapsulate(
			cipherTextBytes,
			state.keysA.secretKey,
		);
		const channel = new EncryptedChannel(sharedSecret);

		// Sign Bob's challenge + fromPeerId (ACK)
		const ackSignData = new TextEncoder().encode(
			replyPayload.challenge + fromPeerId,
		);
		const ackSignatureBytes = await this.identity.firmar(ackSignData);
		const ackSignature = bytesAHex(ackSignatureBytes);

		return {
			payload: {
				signature: ackSignature,
			},
			channel,
		};
	}

	/**
	 * Step 4: Bob verifies Alice's final ACK.
	 */
	async verifyAck(
		fromPeerId: NodoId,
		state: PqcChannelState,
		ackPayload: {
			readonly signature: string;
		},
	): Promise<void> {
		if (state.status !== "responding" || !state.challengeB || !state.channel) {
			throw new Error("Invalid handshake state for ACK verification");
		}

		const pubKeyA = this.getPeerPublicKey(fromPeerId);
		if (!pubKeyA) {
			throw new Error(`Public key of peer ${fromPeerId} not found in registry`);
		}

		// Verify Alice's ACK signature
		const ackSignData = new TextEncoder().encode(
			state.challengeB + this.identity.nodoId,
		);
		const verified = await this.identity.verificar(
			ackSignData,
			hexABytes(ackPayload.signature),
			pubKeyA,
		);
		if (!verified) {
			throw new Error("Handshake signature verification failed for ACK");
		}
	}
}
