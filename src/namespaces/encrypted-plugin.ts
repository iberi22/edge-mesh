/// <reference types="node" />
import crypto from "node:crypto";
import type { PostQuantumIdentity } from "../identity/index.js";
import { canonicalSerialize } from "../protocol/canonical.js";
import { bytesAHex, hexABytes } from "../protocol/utils.js";

export interface HandshakeInit {
	readonly x25519PubKey: string;
	readonly identityPubKey: string;
	readonly nonce_a: string;
	readonly signature: string;
}

export interface HandshakeResponse {
	readonly x25519PubKey: string;
	readonly identityPubKey: string;
	readonly nonce_b: string;
	readonly signature: string;
}

export class EncryptedChannel {
	private readonly key: Uint8Array;

	constructor(sharedSecret: Uint8Array) {
		// Use SHA-256 of the shared secret to derive a robust 256-bit symmetric key
		this.key = new Uint8Array(
			crypto.createHash("sha256").update(sharedSecret).digest(),
		);
	}

	encrypt(plaintext: Uint8Array): {
		readonly ciphertext: Uint8Array;
		readonly iv: Uint8Array;
		readonly tag: Uint8Array;
	} {
		const iv = crypto.randomBytes(12);
		const cipher = crypto.createCipheriv("aes-256-gcm", this.key, iv);
		const ciphertext = Buffer.concat([
			cipher.update(plaintext),
			cipher.final(),
		]);
		const tag = cipher.getAuthTag();
		return {
			ciphertext: new Uint8Array(ciphertext),
			iv: new Uint8Array(iv),
			tag: new Uint8Array(tag),
		};
	}

	decrypt(ciphertext: Uint8Array, iv: Uint8Array, tag: Uint8Array): Uint8Array {
		const decipher = crypto.createDecipheriv("aes-256-gcm", this.key, iv);
		decipher.setAuthTag(tag);
		const plaintext = Buffer.concat([
			decipher.update(ciphertext),
			decipher.final(),
		]);
		return new Uint8Array(plaintext);
	}
}

export class EncryptedHandshake {
	private readonly seenNonces: Set<string> = new Set();

	/**
	 * Alice starts the handshake.
	 * Generates X25519 keypair and creates HandshakeInit message.
	 */
	async initiate(aliceIdentity: PostQuantumIdentity): Promise<{
		readonly message: HandshakeInit;
		readonly ephemeralPrivateKey: crypto.KeyObject;
	}> {
		const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
		const x25519PubKeyDer = publicKey.export({ type: "spki", format: "der" });
		const x25519PubKeyHex = bytesAHex(new Uint8Array(x25519PubKeyDer));

		const identityPubKey = aliceIdentity.exportarPublico();
		const identityPubKeyHex = bytesAHex(identityPubKey);

		// Generate random nonce_a
		const nonce_a = crypto.randomBytes(16).toString("hex");

		// Bind signature to ephemeral X25519 key + identityPubKey + nonce_a
		const payload = {
			x25519PubKey: x25519PubKeyHex,
			identityPubKey: identityPubKeyHex,
			nonce_a,
		};
		const signatureBytes = await aliceIdentity.firmar(
			canonicalSerialize(payload),
		);
		const signatureHex = bytesAHex(signatureBytes);

		return {
			message: {
				x25519PubKey: x25519PubKeyHex,
				identityPubKey: identityPubKeyHex,
				nonce_a,
				signature: signatureHex,
			},
			ephemeralPrivateKey: privateKey,
		};
	}

	/**
	 * Bob receives Alice's HandshakeInit and responds.
	 * Returns Bob's HandshakeResponse and Bob's derived shared secret.
	 */
	async respond(
		bobIdentity: PostQuantumIdentity,
		initMsg: HandshakeInit,
	): Promise<{
		readonly response: HandshakeResponse;
		readonly sharedSecret: Uint8Array;
	}> {
		// Replay check
		if (this.seenNonces.has(initMsg.nonce_a)) {
			throw new Error("Replay attack detected: nonce_a already used");
		}

		// Verify Alice's signature
		const alicePayload = {
			x25519PubKey: initMsg.x25519PubKey,
			identityPubKey: initMsg.identityPubKey,
			nonce_a: initMsg.nonce_a,
		};
		const verified = await bobIdentity.verificar(
			canonicalSerialize(alicePayload),
			hexABytes(initMsg.signature),
			hexABytes(initMsg.identityPubKey),
		);
		if (!verified) {
			throw new Error("Handshake verification failed for Alice signature");
		}

		// Record nonce to prevent future replay
		this.seenNonces.add(initMsg.nonce_a);

		// Generate Bob's X25519 keypair
		const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
		const x25519PubKeyDer = publicKey.export({ type: "spki", format: "der" });
		const x25519PubKeyHex = bytesAHex(new Uint8Array(x25519PubKeyDer));

		const bobIdentityPubKey = bobIdentity.exportarPublico();
		const bobIdentityPubKeyHex = bytesAHex(bobIdentityPubKey);

		// Generate random nonce_b
		const nonce_b = crypto.randomBytes(16).toString("hex");

		// Bind Bob's signature to Bob's ephemeral X25519 key + Bob's identityPubKey + nonce_b + Alice's nonce_a
		const bobPayload = {
			x25519PubKey: x25519PubKeyHex,
			identityPubKey: bobIdentityPubKeyHex,
			nonce_b,
			nonce_a: initMsg.nonce_a,
		};
		const signatureBytes = await bobIdentity.firmar(
			canonicalSerialize(bobPayload),
		);
		const signatureHex = bytesAHex(signatureBytes);

		// Derive Bob's shared secret
		const aliceX25519PubKey = crypto.createPublicKey({
			key: hexABytes(initMsg.x25519PubKey),
			format: "der",
			type: "spki",
		});
		const sharedSecret = crypto.diffieHellman({
			privateKey,
			publicKey: aliceX25519PubKey,
		});

		return {
			response: {
				x25519PubKey: x25519PubKeyHex,
				identityPubKey: bobIdentityPubKeyHex,
				nonce_b,
				signature: signatureHex,
			},
			sharedSecret: new Uint8Array(sharedSecret),
		};
	}

	/**
	 * Alice receives Bob's HandshakeResponse and finalizes.
	 * Returns Alice's derived shared secret.
	 */
	async finalize(
		aliceIdentity: PostQuantumIdentity,
		aliceEphemeralPrivateKey: crypto.KeyObject,
		initMsg: HandshakeInit,
		responseMsg: HandshakeResponse,
	): Promise<Uint8Array> {
		// Verify Bob's signature
		const bobPayload = {
			x25519PubKey: responseMsg.x25519PubKey,
			identityPubKey: responseMsg.identityPubKey,
			nonce_b: responseMsg.nonce_b,
			nonce_a: initMsg.nonce_a,
		};
		const verified = await aliceIdentity.verificar(
			canonicalSerialize(bobPayload),
			hexABytes(responseMsg.signature),
			hexABytes(responseMsg.identityPubKey),
		);
		if (!verified) {
			throw new Error("Handshake verification failed for Bob signature");
		}

		// Derive Alice's shared secret
		const bobX25519PubKey = crypto.createPublicKey({
			key: hexABytes(responseMsg.x25519PubKey),
			format: "der",
			type: "spki",
		});
		const sharedSecret = crypto.diffieHellman({
			privateKey: aliceEphemeralPrivateKey,
			publicKey: bobX25519PubKey,
		});

		return new Uint8Array(sharedSecret);
	}

	/**
	 * Helper method to perform a full simulated handshake between Alice and Bob.
	 */
	static async perform(
		alice: PostQuantumIdentity,
		bob: PostQuantumIdentity,
		replaySet: Set<string> = new Set(),
	): Promise<{
		readonly aliceChannel: EncryptedChannel;
		readonly bobChannel: EncryptedChannel;
	}> {
		const handshake = new EncryptedHandshake();
		if (replaySet) {
			(handshake as any).seenNonces = replaySet;
		}

		// 1. Alice initiates
		const { message: initMsg, ephemeralPrivateKey: alicePrivKey } =
			await handshake.initiate(alice);

		// 2. Bob responds
		const { response: respMsg, sharedSecret: bobSecret } =
			await handshake.respond(bob, initMsg);

		// 3. Alice finalizes
		const aliceSecret = await handshake.finalize(
			alice,
			alicePrivKey,
			initMsg,
			respMsg,
		);

		return {
			aliceChannel: new EncryptedChannel(aliceSecret),
			bobChannel: new EncryptedChannel(bobSecret),
		};
	}
}
