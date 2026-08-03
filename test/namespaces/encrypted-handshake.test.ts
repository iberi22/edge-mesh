import { describe, expect, it } from "vitest";
import { createPostQuantumIdentity } from "../../src/identity/index.js";
import {
	EncryptedChannel,
	EncryptedHandshake,
} from "../../src/namespaces/encrypted-plugin.js";
import { hexABytes } from "../../src/protocol/utils.js";
import type { NodoId } from "../../src/types/index.js";

describe("encrypted handshake", () => {
	it("Handshake exitoso con identidades validas", async () => {
		const aliceId = createPostQuantumIdentity("alice" as NodoId);
		const bobId = createPostQuantumIdentity("bob" as NodoId);

		const handshake = new EncryptedHandshake();

		// 1. Alice inicia el handshake
		const { message: initMsg, ephemeralPrivateKey: alicePrivKey } =
			await handshake.initiate(aliceId);

		// 2. Bob recibe y responde al handshake
		const { response: respMsg, sharedSecret: bobSecret } =
			await handshake.respond(bobId, initMsg);

		// 3. Alice finaliza el handshake
		const aliceSecret = await handshake.finalize(
			aliceId,
			alicePrivKey,
			initMsg,
			respMsg,
		);

		// Verificar que ambos derivan la misma clave compartida
		expect(aliceSecret).toEqual(bobSecret);

		// Establecer canales AEAD con la clave derivada
		const aliceChannel = new EncryptedChannel(aliceSecret);
		const bobChannel = new EncryptedChannel(bobSecret);

		// Probar cifrado y descifrado bidireccional
		const originalText = new TextEncoder().encode("Mensaje ultrasecreto PQC");
		const encrypted = aliceChannel.encrypt(originalText);

		const decrypted = bobChannel.decrypt(
			encrypted.ciphertext,
			encrypted.iv,
			encrypted.tag,
		);
		expect(new TextDecoder().decode(decrypted)).toBe(
			"Mensaje ultrasecreto PQC",
		);
	});

	it("Handshake rechazado si identidad no coincide o firma invalida", async () => {
		const aliceId = createPostQuantumIdentity("alice" as NodoId);
		const bobId = createPostQuantumIdentity("bob" as NodoId);

		const handshake = new EncryptedHandshake();

		// 1. Alice inicia el handshake
		const { message: initMsg } = await handshake.initiate(aliceId);

		// Caso A: Se modifica la firma de Alice
		const tamperedInitMsg = {
			...initMsg,
			signature: "00".repeat(initMsg.signature.length / 2), // Firma corrupta
		};

		await expect(
			handshake.respond(bobId, tamperedInitMsg),
		).rejects.toThrowError(/Handshake verification failed/);

		// Caso B: Se intenta usar una clave de identidad distinta a la que firmó
		const eveId = createPostQuantumIdentity("eve" as NodoId);
		const tamperedIdentityMsg = {
			...initMsg,
			identityPubKey: Buffer.from(eveId.exportarPublico()).toString("hex"),
		};

		await expect(
			handshake.respond(bobId, tamperedIdentityMsg),
		).rejects.toThrowError(/Handshake verification failed/);
	});

	it("Replay de handshake rechazado", async () => {
		const aliceId = createPostQuantumIdentity("alice" as NodoId);
		const bobId = createPostQuantumIdentity("bob" as NodoId);

		const handshake = new EncryptedHandshake();

		// Alice inicia el handshake
		const { message: initMsg } = await handshake.initiate(aliceId);

		// Bob procesa la solicitud por primera vez (exito)
		await handshake.respond(bobId, initMsg);

		// Bob recibe la misma solicitud nuevamente (replay)
		await expect(handshake.respond(bobId, initMsg)).rejects.toThrowError(
			/Replay attack detected/,
		);
	});

	it("Man-in-the-middle detectado", async () => {
		const aliceId = createPostQuantumIdentity("alice" as NodoId);
		const bobId = createPostQuantumIdentity("bob" as NodoId);

		const handshake = new EncryptedHandshake();

		// Alice inicia el handshake
		const { message: initMsg } = await handshake.initiate(aliceId);

		// Un atacante (Eve) intenta suplantar la clave publica de intercambio X25519
		// modificando la clave de Alice por una suya sin conocer la clave privada de identidad de Alice.
		const tamperedInitMsg = {
			...initMsg,
			x25519PubKey: "ab".repeat(32), // Clave X25519 falsa del atacante
		};

		// Bob procesa el mensaje de inicio alterado por el atacante
		// Debe ser rechazado porque la firma de Alice cubre el x25519PubKey original.
		await expect(
			handshake.respond(bobId, tamperedInitMsg),
		).rejects.toThrowError(/Handshake verification failed/);
	});
});
