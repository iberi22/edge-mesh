import { describe, expect, it } from "vitest";
import {
	createPostQuantumIdentity,
	generateKeypair,
	identityFromSecret,
	serializeKeypair,
} from "../../src/identity/index.js";
import {
	createEnvelope,
	signEnvelope,
	verifyEnvelopeSignature,
} from "../../src/protocol/index.js";
import type { NodoId } from "../../src/types/index.js";
import { TIPO_MENSAJE } from "../../src/types/index.js";

describe("identity sign/verify", () => {
	it("roundtrips ML-DSA signature on envelopes", async () => {
		const identity = createPostQuantumIdentity(
			"n1" as NodoId,
			generateKeypair("maestra"),
		);
		const env = createEnvelope(TIPO_MENSAJE.SYNC, "n1" as NodoId, "*", {
			hello: true,
		});
		const signed = await signEnvelope(env, identity);
		const ok = await verifyEnvelopeSignature(
			signed,
			identity.exportarPublico(),
			identity,
		);
		expect(ok).toBe(true);
	});

	it("identityFromSecret restores serialized keypair consistently", async () => {
		const original = generateKeypair("maestra");
		const serialized = serializeKeypair(original);
		const raw = Uint8Array.from(atob(serialized), (c) => c.codePointAt(0)!);
		const restored = identityFromSecret("n2" as NodoId, raw, "maestra");

		const msg = new TextEncoder().encode("shelf-test");
		const sig = await restored.firmar(msg);
		const ok = await restored.verificar(msg, sig, restored.exportarPublico());
		expect(ok).toBe(true);
	});
});
