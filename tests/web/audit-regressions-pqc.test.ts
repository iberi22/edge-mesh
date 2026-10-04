// PQC migration (AGENTS.md §2): every identity / authorization signature of the browser mesh is ML-DSA-65, the device
// id is the fingerprint of that key with one canonical encoding, and nothing falls back to ECDSA.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import { idMatchesPub } from "../../src/web/admission.js";
import {
	createLoopbackHub,
	createMesh,
	fingerprint,
} from "../../src/web/index.js";
import { hostProofBytes } from "../../src/web/pairing.js";
import { deviceIdOf, identityVerify } from "../../src/web/pq.js";
import { keyFingerprint } from "../../src/web/trust/keys.js";
import { b64uEncode } from "../../src/web/util.js";
import { makeVault, pairDirect } from "./helpers.js";

async function ecdsaKey() {
	const kp = (await crypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const pub = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	);
	const sign = async (d: Uint8Array) =>
		new Uint8Array(
			await crypto.subtle.sign(
				{ name: "ECDSA", hash: "SHA-256" },
				kp.privateKey,
				d as BufferSource,
			),
		);
	return { pub, sign };
}

const meshWith = (vault: Awaited<ReturnType<typeof makeVault>>) =>
	createMesh({
		appId: "fize",
		topic: "fize/data/r1",
		doc: new Y.Doc(),
		vault,
		signaling: [createLoopbackHub().transport()],
		deviceName: "x",
	});

describe("PQC: ML-DSA-65 identities, no ECDSA fallback", () => {
	it("Q1: a vault with an ECDSA P-256 identity key is refused (no legacy fallback)", async () => {
		const base = await makeVault("q1");
		const e = await ecdsaKey();
		const vault = {
			...base,
			devicePublicKey: e.pub,
			deviceId: await deviceIdOf(e.pub),
			sign: e.sign,
		};
		const m = meshWith(vault);
		await expect(m.ready).rejects.toThrow(/ML-DSA-65/);
		m.destroy();
	});

	it("Q2: deviceId = deviceIdOf(pub) = trust keyFingerprint(pub) (43 chars); the old SHA-256(pub)[0..22] id is refused", async () => {
		const v = await makeVault("q2");
		const pub = b64uEncode(v.devicePublicKey);
		expect(v.deviceId).toHaveLength(43);
		expect(v.deviceId).toBe(await keyFingerprint(pub));
		expect(await idMatchesPub(v.deviceId, pub)).toBe(true);
		const legacy = await fingerprint(v.devicePublicKey);
		expect(await idMatchesPub(legacy, pub)).toBe(false);
		const m = meshWith({ ...v, deviceId: legacy });
		await expect(m.ready).rejects.toThrow(/deviceIdOf/);
		m.destroy();
	});

	it("Q3: identityVerify accepts ML-DSA-65 only; ECDSA keys/signatures and truncated inputs are false, never a throw", async () => {
		const kp = ml_dsa65.keygen();
		const msg = new TextEncoder().encode("swal");
		const sig = ml_dsa65.sign(msg, kp.secretKey);
		expect(sig).toHaveLength(3309);
		expect(kp.publicKey).toHaveLength(1952);
		expect(identityVerify(kp.publicKey, msg, sig)).toBe(true);
		expect(
			identityVerify(kp.publicKey, new TextEncoder().encode("swaL"), sig),
		).toBe(false);
		expect(identityVerify(kp.publicKey, msg, sig.subarray(1))).toBe(false);
		const e = await ecdsaKey();
		const esig = await e.sign(msg);
		expect(identityVerify(e.pub, msg, esig)).toBe(false);
		expect(identityVerify(kp.publicKey, msg, esig)).toBe(false);
	});

	it("Q4: the guest refuses a grant whose host cannot prove (ML-DSA-65, over the transcript) the identity named by the QR", async () => {
		const host = await makeVault("q4host");
		const guest = await makeVault("q4guest");
		const evil = await makeVault("q4evil");
		// honest host: granted
		expect((await pairDirect(host, guest)).guest).toBe("granted");
		// a host proving another identity than the QR's hostId
		const other = await pairDirect(host, guest, {
			prove: async (t) => {
				const pub = b64uEncode(evil.devicePublicKey);
				return {
					pub,
					sig: b64uEncode(
						await evil.sign(hostProofBytes(t, evil.deviceId, pub)),
					),
				};
			},
		});
		expect(other.guest).toMatch(/did not prove/);
		// a proof by the right key over another transcript (replayed from an earlier session)
		const replay = await pairDirect(host, guest, {
			prove: async () => {
				const pub = b64uEncode(host.devicePublicKey);
				return {
					pub,
					sig: b64uEncode(
						await host.sign(
							hostProofBytes(new Uint8Array(32), host.deviceId, pub),
						),
					),
				};
			},
		});
		expect(replay.guest).toMatch(/did not prove/);
		// a QR edited to name another host (hostId of the victim): the real host's proof no longer matches
		const edited = await pairDirect(host, guest, {
			payload: (p) => ({ ...p, hostId: evil.deviceId }),
		});
		expect(edited.guest).toMatch(/did not prove|transcript|refused/);
		// no proof at all
		const none = await pairDirect(host, guest, {
			prove: async () => undefined as never,
		});
		expect(none.guest).toMatch(/did not prove/);
	});
});
