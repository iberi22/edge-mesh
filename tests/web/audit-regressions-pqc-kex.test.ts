// PQC migration (AGENTS.md §2), key exchanges: the pairing session and the rotation wraps combine ML-KEM-768 with
// ECDH P-256 (HKDF-SHA-256 over ML-KEM secret || ECDH secret); both halves are required, no ECDH-only fallback.
import { describe, expect, it } from "vitest";
import {
	createLoopbackHub,
	deriveRoomId,
	type PeerLink,
} from "../../src/web/index.js";
import {
	createPairOffer,
	type GrantBody,
	GuestPairing,
	HostPairing,
	hostProofBytes,
} from "../../src/web/pairing.js";
import {
	hybridSecret,
	identityVerify,
	kemEncapsulate,
	kemKeygen,
} from "../../src/web/pq.js";
import {
	ecdhSignedBytes,
	rotationId,
	rotationPreId,
	rotationSigBytes,
	unwrapMeshKey,
	wrapMeshKey,
	wrapsHash,
} from "../../src/web/rotation.js";
import {
	b64uDecode,
	b64uEncode,
	randomBytes,
	utf8,
} from "../../src/web/util.js";
import { rawPeer, TOPIC } from "./audit-r3-lib.js";
import {
	makeDev,
	makeVault,
	metaOf,
	pair,
	storedWraps,
	trio,
	until,
} from "./helpers.js";

type Msg = Parameters<HostPairing["handle"]>[0];

/** Host and guest state machines back to back; `tamper` may rewrite any message in flight (a relay in the middle). */
async function pairVia(tamper: (m: Msg, to: "host" | "guest") => Msg) {
	const hostVault = await makeVault("kexHost");
	const guestVault = await makeVault("kexGuest");
	const offer = await createPairOffer(hostVault, {
		mid: "m",
		root: hostVault.deviceId,
		appId: "app",
		topic: "app/data/x",
		now: Date.now(),
	});
	const seen: Msg[] = [];
	const sas: { host?: string; guest?: string } = {};
	const host = new HostPairing(offer, {
		now: Date.now,
		verify: identityVerify,
		prove: async (t) => {
			const pub = b64uEncode(hostVault.devicePublicKey);
			return {
				pub,
				sig: b64uEncode(
					await hostVault.sign(hostProofBytes(t, hostVault.deviceId, pub)),
				),
			};
		},
		onSas: (p) => {
			sas.host = p.code;
			p.confirm();
		},
		buildGrant: async (): Promise<GrantBody> => ({
			meshKey: "",
			epoch: 0,
			mid: "m",
		}),
		onPaired() {},
		onFail() {},
	});
	const guest = await GuestPairing.create(offer.payload, guestVault, {
		name: "g",
		onSas: async (c) => {
			sas.guest = c;
			return true;
		},
		now: Date.now(),
	});
	const toGuest = (m: Msg) => {
		seen.push(m);
		queueMicrotask(() => void guest.handle(tamper(m, "guest"), toHost));
	};
	const toHost = (m: Msg) => {
		seen.push(m);
		queueMicrotask(() => void host.handle(tamper(m, "host"), toGuest));
	};
	guest.attach(toHost);
	const res = await Promise.race([
		guest.result.then(
			() => "granted",
			(e: Error) => e.message,
		),
		new Promise<string>((r) => setTimeout(() => r("timeout"), 3000)),
	]);
	return { res, sas, seen };
}

describe("PQC: hybrid ML-KEM-768 + ECDH P-256 key exchanges", () => {
	it("Q5: the pairing session is hybrid; a substituted ML-KEM ciphertext changes the SAS and nothing is granted", async () => {
		const ok = await pairVia((m) => m);
		expect(ok.res).toBe("granted");
		expect(ok.sas.guest).toBe(ok.sas.host);
		const hello = ok.seen.find((m) => m.t === "hello") as Record<
			string,
			string
		>;
		const ready = ok.seen.find((m) => m.t === "ready") as Record<
			string,
			string
		>;
		expect(b64uDecode(hello.k as string)).toHaveLength(1184); // guest's ephemeral ML-KEM-768 encapsulation key
		expect(b64uDecode(ready.c as string)).toHaveLength(1088); // host's ciphertext
		// a relay that re-encapsulates to the guest's key (it then knows the KEM half, not the ECDH half)
		let guestKem = "";
		const mitm = await pairVia((m) => {
			const r = m as Record<string, string>;
			if (m.t === "hello") guestKem = r.k as string;
			if (m.t === "ready")
				return {
					...m,
					c: b64uEncode(kemEncapsulate(b64uDecode(guestKem)).cipherText),
				} as Msg;
			return m;
		});
		expect(mitm.sas.guest).toMatch(/^\d{6}$/);
		expect(mitm.sas.guest).not.toBe(mitm.sas.host);
		expect(mitm.res).not.toBe("granted");
		// a host reply without the ML-KEM half is refused (no ECDH-only session)
		const noKem = await pairVia((m) =>
			m.t === "ready" ? ({ t: "ready" } as Msg) : m,
		);
		expect(noKem.res).toMatch(/ML-KEM/);
		expect(noKem.sas.guest).toBeUndefined();
	});

	it("Q6: the hybrid combiner needs both secrets and depends on each of them", async () => {
		const k = randomBytes(32);
		const e = randomBytes(32);
		const s = await hybridSecret(k, e, "info", randomBytes(32).fill(1));
		expect(s).toHaveLength(32);
		expect(await hybridSecret(k, e, "info", randomBytes(32).fill(1))).toEqual(
			s,
		);
		const k2 = k.slice();
		k2[0] ^= 1;
		const e2 = e.slice();
		e2[31] ^= 1;
		expect(
			await hybridSecret(k2, e, "info", randomBytes(32).fill(1)),
		).not.toEqual(s);
		expect(
			await hybridSecret(k, e2, "info", randomBytes(32).fill(1)),
		).not.toEqual(s);
		expect(() => hybridSecret(new Uint8Array(0), e, "info")).toThrow(/both/);
		expect(() => hybridSecret(k, new Uint8Array(0), "info")).toThrow(/both/);
	});

	it("Q7: rotation wraps carry an ML-KEM-768 ciphertext; the recipient's ECDH key alone (or another KEM key) cannot open them", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const entry = metaOf(a).get(`ecdh/${b.id}`);
		expect(b64uDecode(entry.kem)).toHaveLength(1184); // the device record carries its ML-KEM encapsulation key
		await a.mesh.revoke(c.id);
		await until(
			() => b.mesh.epoch === 1 && storedWraps(a, 1).some((w) => w.to === b.id),
		);
		const w = storedWraps(a, 1).find((x) => x.to === b.id)!;
		const raw = b64uDecode(w.wrap);
		expect(raw.length).toBe(1088 + 32 + 28); // ML-KEM ciphertext || AES-GCM(32-byte key) with IV and tag
		const pid = await rotationPreId(w.rec);
		const aPub = b64uDecode(metaOf(a).get(`ecdh/${a.id}`).pub);
		const bEcdh = (await b.vault.getEcdhIdentity!()).privateKey;
		const bKem = (await b.vault.getKemIdentity!()).secretKey;
		expect(
			await unwrapMeshKey(bEcdh, bKem, aPub, pid, a.id, b.id, w.wrap),
		).toEqual(b.vault.meshKey);
		await expect(
			unwrapMeshKey(
				bEcdh,
				kemKeygen().secretKey,
				aPub,
				pid,
				a.id,
				b.id,
				w.wrap,
			),
		).rejects.toThrow();
		// the ECDH part alone is not a wrap: no ciphertext, no key
		await expect(
			unwrapMeshKey(bEcdh, bKem, aPub, pid, a.id, b.id, raw.subarray(1088)),
		).rejects.toThrow();
		// and a wrap cannot be made for a device without an ML-KEM-768 key
		await expect(
			wrapMeshKey(
				bEcdh,
				aPub,
				new Uint8Array(65),
				pid,
				b.id,
				a.id,
				randomBytes(32),
			),
		).rejects.toThrow(/ML-KEM/);
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("Q8: a member vouching for a malformed ML-KEM key or P-256 point cannot break the owner's re-keying", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const d = await makeDev("devD", hub);
		await pair(a, d);
		const e = await makeDev("devE", hub);
		await pair(a, e);
		const all = [a, b, c, d, e];
		await until(() =>
			all.every((x) => all.every((y) => metaOf(x).has(`ecdh/${y.id}`))),
		);
		await until(() => [a, b, c].every((x) => x.mesh.devices().length === 5));
		// C signs (with its own, valid identity) key-agreement keys that make encapsulation / ECDH import throw
		const vouch = async (pub: string, kem: string) => {
			const sig = b64uEncode(
				await c.vault.sign(ecdhSignedBytes(c.id, pub, kem)),
			);
			metaOf(c).set(`ecdh/${c.id}`, { pub, kem, sig });
			await until(
				() =>
					metaOf(a).get(`ecdh/${c.id}`)?.kem === kem &&
					metaOf(a).get(`ecdh/${c.id}`)?.pub === pub,
			);
		};
		const good = metaOf(c).get(`ecdh/${c.id}`);
		await vouch(good.pub, b64uEncode(new Uint8Array(1184).fill(255))); // wrong modulus
		await a.mesh.revoke(d.id);
		await until(
			() => b.mesh.epoch === 1 && c.mesh.epoch === 1 && e.mesh.epoch === 1,
			8000,
		);
		const bad = new Uint8Array(65);
		bad[0] = 4; // (0, 0) is not on the curve
		await vouch(b64uEncode(bad), good.kem);
		await a.mesh.revoke(e.id);
		await until(() => b.mesh.epoch === 2 && c.mesh.epoch === 2, 8000);
		for (const x of [a, b, c, d, e]) x.mesh.destroy();
	}, 30_000);
});

describe("PQC: rotation records are signed by the owner with ML-DSA-65", () => {
	it("Q9: a member holding the owner's ECDH key (a broken P-256) cannot push a key: unsigned or wrongly signed rotations are rejected", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const all = [a, b, c];
		await until(
			() =>
				all.every((x) => all.every((y) => metaOf(x).has(`ecdh/${y.id}`))) &&
				c.mesh.devices().length === 3,
		);
		const k0 = (b.vault.meshKey as Uint8Array).slice();
		const instance = a.mesh.namespace.split("/")[1] as string;
		const ownerEcdh = (await a.vault.getEcdhIdentity!()).privateKey; // what a quantum adversary would compute
		const cKex = metaOf(a).get(`ecdh/${c.id}`);
		const rejected: string[] = [];
		c.mesh.on("rejected", (e) => rejected.push(e.reason));
		b.mesh.destroy(); // B speaks raw from here on (modified client)
		const forge = async (sign?: (id: string) => Promise<string>) => {
			const rec: Record<string, unknown> = {
				v: 1,
				epoch: 1,
				from: a.id,
				revoked: [],
				to: [c.id],
				n: b64uEncode(randomBytes(16)),
				revs: [],
				wh: "",
			};
			const pid = await rotationPreId(rec as never);
			const wrap = await wrapMeshKey(
				ownerEcdh,
				b64uDecode(cKex.pub),
				b64uDecode(cKex.kem),
				pid,
				a.id,
				c.id,
				randomBytes(32),
			);
			const wraps = { [c.id]: wrap };
			rec.wh = await wrapsHash(wraps);
			if (sign) rec.sig = await sign(await rotationId(rec as never));
			return utf8(JSON.stringify({ rot: rec, to: c.id, wrap, wraps }));
		};
		const t = hub.transport("evil");
		const lks: PeerLink[] = [];
		const peers: Array<Promise<Awaited<ReturnType<typeof rawPeer>>>> = [];
		t.onLink((l) => {
			lks.push(l);
			peers.push(rawPeer(b.vault, k0, 0, l, instance));
		});
		await t.join(await deriveRoomId(k0, "fize", TOPIC, 0, instance), b.id);
		await until(() => lks.some((l) => l.id === c.id));
		const p = await (peers[lks.findIndex((l) => l.id === c.id)] as Promise<
			Awaited<ReturnType<typeof rawPeer>>
		>);
		await until(() => p.isAuthed(), 3000);
		await p.send(3, await forge()); // no signature
		await p.send(
			3,
			await forge(async (id) =>
				b64uEncode(await b.vault.sign(rotationSigBytes(id))),
			),
		); // B's key
		await new Promise((r) => setTimeout(r, 1500));
		expect(c.mesh.epoch).toBe(0);
		expect(c.vault.meshKey).toEqual(a.vault.meshKey);
		expect(
			rejected.filter((r) => r === "rotation signature invalid"),
		).toHaveLength(2);
		// the owner's own rotations still go through
		await a.mesh.revoke(b.id);
		await until(() => c.mesh.epoch === 1);
		for (const x of [a, c]) x.mesh.destroy();
		t.close();
	}, 30_000);
});

describe("a destroyed mesh never touches the vault", () => {
	it("Q10/Q11: destroying the mesh while its re-key is in flight leaves the vault as it was; the owner re-keys when it starts again", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const all = [a, b, c];
		await until(
			() =>
				all.every((x) => all.every((y) => metaOf(x).has(`ecdh/${y.id}`))) &&
				a.mesh.devices().length === 3,
		);
		const k0 = (a.vault.meshKey as Uint8Array).slice();
		const sign = a.vault.sign.bind(a.vault);
		let hit = false;
		// the app tears the mesh down exactly while the owner signs the new rotation (ML-DSA takes ~8 ms)
		a.vault.sign = async (d: Uint8Array) => {
			if (new TextDecoder().decode(d.subarray(0, 17)) === '["swal-rot-sig/v1') {
				hit = true;
				a.mesh.destroy();
			}
			return sign(d);
		};
		await a.mesh.revoke(c.id).catch(() => {});
		await new Promise((r) => setTimeout(r, 300));
		expect(hit).toBe(true);
		expect(a.vault.meshKey).toEqual(k0);
		expect(a.vault.epoch).toBe(0);
		// Q11: the revocation is on record but no re-key happened: the owner executes it when it starts again
		expect(a.mesh.rekeyPending).toBe(true);
		const a2 = await makeDev("devA", hub, undefined, {
			doc: a.doc,
			vault: a.vault,
		});
		await until(() => a2.mesh.epoch === 1 && b.mesh.epoch === 1, 8000);
		expect(b.vault.meshKey).toEqual(a2.vault.meshKey);
		expect(c.vault.meshKey).not.toEqual(a2.vault.meshKey);
		expect(a2.mesh.rekeyPending).toBe(false);
		for (const x of [a2, b, c]) x.mesh.destroy();
	});
});
