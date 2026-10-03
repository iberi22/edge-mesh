import { type Admission, idMatchesPub, type TrustRoot } from "./admission.js";
import { hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { hybridSecret, identityVerify, kemDecapsulate, kemEncapsulate, kemKeygen } from "./pq.js";
import { hmac } from "./rooms.js";
import type { Device, VaultClient } from "./types.js";
import { b64uDecode, b64uEncode, bs, concat, equalBytes, fromUtf8, randomBytes, utf8 } from "./util.js";

export const PAIR_TTL_MS = 5 * 60_000;
const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

/**
 * QR payload v4. Wire form = base64url(JSON array [4, mid, appId, topic, hostPub, hostId, pairSecret, exp, root]);
 * ~300 raw bytes (an ML-DSA-65 key and signature, ~7 KB in base64url, would not fit a scannable QR).
 * `hostPub`: host ephemeral ECDH P-256 key (raw, 65B). `hostId`: deviceId (= fingerprint of the ML-DSA-65 identity
 * key) of the host; the host proves that identity inside the SAS-authenticated session (`GrantBody.hostProof`, a
 * signature over the transcript). `root`: deviceId of the mesh owner (S6). The QR itself is the out-of-band channel.
 */
export interface PairPayload {
	v: 4;
	mid: string;
	root: string;
	appId: string;
	topic: string;
	hostPub: string;
	hostId: string;
	pairSecret: string;
	exp: number;
}

export interface GrantBody {
	meshKey: string;
	epoch: number;
	mid: string;
	hostDevice?: Device;
	/** The host's ML-DSA-65 identity key and its signature over the pairing transcript (`hostProofBytes`). */
	hostProof?: { pub: string; sig: string };
	/** Trust anchor the guest pins (the mesh owner), sent over the SAS-authenticated session. */
	root?: TrustRoot;
	/** The guest's own admission followed by its issuer's chain up to (excluding) the root. */
	admissions?: Admission[];
	/** The rotation that produced `meshKey` (B4: concurrent rotations are resolved by its id). */
	rot?: unknown;
	/** Application data attached by the host for this guest (MeshOptions pairHost({ extra })). */
	extra?: unknown;
}

export function encodePairPayload(p: PairPayload): string {
	return b64uEncode(utf8(JSON.stringify([p.v, p.mid, p.appId, p.topic, p.hostPub, p.hostId, p.pairSecret, p.exp, p.root])));
}

export function decodePairPayload(s: string): PairPayload {
	let a: unknown;
	try {
		a = JSON.parse(fromUtf8(b64uDecode(s.trim())));
	} catch {
		throw new Error("invalid pairing payload");
	}
	if (!Array.isArray(a) || a.length !== 9 || a[0] !== 4) throw new Error("unsupported pairing payload");
	const [v, mid, appId, topic, hostPub, hostId, pairSecret, exp, root] = a;
	if (![mid, appId, topic, hostPub, hostId, pairSecret, root].every((x) => typeof x === "string") || typeof exp !== "number") {
		throw new Error("malformed pairing payload");
	}
	if (b64uDecode(pairSecret).length !== 16) throw new Error("malformed pairing secret");
	return { v, mid, root, appId, topic, hostPub, hostId, pairSecret, exp };
}

export async function derivePairKey(pairSecret: Uint8Array): Promise<CryptoKey> {
	return importAesKey(await hkdf(pairSecret, "swal-pair/v1"));
}

async function pairMacKey(pairSecret: Uint8Array): Promise<Uint8Array> {
	return hkdf(pairSecret, "swal-pair-proof/v1");
}

export interface PairOfferState {
	payload: PairPayload;
	encoded: string;
	pairSecret: Uint8Array;
	hostKeys: CryptoKeyPair;
}

export async function createPairOffer(
	vault: VaultClient,
	o: { mid: string; root: string; appId: string; topic: string; now: number; ttlMs?: number },
): Promise<PairOfferState> {
	const hostKeys = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
	const pairSecret = randomBytes(16);
	const payload: PairPayload = {
		v: 4,
		mid: o.mid,
		root: o.root,
		appId: o.appId,
		topic: o.topic,
		hostPub: b64uEncode(new Uint8Array(await crypto.subtle.exportKey("raw", hostKeys.publicKey))),
		hostId: vault.deviceId,
		pairSecret: b64uEncode(pairSecret),
		exp: o.now + (o.ttlMs ?? PAIR_TTL_MS),
	};
	return { payload, encoded: encodePairPayload(payload), pairSecret, hostKeys };
}

/** What the host signs with its identity key: the transcript, its id and key (inside the encrypted grant). */
export const hostProofBytes = (transcript: Uint8Array, hostId: string, pub: string) =>
	utf8(JSON.stringify(["swal-pair-host/v1", b64uEncode(transcript), hostId, pub]));

/** Guest-side check of the host's identity proof: hostId (from the QR) = fingerprint(pub) and a valid ML-DSA-65 signature. */
export async function verifyHostProof(p: PairPayload, transcript: Uint8Array, proof: unknown): Promise<boolean> {
	const h = proof as { pub?: unknown; sig?: unknown } | null;
	if (!h || typeof h.pub !== "string" || typeof h.sig !== "string") return false;
	if (!(await idMatchesPub(p.hostId, h.pub))) return false;
	try {
		return identityVerify(b64uDecode(h.pub), hostProofBytes(transcript, p.hostId, h.pub), b64uDecode(h.sig));
	} catch {
		return false;
	}
}

/**
 * Pairing transcript hash: binds the SAS and the session key to BOTH ephemeral ECDH keys, the guest's ephemeral
 * ML-KEM-768 encapsulation key and the host's ciphertext to it, BOTH nonces (host: pairSecret from the QR; guest:
 * fresh `n` in its hello), the host identity (its id) and the mesh/app/topic.
 */
export async function pairTranscript(
	p: PairPayload,
	guestPub: string,
	guestNonce: string,
	guestKem: string,
	kemCt: string,
): Promise<Uint8Array> {
	const t = JSON.stringify([
		"swal-pair-transcript/v5",
		p.appId,
		p.topic,
		p.mid,
		p.root,
		p.hostId,
		p.hostPub,
		guestPub,
		p.pairSecret,
		guestNonce,
		guestKem,
		kemCt,
		p.exp,
	]);
	return new Uint8Array(await crypto.subtle.digest("SHA-256", bs(utf8(t))));
}

/**
 * 6-digit Short Authentication String: HKDF(ikm = ML-KEM secret || ECDH secret, salt = transcript hash), 40 bits
 * mod 10^6. A man in the middle must replace the ECDH key or the KEM ciphertext, which changes the code.
 */
export async function sasCode(shared: Uint8Array, transcript: Uint8Array): Promise<string> {
	const b = await hkdf(shared, "swal-sas/v3", transcript);
	const n = (b[0] * 2 ** 32 + new DataView(b.buffer, b.byteOffset).getUint32(1, false)) % 1_000_000;
	return String(n).padStart(6, "0");
}

/** Hybrid session (AGENTS.md §2): HKDF-SHA-256(ML-KEM-768 secret || ECDH P-256 secret, salt = transcript). */
async function session(kemSecret: Uint8Array, ecdhSecret: Uint8Array, transcript: Uint8Array) {
	const key = await importAesKey(await hybridSecret(kemSecret, ecdhSecret, "swal-pair-session/v3", transcript));
	return { key, sas: await sasCode(concat(kemSecret, ecdhSecret), transcript) };
}

/**
 * What the guest signs with its IDENTITY key inside the ack: proof of possession of the key it asks to be admitted
 * with, bound to this pairing session (transcript) so it cannot be replayed into another one.
 */
export const ackSignedBytes = (transcript: Uint8Array, deviceId: string, pub: string, name: string) =>
	utf8(JSON.stringify(["swal-pair-ack/v1", b64uEncode(transcript), deviceId, pub, name]));

export interface PairAck {
	deviceId: string;
	pub: string;
	name: string;
	sig: string;
}

/** Host-side check of a guest ack: deviceId = fingerprint(pub) and a valid signature by that key over the transcript. */
export async function verifyPairAck(
	verify: (pub: Uint8Array, data: Uint8Array, sig: Uint8Array) => boolean | Promise<boolean>,
	transcript: Uint8Array,
	a: Partial<PairAck>,
): Promise<string | null> {
	if (typeof a.deviceId !== "string" || typeof a.pub !== "string" || typeof a.sig !== "string") return "malformed ack";
	if (!(await idMatchesPub(a.deviceId, a.pub))) return "deviceId is not the fingerprint of the guest key";
	const name = typeof a.name === "string" ? a.name : "";
	try {
		if (await verify(b64uDecode(a.pub), ackSignedBytes(transcript, a.deviceId, a.pub, name), b64uDecode(a.sig))) return null;
	} catch {}
	return "guest did not prove possession of its identity key";
}

const helloProof = async (secret: Uint8Array, e: string, n: string, k: string) =>
	hmac(await pairMacKey(secret), utf8(`hello/v3|${e}|${n}|${k}`));

type Msg =
	/** e: guest ephemeral ECDH key, n: guest nonce, k: guest ephemeral ML-KEM-768 encapsulation key, p: proof */
	| { t: "hello"; e: string; n: string; k: string; p: string }
	/** c: host's ML-KEM-768 ciphertext to `k` */
	| { t: "ready"; c: string }
	| { t: "ack"; ct: string }
	| { t: "grant"; ct: string }
	| { t: "abort" }
	| { t: "err"; e: string };

export type PairSend = (m: Msg) => void;

export interface SasPrompt {
	code: string;
	confirm(): void;
	reject(): void;
}

const json = (o: unknown) => utf8(JSON.stringify(o));
const parse = <T>(b: Uint8Array) => JSON.parse(fromUtf8(b)) as T;

/** Host side. One instance per offer. pairSecret is single-use: burned by the first valid hello. */
export class HostPairing {
	private burned = false;
	private done = false;
	private sess: { key: CryptoKey; sas: string } | null = null;
	private transcript: Uint8Array | null = null;
	private hostOk = false;
	private guestDevice: Omit<Device, "addedAt"> | null = null;
	private send: PairSend | null = null;

	constructor(
		private offer: PairOfferState,
		private hooks: {
			now(): number;
			/** identity-signature check (the host vault's verify) for the guest's proof of possession */
			verify(pub: Uint8Array, data: Uint8Array, sig: Uint8Array): boolean | Promise<boolean>;
			/** the host's identity proof over the transcript (see `hostProofBytes`) */
			prove(transcript: Uint8Array): Promise<{ pub: string; sig: string }>;
			onSas(p: SasPrompt): void;
			buildGrant(guest: Omit<Device, "addedAt">): Promise<GrantBody>;
			onPaired(d: Device): void;
			onFail(reason: string): void;
		},
	) {}

	get expired() {
		return this.hooks.now() > this.offer.payload.exp;
	}
	get finished() {
		return this.done;
	}

	cancel() {
		this.done = true;
	}

	async handle(msg: Msg, send: PairSend): Promise<void> {
		if (this.done) return send({ t: "err", e: "closed" });
		try {
			if (msg.t === "hello") return await this.onHello(msg, send);
			if (this.send !== send) return; // only the link that burned the secret may continue
			if (msg.t === "ack") return await this.onAck(msg);
			if (msg.t === "abort") return this.fail("guest rejected SAS");
		} catch (e) {
			if (this.send !== send) return;
			send({ t: "err", e: "refused" });
			this.fail(e instanceof Error ? e.message : "protocol error");
		}
	}

	private fail(reason: string) {
		this.done = true;
		this.hooks.onFail(reason);
	}

	private async onHello(msg: Extract<Msg, { t: "hello" }>, send: PairSend) {
		if (this.expired) return send({ t: "err", e: "expired" });
		if (this.burned) return send({ t: "err", e: "used" });
		const secret = this.offer.pairSecret;
		let got: Uint8Array;
		try {
			if (typeof msg.e !== "string" || typeof msg.n !== "string" || typeof msg.k !== "string" || b64uDecode(msg.n).length !== 16)
				throw new Error();
			got = b64uDecode(msg.p);
		} catch {
			return send({ t: "err", e: "bad proof" });
		}
		const expect = await helloProof(secret, msg.e, msg.n, msg.k);
		if (!equalBytes(expect, got)) return send({ t: "err", e: "bad proof" });
		if (this.burned) return send({ t: "err", e: "used" }); // re-check: another hello may have won during the awaits above
		this.burned = true; // single use, enforced by the host (no await between check and set)
		this.send = send;
		const guestPub = await crypto.subtle.importKey("raw", bs(b64uDecode(msg.e)), ECDH, false, []);
		const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: guestPub }, this.offer.hostKeys.privateKey, 256));
		const kem = kemEncapsulate(b64uDecode(msg.k)); // throws on a malformed key: the hello is refused
		const c = b64uEncode(kem.cipherText);
		this.transcript = await pairTranscript(this.offer.payload, msg.e, msg.n, msg.k, c);
		this.sess = await session(kem.sharedSecret, shared, this.transcript);
		send({ t: "ready", c });
		this.hooks.onSas({
			code: this.sess.sas,
			confirm: () => {
				this.hostOk = true;
				void this.tryGrant();
			},
			reject: () => {
				send({ t: "abort" });
				this.fail("host rejected SAS");
			},
		});
	}

	private async onAck(msg: Extract<Msg, { t: "ack" }>) {
		if (!this.sess || !this.transcript || this.guestDevice) return;
		const body = parse<Partial<PairAck>>(await openUpdate(this.sess.key, b64uDecode(msg.ct), "swal-pair/ack"));
		const bad = await verifyPairAck(this.hooks.verify, this.transcript, body ?? {});
		if (bad || typeof body.deviceId !== "string" || typeof body.pub !== "string") throw new Error(bad ?? "malformed ack");
		this.guestDevice = { deviceId: body.deviceId, pub: body.pub, name: typeof body.name === "string" ? body.name : "" };
		await this.tryGrant();
	}

	private async tryGrant() {
		if (!this.hostOk || !this.guestDevice || !this.sess || !this.send || this.done) return;
		this.done = true;
		let grant: GrantBody;
		try {
			grant = await this.hooks.buildGrant(this.guestDevice);
			grant.hostProof = await this.hooks.prove(this.transcript as Uint8Array);
		} catch (e) {
			this.send({ t: "err", e: "refused" });
			this.hooks.onFail(`grant refused: ${e instanceof Error ? e.message : String(e)}`);
			return;
		}
		const ct = b64uEncode(await sealUpdate(this.sess.key, json(grant), "swal-pair/grant"));
		this.send({ t: "grant", ct });
		this.hooks.onPaired({ ...this.guestDevice, addedAt: this.hooks.now() });
	}
}

/** Guest side. */
export class GuestPairing {
	private sess: { key: CryptoKey; sas: string } | null = null;
	private transcript: Uint8Array = new Uint8Array(0);
	private ePub = "";
	private nonce = "";
	private kemPub = "";
	private kemSecret: Uint8Array = new Uint8Array(0);
	private ecdhSecret: Uint8Array = new Uint8Array(0);
	private proof = "";
	private sent = new WeakSet<object>();
	private settled = false;
	readonly result: Promise<GrantBody>;
	private resolve!: (g: GrantBody) => void;
	private reject!: (e: Error) => void;
	private active: PairSend | null = null;

	private constructor(
		readonly payload: PairPayload,
		private vault: VaultClient,
		private hooks: { name: string; onSas(code: string): Promise<boolean> },
	) {
		this.result = new Promise((res, rej) => {
			this.resolve = res;
			this.reject = rej;
		});
		this.result.catch(() => {});
	}

	static async create(
		payload: PairPayload,
		vault: VaultClient,
		hooks: { name: string; onSas(code: string): Promise<boolean>; now: number },
	): Promise<GuestPairing> {
		if (hooks.now > payload.exp) throw new Error("pairing code expired");
		const g = new GuestPairing(payload, vault, hooks);
		const eph = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
		g.ePub = b64uEncode(new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey)));
		g.nonce = b64uEncode(randomBytes(16));
		const kem = kemKeygen(); // ephemeral: one pairing only
		g.kemPub = b64uEncode(kem.publicKey);
		g.kemSecret = kem.secretKey;
		const secret = b64uDecode(payload.pairSecret);
		const hostPub = await crypto.subtle.importKey("raw", bs(b64uDecode(payload.hostPub)), ECDH, false, []);
		g.ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: hostPub }, eph.privateKey, 256));
		g.proof = b64uEncode(await helloProof(secret, g.ePub, g.nonce, g.kemPub));
		return g;
	}

	/** Called for every new link in the pairing room; says hello over it. */
	attach(send: PairSend) {
		if (this.settled) return;
		send({ t: "hello", e: this.ePub, n: this.nonce, k: this.kemPub, p: this.proof });
		this.sent.add(send);
	}

	fail(e: Error) {
		if (this.settled) return;
		this.settled = true;
		this.reject(e);
	}

	async handle(msg: Msg, send: PairSend): Promise<void> {
		if (this.settled) return;
		try {
			if (msg.t === "err") return this.fail(new Error(`host refused pairing: ${msg.e}`));
			if (msg.t === "abort") return this.fail(new Error("host rejected the SAS"));
			if (msg.t === "ready" && !this.active) {
				if (typeof msg.c !== "string") throw new Error("pairing: the host sent no ML-KEM ciphertext");
				this.active = send;
				// hybrid session: a substituted ciphertext (or ECDH key) yields another SAS, caught by the user
				const kemSecret = kemDecapsulate(b64uDecode(msg.c), this.kemSecret);
				this.transcript = await pairTranscript(this.payload, this.ePub, this.nonce, this.kemPub, msg.c);
				this.sess = await session(kemSecret, this.ecdhSecret, this.transcript);
				const ok = await this.hooks.onSas(this.sess.sas);
				if (!ok) {
					send({ t: "abort" });
					return this.fail(new Error("SAS rejected by user"));
				}
				const deviceId = this.vault.deviceId;
				const pub = b64uEncode(this.vault.devicePublicKey);
				const name = this.hooks.name;
				const sig = b64uEncode(await this.vault.sign(ackSignedBytes(this.transcript, deviceId, pub, name)));
				const ack: PairAck = { deviceId, pub, name, sig };
				if (!this.sess) return;
				const ct = b64uEncode(await sealUpdate(this.sess.key, json(ack), "swal-pair/ack"));
				send({ t: "ack", ct });
			} else if (msg.t === "grant" && this.active === send && this.sess) {
				const g = parse<GrantBody>(await openUpdate(this.sess.key, b64uDecode(msg.ct), "swal-pair/grant"));
				// the host proves, inside the SAS-authenticated session, that it holds the identity the QR names
				if (!(await verifyHostProof(this.payload, this.transcript, g.hostProof)))
					throw new Error("pairing grant: the host did not prove the identity named by the pairing code");
				this.settled = true;
				this.resolve(g);
			}
		} catch (e) {
			this.fail(e instanceof Error ? e : new Error(String(e)));
		}
	}
}

