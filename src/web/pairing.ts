import type { Admission, TrustRoot } from "./admission.js";
import { hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { hmac } from "./rooms.js";
import type { Device, VaultClient } from "./types.js";
import { b64uDecode, b64uEncode, bs, equalBytes, fromUtf8, randomBytes, utf8 } from "./util.js";

export const PAIR_TTL_MS = 5 * 60_000;
const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

/**
 * QR payload v2. Wire form = base64url(JSON array
 * [2, mid, appId, topic, hostPub, dpk, sig, pairSecret, exp]); ~400 raw bytes.
 * `hostPub`: host ephemeral ECDH P-256 key (raw, 65B). `dpk`: host device identity key
 * (not in MESH.md; needed so `sig` is verifiable). `sig`: vault.sign over every other field.
 */
export interface PairPayload {
	v: 2;
	mid: string;
	appId: string;
	topic: string;
	hostPub: string;
	dpk: string;
	sig: string;
	pairSecret: string;
	exp: number;
}

export interface GrantBody {
	meshKey: string;
	epoch: number;
	mid: string;
	/** Y.encodeStateAsUpdate of the shared doc (base64url) */
	snapshot: string;
	hostDevice?: Device;
	/** Trust anchor the guest pins (the mesh owner), sent over the SAS-authenticated session. */
	root?: TrustRoot;
	/** The guest's own admission followed by its issuer's chain up to (excluding) the root. */
	admissions?: Admission[];
	/** Application data attached by the host for this guest (MeshOptions pairHost({ extra })). */
	extra?: unknown;
}

const signedBytes = (p: Omit<PairPayload, "sig">) =>
	utf8(["swal-pair/v2", p.mid, p.appId, p.topic, p.hostPub, p.dpk, p.pairSecret, p.exp].join("|"));

export function encodePairPayload(p: PairPayload): string {
	return b64uEncode(utf8(JSON.stringify([p.v, p.mid, p.appId, p.topic, p.hostPub, p.dpk, p.sig, p.pairSecret, p.exp])));
}

export function decodePairPayload(s: string): PairPayload {
	let a: unknown;
	try {
		a = JSON.parse(fromUtf8(b64uDecode(s.trim())));
	} catch {
		throw new Error("invalid pairing payload");
	}
	if (!Array.isArray(a) || a.length !== 9 || a[0] !== 2) throw new Error("unsupported pairing payload");
	const [v, mid, appId, topic, hostPub, dpk, sig, pairSecret, exp] = a;
	if (![mid, appId, topic, hostPub, dpk, sig, pairSecret].every((x) => typeof x === "string") || typeof exp !== "number") {
		throw new Error("malformed pairing payload");
	}
	if (b64uDecode(pairSecret).length !== 16) throw new Error("malformed pairing secret");
	return { v, mid, appId, topic, hostPub, dpk, sig, pairSecret, exp };
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
	o: { mid: string; appId: string; topic: string; now: number; ttlMs?: number },
): Promise<PairOfferState> {
	const hostKeys = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
	const pairSecret = randomBytes(16);
	const base = {
		v: 2 as const,
		mid: o.mid,
		appId: o.appId,
		topic: o.topic,
		hostPub: b64uEncode(new Uint8Array(await crypto.subtle.exportKey("raw", hostKeys.publicKey))),
		dpk: b64uEncode(vault.devicePublicKey),
		pairSecret: b64uEncode(pairSecret),
		exp: o.now + (o.ttlMs ?? PAIR_TTL_MS),
	};
	const sig = b64uEncode(await vault.sign(signedBytes(base)));
	const payload: PairPayload = { ...base, sig };
	return { payload, encoded: encodePairPayload(payload), pairSecret, hostKeys };
}

export async function verifyPairPayload(vault: VaultClient, p: PairPayload): Promise<boolean> {
	const { sig, ...rest } = p;
	return vault.verify(b64uDecode(p.dpk), signedBytes(rest), b64uDecode(sig));
}

/**
 * Pairing transcript hash: binds the SAS and the session key to BOTH ephemeral ECDH keys, BOTH nonces
 * (host: pairSecret from the QR; guest: fresh `n` in its hello), the host identity key and the mesh/app/topic.
 */
export async function pairTranscript(p: PairPayload, guestPub: string, guestNonce: string): Promise<Uint8Array> {
	const t = JSON.stringify([
		"swal-pair-transcript/v2",
		p.appId,
		p.topic,
		p.mid,
		p.dpk,
		p.hostPub,
		guestPub,
		p.pairSecret,
		guestNonce,
		p.exp,
	]);
	return new Uint8Array(await crypto.subtle.digest("SHA-256", bs(utf8(t))));
}

/** 6-digit Short Authentication String: HKDF(ECDH shared secret, salt = transcript hash), 40 bits mod 10^6. */
export async function sasCode(shared: Uint8Array, transcript: Uint8Array): Promise<string> {
	const b = await hkdf(shared, "swal-sas/v2", transcript);
	const n = (b[0] * 2 ** 32 + new DataView(b.buffer, b.byteOffset).getUint32(1, false)) % 1_000_000;
	return String(n).padStart(6, "0");
}

async function session(shared: Uint8Array, transcript: Uint8Array) {
	const key = await importAesKey(await hkdf(shared, "swal-pair-session/v2", transcript));
	return { key, sas: await sasCode(shared, transcript) };
}

const helloProof = async (secret: Uint8Array, e: string, n: string) => hmac(await pairMacKey(secret), utf8(`hello/v2|${e}|${n}`));

type Msg =
	| { t: "hello"; e: string; n: string; p: string }
	| { t: "ready" }
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
	private hostOk = false;
	private guestDevice: Omit<Device, "addedAt"> | null = null;
	private send: PairSend | null = null;

	constructor(
		private offer: PairOfferState,
		private hooks: {
			now(): number;
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
		} catch {
			if (this.send === send) this.fail("protocol error");
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
			if (typeof msg.e !== "string" || typeof msg.n !== "string" || b64uDecode(msg.n).length !== 16) throw new Error();
			got = b64uDecode(msg.p);
		} catch {
			return send({ t: "err", e: "bad proof" });
		}
		const expect = await helloProof(secret, msg.e, msg.n);
		if (!equalBytes(expect, got)) return send({ t: "err", e: "bad proof" });
		if (this.burned) return send({ t: "err", e: "used" }); // re-check: another hello may have won during the awaits above
		this.burned = true; // single use, enforced by the host (no await between check and set)
		this.send = send;
		const guestPub = await crypto.subtle.importKey("raw", bs(b64uDecode(msg.e)), ECDH, false, []);
		const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: guestPub }, this.offer.hostKeys.privateKey, 256));
		this.sess = await session(shared, await pairTranscript(this.offer.payload, msg.e, msg.n));
		send({ t: "ready" });
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
		if (!this.sess) return;
		const body = parse<{ deviceId: string; pub: string; name: string }>(
			await openUpdate(this.sess.key, b64uDecode(msg.ct), "swal-pair/ack"),
		);
		if (typeof body.deviceId !== "string" || typeof body.pub !== "string") throw new Error("bad ack");
		this.guestDevice = { deviceId: body.deviceId, pub: body.pub, name: String(body.name ?? "") };
		await this.tryGrant();
	}

	private async tryGrant() {
		if (!this.hostOk || !this.guestDevice || !this.sess || !this.send || this.done) return;
		this.done = true;
		let grant: GrantBody;
		try {
			grant = await this.hooks.buildGrant(this.guestDevice);
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
	private ePub = "";
	private nonce = "";
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
		if (!(await verifyPairPayload(vault, payload))) throw new Error("pairing payload signature invalid");
		const g = new GuestPairing(payload, vault, hooks);
		const eph = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
		g.ePub = b64uEncode(new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey)));
		g.nonce = b64uEncode(randomBytes(16));
		const secret = b64uDecode(payload.pairSecret);
		const hostPub = await crypto.subtle.importKey("raw", bs(b64uDecode(payload.hostPub)), ECDH, false, []);
		const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: hostPub }, eph.privateKey, 256));
		g.sess = await session(shared, await pairTranscript(payload, g.ePub, g.nonce));
		g.proof = b64uEncode(await helloProof(secret, g.ePub, g.nonce));
		return g;
	}

	/** Called for every new link in the pairing room; says hello over it. */
	attach(send: PairSend) {
		if (this.settled) return;
		send({ t: "hello", e: this.ePub, n: this.nonce, p: this.proof });
		this.sent.add(send);
	}

	fail(e: Error) {
		if (this.settled) return;
		this.settled = true;
		this.reject(e);
	}

	async handle(msg: Msg, send: PairSend): Promise<void> {
		if (this.settled || !this.sess) return;
		try {
			if (msg.t === "err") return this.fail(new Error(`host refused pairing: ${msg.e}`));
			if (msg.t === "abort") return this.fail(new Error("host rejected the SAS"));
			if (msg.t === "ready" && !this.active) {
				this.active = send;
				const ok = await this.hooks.onSas(this.sess.sas);
				if (!ok) {
					send({ t: "abort" });
					return this.fail(new Error("SAS rejected by user"));
				}
				const ct = b64uEncode(
					await sealUpdate(
						this.sess.key,
						json({ deviceId: this.vault.deviceId, pub: b64uEncode(this.vault.devicePublicKey), name: this.hooks.name }),
						"swal-pair/ack",
					),
				);
				send({ t: "ack", ct });
			} else if (msg.t === "grant" && this.active === send) {
				const g = parse<GrantBody>(await openUpdate(this.sess.key, b64uDecode(msg.ct), "swal-pair/grant"));
				this.settled = true;
				this.resolve(g);
			}
		} catch (e) {
			this.fail(e instanceof Error ? e : new Error(String(e)));
		}
	}
}

