// Security state of a mesh (round 5): an append-only, content-addressed set of self-verifying signed documents,
// kept in each device's local store and exchanged over the authenticated trust channel. Nothing of it lives in the
// shared Y.Doc: members can only ADD documents (there are no slots to squat, overwrite or delete).
//
// Documents
// - web/trust grants and revocations: membership and authority. The mesh root (owner) is the trust root; a grant
//   with `delegate >= 1` makes an admin, any other grant a member. A revocation is effective only when issued by the
//   root or by a strict ancestor of the revoked grant (an admin revokes the devices it admitted) and always cascades.
// - key-agreement records (`kex`): a device's P-256 + ML-KEM-768 public keys, signed by its own identity key.
// - owner rotations (`rot`, see rotation.ts): signed by the root; their `cut` lists are authoritative (executed).
//
// Determinism: what a device concludes is a function of the documents it holds, whatever their arrival order.
import { isDeviceId, isEpoch, type Role, type TrustRoot } from "./admission.js";
import {
	identityVerify,
	kemEncapsulate,
	ML_KEM_PUBLIC_KEY_BYTES,
} from "./pq.js";
import {
	isEcdhPublicKey,
	isRotDoc,
	type RotDoc,
	rotationId,
	rotationSigBytes,
	wrapsHash,
} from "./rotation.js";
import type { MeshStore } from "./store.js";
import { canonicalBytes, contentId, sha256B64u } from "./trust/canonical.js";
import { checkIntegrity, issueGrant, issueRevocation } from "./trust/docs.js";
import {
	isPublicKey,
	isSignature,
	SIG_ALG,
	type Signer,
	signCanonical,
	verifyCanonical,
} from "./trust/keys.js";
import { createTrustStore, type TrustStore } from "./trust/store.js";
import type { Grant, Revocation, TrustSchema } from "./trust/types.js";
import { b64uDecode } from "./util.js";

/** Module every mesh grant names (apps may add their own modules to the schema). */
export const MESH_MODULE = "mesh";
export const MESH_SCHEMA: TrustSchema = {
	modules: [MESH_MODULE],
	roles: {
		admin: { permissions: { [MESH_MODULE]: "administrar" }, delegate: 1 },
		member: { permissions: { [MESH_MODULE]: "editar" }, delegate: 0 },
	},
	maxDepth: 2,
};

/** A device's key-agreement keys (rotation wraps), signed by the device's own ML-DSA-65 identity key. */
export interface KexDoc {
	t: "kex";
	v: 1;
	inst: string;
	dev: string;
	/** raw P-256 public key, base64url */
	ecdh: string;
	/** ML-KEM-768 encapsulation key, base64url */
	kem: string;
	/** the device's own counter: the highest one wins (a device that changes its keys publishes n + 1) */
	n: number;
	sig: string;
}
export type SecDoc = Grant | Revocation | KexDoc | RotDoc;
export interface AddOutcome {
	status: "accepted" | "duplicate" | "pending" | "rejected";
	id?: string;
	reason?: string;
}

/** Members an admin's grants can make (its lowest grant ids count; R5-S3: an admin cannot flood the recipient list). */
export const MAX_MEMBERS_PER_ADMIN = 256;
/** Grants of one non-root issuer kept at all (beyond: the cap-N smallest ids are kept, see `applyCap`). */
export const MAX_STORED_PER_ISSUER = 4 * MAX_MEMBERS_PER_ADMIN;
/** Revocations of one target grant by one issuer kept (beyond: the cap-N smallest ids are kept, see `applyCap`). */
export const MAX_REVS_PER_ISSUER_TARGET = 4;
/** Recent owner rotations kept in full (with their wraps) to serve stragglers; their cuts are kept for good. */
export const MAX_ROTATIONS_KEPT = 32;
const MAX_DEFERRED = 512;
/** R6-S5: a count alone does not bound memory: one deferred document may carry a large `upTo`/wrap list. */
export const MAX_DOC_BYTES = 512 * 1024;
/** R6-S5: total bytes held by deferred documents (the auditor measured 126 MiB from 64 deferred revocations). */
export const MAX_DEFERRED_BYTES = 8 * 1024 * 1024;
const MAX_REMEMBERED = 8192;

/**
 * R6-S2: refusals that are a property of THIS device's context, not of the document, so they are not permanent failures
 * and are not remembered as `bad`. `pending overflow` is the waiting set of the trust store being full: in the auditor's
 * proof a REAL grant is turned away that way, so its key must stay in `missing()` and whichever peer offers it again
 * must be served — no sender can keep a genuine document out by filling the room first.
 *
 * R6-S2b adds the per-SENDER room: the same refusal, counted on the peer that sent the documents instead of on the
 * issuers they name, since an attacker signs its junk with fresh random keys and so holds one waiting slot per issuer.
 */
const CONTEXTUAL_REFUSALS: ReadonlySet<string | undefined> = new Set([
	"pending overflow",
	"sender pending overflow",
	"deferred-overflow",
	"issuer over its cap",
]);

/** Bounded set that forgets the least recently used entry. */
class LruSet {
	private m = new Map<string, true>();
	constructor(private readonly cap: number) {}
	has(k: string) {
		if (!this.m.has(k)) return false;
		this.m.delete(k);
		this.m.set(k, true);
		return true;
	}
	add(k: string) {
		this.m.delete(k);
		this.m.set(k, true);
		if (this.m.size > this.cap)
			this.m.delete(this.m.keys().next().value as string);
	}
	values() {
		return [...this.m.keys()];
	}
	clear() {
		this.m.clear();
	}
}

const kexBody = (k: KexDoc) => ({
	t: k.t,
	v: k.v,
	inst: k.inst,
	dev: k.dev,
	ecdh: k.ecdh,
	kem: k.kem,
	n: k.n,
});

function isKexShape(x: unknown): x is KexDoc {
	const k = x as KexDoc;
	return (
		typeof k === "object" &&
		k !== null &&
		k.t === "kex" &&
		k.v === 1 &&
		typeof k.inst === "string" &&
		isDeviceId(k.dev) &&
		typeof k.ecdh === "string" &&
		k.ecdh.length <= 128 &&
		typeof k.kem === "string" &&
		k.kem.length <= 2048 &&
		Number.isSafeInteger(k.n) &&
		k.n >= 0 &&
		isSignature(k.sig)
	);
}

/** Inventory id of a document: kind prefix + content id (rotation id for rotations). */
async function docKey(x: SecDoc): Promise<string> {
	if (x.t === "grant") return `g:${x.id}`;
	if (x.t === "revoke") return `r:${x.id}`;
	if (x.t === "kex") return `k:${await contentId(kexBody(x))}`;
	return `R:${await rotationId(x)}`;
}

export interface MemberInfo {
	deviceId: string;
	pub: string;
	role: Exclude<Role, "owner">;
	grant: Grant;
}

export class SecurityState {
	readonly trust: TrustStore;
	readonly root: TrustRoot;
	private readonly store: MeshStore;
	private readonly now: () => number;
	private readonly kex = new Map<string, KexDoc & { key: string }>();
	private readonly rots = new Map<string, RotDoc & { id: string }>();
	private readonly cuts = new Set<string>();
	/** inventory: keys of every document held */
	private readonly have = new Set<string>();
	/** keys of documents dropped for good (superseded key records, pruned rotations): never asked for again */
	private readonly gone: LruSet;
	/** hashes of whole documents that failed verification (a forged copy never blocks the genuine one) */
	private readonly bad = new LruSet(4096);
	/** R6-B1: documents waiting for their parent/target, by the hash of the WHOLE document (never by the id it claims) */
	private readonly deferred = new Map<string, SecDoc>();
	/** R6-S2b: who sent each parked document, so the retry charges that sender's waiting slots and not the parent's. */
	private readonly deferredFrom = new Map<string, string>();
	/** R6-S5: bytes held by `deferred` (kept exact: every set and every drop goes through defer/unpark) */
	private deferredBytesHeld = 0;
	private readonly listeners = new Set<() => void>();
	private queue: Promise<unknown> = Promise.resolve();
	private capIndex: Map<string, Set<string>> | null = null;
	version = 0;

	private constructor(
		trust: TrustStore,
		root: TrustRoot,
		store: MeshStore,
		now: () => number,
	) {
		this.trust = trust;
		this.root = root;
		this.store = store;
		this.now = now;
		this.gone = new LruSet(MAX_REMEMBERED);
		trust.onChange(() => {
			this.capIndex = null;
		});
	}

	static async open(o: {
		root: TrustRoot;
		store: MeshStore;
		schema?: TrustSchema;
		now?: () => number;
	}): Promise<SecurityState> {
		const now = o.now ?? Date.now;
		const trust = await createTrustStore({
			inst: o.root.mid,
			root: o.root.pub,
			rootFingerprint: o.root.deviceId,
			schema: o.schema ?? MESH_SCHEMA,
			now,
			maxPending: 256,
		});
		const s = new SecurityState(trust, o.root, o.store, now);
		await s.load();
		return s;
	}

	get inst() {
		return this.root.mid;
	}

	onChange(cb: () => void): () => void {
		this.listeners.add(cb);
		return () => this.listeners.delete(cb);
	}

	// ─── ingest ──────────────────────────────────────────────────────────────

/**
	 * Add documents (any order, any source). Serialized; listeners fire once when anything was accepted.
	 * `opts.from` (R6-S2b) is the transport-level id of the peer that sent them: the trust store charges the waiting
	 * slots they park to that sender, so one peer cannot take the whole waiting set by signing with fresh random keys.
	 * Leave it undefined for local/own documents (a pair's own, ours, restored from storage): no sender is charged.
	 */
	addMany(
		xs: readonly unknown[],
		opts?: { from?: string },
	): Promise<AddOutcome[]> {
		const run = this.queue.then(async () => {
			const before = this.version;
			const out: AddOutcome[] = [];
			for (const x of xs) out.push(await this.ingest(x, opts?.from));
			if (this.version !== before) {
				await this.retryDeferred();
				this.scheduleSave();
				for (const cb of [...this.listeners]) {
					try {
						cb();
					} catch {}
				}
			}
			return out;
		});
		this.queue = run.catch(() => undefined);
		return run;
	}

	add(x: unknown): Promise<AddOutcome> {
		return this.addMany([x]).then((r) => r[0] as AddOutcome);
	}

	private async ingest(
		x: unknown,
		from?: string,
		retry = false,
	): Promise<AddOutcome> {
		const t = (x as { t?: unknown } | null)?.t;
		if (t !== "grant" && t !== "revoke" && t !== "kex" && t !== "rot")
			return { status: "rejected", reason: "unknown document" };
		const doc = x as SecDoc;
		if ((doc as { inst?: unknown }).inst !== this.inst)
			return { status: "rejected", reason: "other mesh" };
		// R5-B3: one encoding per signature; ids are content ids, so a copy with another encoding is not "another" doc
		if (!isSignature((doc as { sig?: unknown }).sig))
			return { status: "rejected", reason: "non-canonical signature" };
		let key: string;
		try {
			key = await docKey(doc);
		} catch {
			return { status: "rejected", reason: "malformed" };
		}
		if (this.have.has(key)) return { status: "duplicate", id: key };
		if (this.gone.has(key))
			return { status: "duplicate", id: key, reason: "superseded" };
		const bytes = canonicalBytes(doc);
		// R6-S5: bounded before any crypto, so an oversize document costs nothing and is never parked
		if (bytes.length > MAX_DOC_BYTES)
			return { status: "rejected", id: key, reason: "oversize document" };
		const whole = await sha256B64u(bytes);
		if (this.bad.has(whole))
			return { status: "rejected", id: key, reason: "known bad" };
		let r: AddOutcome;
		if (doc.t === "grant" || doc.t === "revoke")
			r = await this.ingestTrust(doc, key, from);
		else if (doc.t === "kex") r = await this.ingestKex(doc, key);
		else r = await this.ingestRot(doc, key);
		// R6-S2: a context-dependent refusal (the waiting set was full) is NOT a property of the document: it is not
		// remembered as bad, so the id stays in `missing()` and the peer that offers it again is served
		if (r.status === "rejected" && !CONTEXTUAL_REFUSALS.has(r.reason))
			this.bad.add(whole);
		if (r.status === "pending" && !retry) {
			// R6-B1: nothing is parked before the id is shown to be the content address of these very bytes. A forged
			// copy carrying the id of a genuine document (of somebody else) used to be parked under that id and, since a
			// parked id was never asked for again, it withheld the genuine one for good: the owner never re-keyed and the
			// revoked member kept the key. The forgery is refused (a failure for its sender) instead of parked.
			if (doc.t === "grant" || doc.t === "revoke") {
				const why = await checkIntegrity(doc);
				if (why) {
					this.bad.add(whole);
					return { status: "rejected", id: key, reason: why };
				}
			}
			// R6-S5: parking is bounded by bytes; a document that does not fit is dropped and counts as a failure
			// (it is not remembered as bad: the genuine one is still asked for)
			const why = this.defer(whole, doc, bytes.length, from);
			if (why) return { status: "rejected", id: key, reason: why };
		}
		return r;
	}

	/**
	 * Park a document until its parent/target arrives. Returns a reason if it was dropped instead.
	 * R6-B1: keyed by the hash of the WHOLE document received, never by the id it claims, so a forged copy parked under
	 * somebody else's id can neither shadow the genuine one nor take its key out of `missing()`.
	 * R6-S2b: remembers which peer sent it, so the retry charges that sender's waiting slots and not the parent's.
	 */
	private defer(
		whole: string,
		doc: SecDoc,
		bytes: number,
		from?: string,
	): string | undefined {
		if (this.deferred.has(whole)) return undefined;
		if (this.deferredBytesHeld + bytes > MAX_DEFERRED_BYTES)
			return "deferred budget exhausted";
		if (this.deferred.size >= MAX_DEFERRED)
			this.unpark(this.deferred.keys().next().value as string);
		this.deferred.set(whole, doc);
		if (from !== undefined) this.deferredFrom.set(whole, from);
		this.deferredBytesHeld += bytes;
		return undefined;
	}

	/** Drop a parked document and give its bytes back. */
	private unpark(whole: string) {
		const doc = this.deferred.get(whole);
		if (!doc) return;
		this.deferred.delete(whole);
		this.deferredFrom.delete(whole);
		this.deferredBytesHeld -= canonicalBytes(doc).length;
	}

	/** Bytes held by parked documents (R6-S5 accounting). */
	deferredBytes(): number {
		return this.deferredBytesHeld;
	}

	private async retryDeferred() {
		for (let pass = 0; pass < 3 && this.deferred.size; pass++) {
			let progress = false;
			for (const [whole, d] of [...this.deferred]) {
				// R6-S2b: retried under the sender that sent it, so its waiting slots go back where they came from
				const r = await this.ingest(d, this.deferredFrom.get(whole), true);
				if (r.status !== "pending") {
					this.unpark(whole);
					progress ||= r.status === "accepted";
				}
			}
			if (!progress) break;
		}
	}

	private async ingestTrust(
		doc: Grant | Revocation,
		key: string,
		from?: string,
	): Promise<AddOutcome> {
		// a grant needs nothing up front (its cap is applied once it is accepted, see `applyCap`); a revocation does:
		// it counts only against a known grant and from the root or a strict ancestor of it, anything else is not
		// stored (no member can fill anybody's storage with revocations that can never apply)
		if (doc.t === "revoke") {
			const target = this.trust.getGrant(doc.target);
			if (!target)
				return { status: "pending", id: key, reason: "unknown target" };
			if (doc.parent !== undefined && !this.trust.getGrant(doc.parent))
				return { status: "pending", id: key, reason: "unknown issuer grant" };
			if (
				doc.issuer !== this.root.deviceId &&
				!this.trust.canRevoke(doc.issuer, doc.target, doc.parent)
			)
				return {
					status: "rejected",
					id: key,
					reason: "issuer cannot revoke this grant",
				};
		}
		const r = await this.trust.add(doc, { from });
		if (r.status === "accepted") {
			if (this.applyCap(doc)) {
				// the arriving document sorts last in its bucket: the kept set is already the cap-N smallest ids, so it
				// goes straight back out (nothing better is held yet, and none is lost: it is asked for again)
				return { status: "rejected", id: key, reason: "issuer over its cap" };
			}
			this.have.add(key);
			this.version++;
			return { status: "accepted", id: key };
		}
		if (r.status === "duplicate") {
			this.have.add(key);
			return { status: "duplicate", id: key };
		}
		if (r.status === "pending")
			return { status: "pending", id: key, reason: r.reason };
		return { status: "rejected", id: key, reason: r.reason };
	}

	/**
	 * R6-S4 (order-independent caps). A cap used to be "the first N that arrive are kept", so two devices holding the
	 * same documents concluded different things: different revocations kept give a different seq cut-off, and different
	 * grants kept give a different membership. The rule is now on the set, not on the arrival order: for each bucket
	 * (grants per issuer, revocations per (issuer, target)) the kept documents are the cap-N ones with the SMALLEST
	 * content address, and a document arriving with a smaller address evicts the largest kept one. Keeping the smallest
	 * ids is incremental (each arrival leaves the cap-N smallest of everything seen so far), so every device ends with
	 * the same set whatever the order, and it agrees with the existing `withinCap` rule for members.
	 * Returns true when the document just accepted is itself the one pushed out.
	 */
	private applyCap(doc: Grant | Revocation): boolean {
		const cap =
			doc.t === "grant"
				? MAX_STORED_PER_ISSUER
				: MAX_REVS_PER_ISSUER_TARGET;
		if (cap <= 0) return false;
		if (doc.t === "grant" && doc.issuer === this.root.deviceId) return false; // the root's own grants are not capped
		const bucket: string[] = [];
		for (const d of this.trust.docs()) {
			if (d.issuer !== doc.issuer) continue;
			if (doc.t === "grant" ? d.t === "grant" : d.t === "revoke" && d.target === doc.target)
				bucket.push(d.id);
		}
		if (bucket.length <= cap) return false;
		const worst = bucket.reduce((a, b) => (a > b ? a : b));
		this.trust.dropAccepted([worst]);
		const evicted = `${doc.t === "grant" ? "g" : "r"}:${worst}`;
		this.have.delete(evicted);
		// the same cap pushes it out on every device, so it is never asked for again (like a pruned rotation)
		this.gone.add(evicted);
		return worst === doc.id;
	}

	/** Identity key of a device: the root's, or the subject key of any of its grants (revoked ones too). */
	identityOf(dev: string): string | undefined {
		return dev === this.root.deviceId ? this.root.pub : this.trust.keyOf(dev);
	}

	private async ingestKex(doc: KexDoc, key: string): Promise<AddOutcome> {
		if (!isKexShape(doc))
			return { status: "rejected", reason: "malformed key record" };
		const pub = this.identityOf(doc.dev);
		if (!pub) return { status: "pending", id: key, reason: "unknown device" };
		// N3: the signature is verified BEFORE anything is written to the persistent superseded list, so a forged record
		// can never retire a real one for good (it would then never be asked for again)
		if (!(await verifyCanonical(pub, kexBody(doc), doc.sig)))
			return { status: "rejected", id: key, reason: "bad signature" };
		const cur = this.kex.get(doc.dev);
		if (cur && (cur.n > doc.n || (cur.n === doc.n && cur.key < key))) {
			this.gone.add(key); // superseded: never asked for again
			return { status: "duplicate", id: key, reason: "superseded" };
		}
		try {
			const kem = b64uDecode(doc.kem);
			if (
				kem.length !== ML_KEM_PUBLIC_KEY_BYTES ||
				!(await isEcdhPublicKey(b64uDecode(doc.ecdh)))
			)
				return { status: "rejected", id: key, reason: "bad key" };
			kemEncapsulate(kem); // FIPS 203 input check: a malformed key must never make a wrap throw
		} catch {
			return { status: "rejected", id: key, reason: "bad key" };
		}
		if (cur) {
			this.have.delete(cur.key);
			this.gone.add(cur.key);
		}
		this.kex.set(doc.dev, { ...doc, key });
		this.have.add(key);
		this.version++;
		return { status: "accepted", id: key };
	}

	private async ingestRot(doc: RotDoc, key: string): Promise<AddOutcome> {
		if (!isRotDoc(doc))
			return { status: "rejected", reason: "malformed rotation" };
		if (doc.from !== this.root.deviceId)
			return {
				status: "rejected",
				id: key,
				reason: "rotation not from the owner",
			};
		const id = key.slice(2);
		if ((await wrapsHash(doc.wraps)) !== doc.wh)
			return { status: "rejected", id: key, reason: "wrap set does not match" };
		let ok = false;
		try {
			ok = identityVerify(
				b64uDecode(this.root.pub),
				rotationSigBytes(id),
				b64uDecode(doc.sig),
			);
		} catch {}
		if (!ok)
			return {
				status: "rejected",
				id: key,
				reason: "rotation signature invalid",
			};
		for (const c of doc.cut) this.cuts.add(c); // executed for good, even once the rotation itself is pruned
		const {
			t,
			v,
			inst,
			epoch,
			from,
			to,
			revoked,
			cut,
			revs,
			n,
			wh,
			wraps,
			sig,
		} = doc;
		this.rots.set(id, {
			t,
			v,
			inst,
			epoch,
			from,
			to,
			revoked,
			cut,
			revs,
			n,
			wh,
			wraps,
			sig,
			id,
		});
		this.have.add(key);
		while (this.rots.size > MAX_ROTATIONS_KEPT) {
			const oldest = [...this.rots.values()].sort(
				(a, b) => a.epoch - b.epoch || (a.id < b.id ? 1 : -1),
			)[0] as RotDoc & { id: string };
			this.rots.delete(oldest.id);
			this.have.delete(`R:${oldest.id}`);
			this.gone.add(`R:${oldest.id}`);
		}
		this.version++;
		return { status: "accepted", id: key };
	}

	// ─── persistence ─────────────────────────────────────────────────────────

	private saving: Promise<void> | null = null;
	private dirty = false;
	/** Persist, coalesced: at most one write in flight and one more queued. */
	private scheduleSave() {
		this.dirty = true;
		if (this.saving) return;
		this.saving = (async () => {
			while (this.dirty) {
				this.dirty = false;
				try {
					await this.save();
				} catch {}
			}
			this.saving = null;
		})();
	}
	/** Resolves once everything accepted so far is in the local store. */
	async flush(): Promise<void> {
		await this.queue;
		while (this.saving) await this.saving;
	}

	private async save() {
		await this.store.set("sec/trust", this.trust.docs());
		await this.store.set(
			"sec/kex",
			[...this.kex.values()].map(({ key: _k, ...d }) => d),
		);
		await this.store.set(
			"sec/rots",
			[...this.rots.values()].map(({ id: _i, ...d }) => d),
		);
		await this.store.set("sec/cuts", [...this.cuts]);
		await this.store.set("sec/gone", this.gone.values());
	}

	private async load() {
		const arr = async (k: string) => {
			const v = await this.store.get(k);
			return Array.isArray(v) ? v : [];
		};
		for (const c of await arr("sec/cuts"))
			if (typeof c === "string") this.cuts.add(c);
		for (const g of await arr("sec/gone"))
			if (typeof g === "string") this.gone.add(g);
		// everything is verified again (the local store is the device's, but checks are cheap enough and keep one path)
		await this.addMany([
			...(await arr("sec/trust")),
			...(await arr("sec/kex")),
			...(await arr("sec/rots")),
		]);
	}

	// ─── queries ─────────────────────────────────────────────────────────────

	/** Grant ids executed by an owner rotation (authoritative cuts). */
	isCut(grantId: string): boolean {
		return this.cuts.has(grantId);
	}
	executedCuts(): string[] {
		return [...this.cuts];
	}

	private chainOf(g: Grant): Grant[] {
		const out: Grant[] = [g];
		for (
			let p = g.parent ? this.trust.getGrant(g.parent) : undefined;
			p && out.length < 8;
			p = p.parent ? this.trust.getGrant(p.parent) : undefined
		)
			out.push(p);
		return out;
	}

	/** The grant was cut off by an owner rotation (itself or an ancestor: revocations cascade). */
	private executed(g: Grant): boolean {
		return this.chainOf(g).some((x) => this.cuts.has(x.id));
	}

	/** R5-S3: an admin's grants count up to MAX_MEMBERS_PER_ADMIN (its lowest grant ids: the same on every device). */
	private withinCap(g: Grant): boolean {
		if (g.issuer === this.root.deviceId) return true;
		if (!this.capIndex) {
			const by = new Map<string, string[]>();
			for (const d of this.trust.docs())
				if (d.t === "grant" && d.issuer !== this.root.deviceId)
					by.set(d.issuer, [...(by.get(d.issuer) ?? []), d.id]);
			this.capIndex = new Map(
				[...by].map(([k, ids]) => [
					k,
					new Set(ids.sort().slice(0, MAX_MEMBERS_PER_ADMIN)),
				]),
			);
		}
		return this.capIndex.get(g.issuer)?.has(g.id) ?? false;
	}

	/** The grant that makes `dev` a member now (best role), or null. Never null for the root (its own authority). */
	memberGrant(dev: string): Grant | null {
		if (dev === this.root.deviceId) return null;
		const ok = this.trust
			.activeGrants(dev, { time: this.now() })
			.filter(
				(g) =>
					!this.executed(g) && this.chainOf(g).every((x) => this.withinCap(x)),
			);
		ok.sort(
			(a, b) =>
				b.delegate - a.delegate ||
				this.chainOf(a).length - this.chainOf(b).length ||
				(a.id < b.id ? -1 : 1),
		);
		return ok[0] ?? null;
	}

	roleOf(dev: string): Role | null {
		if (dev === this.root.deviceId) return "owner";
		const g = this.memberGrant(dev);
		return g ? (g.delegate >= 1 ? "admin" : "member") : null;
	}

	/** Every device with a grant (members and former members), except the root. */
	knownDevices(): string[] {
		const out = new Set<string>();
		for (const d of this.trust.docs())
			if (d.t === "grant") out.add(d.subject.fp);
		out.delete(this.root.deviceId);
		return [...out];
	}

	/**
	 * Results of the whole-set queries. Valid while no document is added (both counters unchanged)
	 * AND within the same second: membership depends on the clock (grants expire / start), so a
	 * cache keyed only on versions would keep an expired member listed until the next document.
	 */
	private memo: {
		key: string;
		members?: MemberInfo[];
		unexecuted?: { devices: string[]; cut: string[]; revs: string[] };
	} = { key: "" };
	private memoFor() {
		const key = `${this.version}|${this.trust.version}|${Math.floor(this.now() / 1000)}`;
		if (this.memo.key !== key) this.memo = { key };
		return this.memo;
	}

	members(): MemberInfo[] {
		const m = this.memoFor();
		if (!m.members) m.members = this.computeMembers();
		return m.members;
	}
	private computeMembers(): MemberInfo[] {
		const out: MemberInfo[] = [];
		for (const dev of this.knownDevices()) {
			const g = this.memberGrant(dev);
			if (g)
				out.push({
					deviceId: dev,
					pub: g.subject.pub,
					role: g.delegate >= 1 ? "admin" : "member",
					grant: g,
				});
		}
		return out;
	}

	/** Has grants, none of which makes it a member any more. */
	isOut(dev: string): boolean {
		return (
			dev !== this.root.deviceId &&
			this.trust.grantsOf(dev).length > 0 &&
			this.memberGrant(dev) === null
		);
	}

	/**
	 * R5-B2: devices that lost membership through a revocation the owner has not executed yet: whoever they are, and
	 * whenever they were paired, they may hold the current key. Executed = cut by an owner rotation (itself or an
	 * ancestor). Returns the devices, the grant ids to cut and the revocation documents behind them.
	 */
	unexecuted(only?: ReadonlySet<string>): {
		devices: string[];
		cut: string[];
		revs: string[];
	} {
		if (!only) {
			const m = this.memoFor();
			if (!m.unexecuted) m.unexecuted = this.computeUnexecuted();
			return m.unexecuted;
		}
		return this.computeUnexecuted(only);
	}
	private computeUnexecuted(only?: ReadonlySet<string>): {
		devices: string[];
		cut: string[];
		revs: string[];
	} {
		const devices = new Set<string>();
		const cut = new Set<string>();
		const revs = new Set<string>();
		const revocations = this.trust.revocations();
		for (const dev of this.knownDevices()) {
			if (only && !only.has(dev)) continue;
			if (this.memberGrant(dev)) continue;
			for (const g of this.trust.grantsOf(dev)) {
				if (
					this.trust.cutOf(g.id) === Number.POSITIVE_INFINITY ||
					this.executed(g)
				)
					continue;
				devices.add(dev);
				cut.add(g.id);
				const chain = new Set(this.chainOf(g).map((x) => x.id));
				for (const r of revocations) if (chain.has(r.target)) revs.add(r.id);
			}
		}
		return {
			devices: [...devices].sort(),
			cut: [...cut].sort(),
			revs: [...revs].sort(),
		};
	}

	/** Best key-agreement record of a device (root or one with a grant). */
	keyAgreement(dev: string): { ecdh: string; kem: string } | null {
		const k = this.kex.get(dev);
		return k ? { ecdh: k.ecdh, kem: k.kem } : null;
	}
	kexDoc(dev: string): KexDoc | null {
		const k = this.kex.get(dev);
		if (!k) return null;
		const { key: _k, ...d } = k;
		return d;
	}

	rotations(): Array<RotDoc & { id: string }> {
		return [...this.rots.values()].sort((a, b) => a.epoch - b.epoch);
	}
	rotation(id: string): (RotDoc & { id: string }) | undefined {
		return this.rots.get(id);
	}

	// ─── exchange ────────────────────────────────────────────────────────────

	inventory(): string[] {
		return [...this.have];
	}
	/**
	 * Keys among `ids` this device does not hold (nor dropped for good, nor knows to be bad).
	 * R6-B1: parked documents do NOT hide a key. Only a VERIFIED (accepted) document with that id stops it from being
	 * asked for again: otherwise one forged copy parked under an id withholds the genuine one from every peer.
	 */
	missing(ids: readonly unknown[]): string[] {
		return ids.filter(
			(k): k is string =>
				typeof k === "string" &&
				k.length <= 64 &&
				/^[gkrR]:/.test(k) &&
				!this.have.has(k) &&
				!this.gone.has(k),
		);
	}
	async get(keys: readonly string[]): Promise<SecDoc[]> {
		const want = new Set(keys);
		const out: SecDoc[] = [];
		for (const d of this.trust.docs())
			if (want.has(`${d.t === "grant" ? "g" : "r"}:${d.id}`)) out.push(d);
		for (const k of this.kex.values())
			if (want.has(k.key)) out.push(this.kexDoc(k.dev) as KexDoc);
		for (const r of this.rots.values())
			if (want.has(`R:${r.id}`)) {
				const { id: _i, ...d } = r;
				out.push(d);
			}
		return out;
	}

	// ─── issuing ─────────────────────────────────────────────────────────────

	/** Grant for `subjectPub` signed by `signer` (the root, or a member whose own grant may delegate). */
	async issueGrant(
		signer: Signer,
		subjectPub: string,
		o: {
			role: "admin" | "member";
			name?: string;
			epoch?: number;
			permissions?: Record<string, "ver" | "editar" | "administrar">;
			now?: number;
		},
	): Promise<Grant> {
		if (!isPublicKey(subjectPub))
			throw new Error("subject is not an ML-DSA-65 public key");
		const preset =
			this.trust.schema.roles?.[o.role] ?? MESH_SCHEMA.roles?.[o.role];
		if (!preset) throw new Error(`unknown role "${o.role}"`);
		const parent =
			signer.fp === this.root.deviceId
				? undefined
				: this.memberGrant(signer.fp);
		if (signer.fp !== this.root.deviceId && (!parent || parent.delegate < 1))
			throw new Error("this device cannot admit others");
		return issueGrant(
			signer,
			{
				subject: { pub: subjectPub },
				role: o.role,
				permissions: o.permissions ?? { ...preset.permissions },
				delegate: preset.delegate ?? 0,
				name: o.name,
				notBefore: 0, // B6: membership never depends on a clock
				epoch: o.epoch,
				issuedAt: o.now,
			},
			{ inst: this.inst, parent: parent ?? undefined, now: o.now },
		);
	}

	/**
	 * Revocations of every grant of `target` that `signer` may revoke (root: all of them; an admin: those it issued,
	 * directly or below). `heads` (web/oplog `headIds()`) keep the target's history up to there; omitted = none kept.
	 */
	async revocationsFor(
		signer: Signer,
		target: string,
		o: {
			heads?: Readonly<Record<string, number | { seq: number; id: string }>>;
			reason?: string;
			now?: number;
		} = {},
	): Promise<Revocation[]> {
		const own =
			signer.fp === this.root.deviceId
				? undefined
				: this.memberGrant(signer.fp);
		const out: Revocation[] = [];
		for (const g of this.trust.grantsOf(target)) {
			if (
				this.trust.cutOf(g.id) !== Number.POSITIVE_INFINITY ||
				this.executed(g)
			)
				continue;
			if (own && !this.trust.canRevoke(signer.fp, g.id, own.id)) continue;
			if (!own && signer.fp !== this.root.deviceId) continue;
			const input = this.trust.prepareRevocation(g.id, o.heads ?? {}, o.reason);
			out.push(
				await issueRevocation(signer, input, {
					inst: this.inst,
					parent: own ?? undefined,
					now: o.now,
				}),
			);
		}
		return out;
	}

	/** This device's own key-agreement record (counter `n` above every record of it seen so far). */
	async kexRecord(signer: Signer, ecdh: string, kem: string): Promise<KexDoc> {
		const cur = this.kex.get(signer.fp);
		if (cur && cur.ecdh === ecdh && cur.kem === kem)
			return this.kexDoc(signer.fp) as KexDoc;
		const body = {
			t: "kex" as const,
			v: 1 as const,
			inst: this.inst,
			dev: signer.fp,
			ecdh,
			kem,
			n: (cur?.n ?? -1) + 1,
		};
		return { ...body, sig: await signCanonical(signer, body) };
	}
}

/** A web/trust Signer over a mesh vault (ML-DSA-65 identity key). */
export function vaultSigner(
	v: {
		deviceId: string;
		devicePublicKey: Uint8Array;
		sign(d: Uint8Array): Promise<Uint8Array>;
	},
	pubB64: string,
): Signer {
	return { alg: SIG_ALG, fp: v.deviceId, pub: pubB64, sign: (d) => v.sign(d) };
}

export { isEpoch };
