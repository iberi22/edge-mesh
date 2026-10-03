import * as Y from "yjs";
import { Awareness, applyAwarenessUpdate, encodeAwarenessUpdate, removeAwarenessStates } from "y-protocols/awareness";
import {
	type Admission,
	type Revocation,
	type Role,
	type TrustRoot,
	canIssue,
	canRevokeRole,
	idMatchesPub,
	isDeviceId,
	signAdmission,
	signRevocation,
	verifyChain,
	verifyRevocation,
} from "./admission.js";
import { deriveDocMaterial, deriveSenderKey, hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { DEFAULT_MAX_FRAME, F_FRAG, Reassembler, fragment } from "./fragment.js";
import { type EcdhIdentity, ecdhSignedBytes, generateEcdhIdentity, unwrapMeshKey, wrapMeshKey } from "./rotation.js";
import {
	type GrantBody,
	GuestPairing,
	HostPairing,
	type PairPayload,
	type SasPrompt,
	createPairOffer,
	decodePairPayload,
	derivePairKey,
} from "./pairing.js";
import { derivePairRoomId, deriveRoomId, fingerprint, meshNamespace } from "./rooms.js";
import { type MeshStore, idbStore, memoryStore } from "./store.js";
import type { Device, PeerLink, RtcOptions, SigTransport, VaultClient } from "./types.js";
import { b64uDecode, b64uEncode, concat, fromUtf8, randomBytes, utf8 } from "./util.js";
import { connectViaSignaling } from "./webrtc.js";

export type MeshStatus = "off" | "connecting" | "online";
export type MeshEvent = "status" | "peers" | "devices" | "sas" | "paired" | "revoked" | "rejected" | "error";

export interface MeshOptions {
	appId: string;
	topic: string;
	doc: Y.Doc;
	vault: VaultClient;
	/** Tried/used in order; ALL optional. Default [] = no network at all. No public defaults. */
	signaling?: SigTransport[];
	persist?: "idb";
	deviceName?: string;
	rtc?: RtcOptions;
	now?: () => number;
	/**
	 * Device-local store for trust state (pinned root, verified admissions, revocations). Default: `vault.store`,
	 * else IndexedDB when persist:'idb', else memory (a reloaded device then has to be paired again).
	 */
	store?: MeshStore;
	/**
	 * Replaces the built-in admission check (signed admission chain up to the pinned root). Called for every
	 * candidate device with the identity key the mesh would trust for it (the mesh already checked that `deviceId`
	 * is the fingerprint of that key); it decides whether that key is a member (e.g. against a signed grant).
	 * Only devices it accepts receive rotation wraps, have their ECDH key used and appear in `devices()`.
	 */
	authorizeDevice?: (deviceId: string, devicePub: Uint8Array) => boolean | Promise<boolean>;
	/**
	 * May `issuer` revoke `target` (which rotates the mesh key for everybody)? Checked before a local revoke() and
	 * for every incoming rotation. Default: built-in roles (owner > admin > member; nobody revokes the owner).
	 */
	canRotate?: (issuer: string, target: string) => boolean | Promise<boolean>;
	/**
	 * Data authorization hook: called before applying every incoming Yjs update with the AUTHENTICATED peer that
	 * delivered it (with signFrames on). Default: allow. Note that a sync reply may carry other members' changes:
	 * `sender` is the delivering device, not necessarily the author (per-author authorization needs a signed log).
	 * A refused update is dropped and reported as a 'rejected' event.
	 */
	authorizeUpdate?: (sender: string, update: Uint8Array) => boolean | Promise<boolean>;
	/**
	 * Sign every data frame with the device identity key and require valid signatures from ADMITTED devices
	 * (default true). Per-sender subkeys alone do not authenticate the sender: every member can derive them.
	 * `false` restores the legacy unsigned wire; it must then be off on every device of the mesh.
	 */
	signFrames?: boolean;
	/**
	 * Namespace of this mesh instance within the app (e.g. a restaurant id); it is bound into the room ids and
	 * every channel frame. Must be identical on all devices. Default: fingerprint of the owner's identity key.
	 */
	instance?: string;
	/** Largest message handed to a link; bigger ones are fragmented (H5). Default 64 KiB. */
	maxFrameBytes?: number;
	/** Largest reassembled message accepted from a peer. Default 64 MiB. */
	maxMessageBytes?: number;
}

export interface PairHostOptions {
	/** Role of the admitted guest. Default "member". Only the owner admits admins. */
	role?: Exclude<Role, "owner">;
	/** Application data for this guest (e.g. a signed capability grant), sent inside the encrypted grant. */
	extra?: (guest: Device) => unknown | Promise<unknown>;
}

/** A private, encrypted, signed message channel of one kind inside the mesh (e.g. "oplog"). */
export interface MeshChannel {
	/** `{appId}/{instance}/{kind}`: frames from any other app or instance are rejected. */
	readonly namespace: string;
	/** Send to every connected, authenticated member (or only `to`). Large payloads are fragmented. */
	send(data: Uint8Array, opts?: { to?: string }): Promise<void>;
	/** `from` is the authenticated sender (signFrames on). */
	onMessage(cb: (data: Uint8Array, from: string) => void): () => void;
	close(): void;
}

export interface PairJoinResult {
	host?: Device;
	extra?: unknown;
}

export interface PairOffer {
	/** Show as QR / copy-paste. */
	payload: string;
	expiresAt: number;
	cancel(): void;
}

export interface Mesh {
	readonly status: MeshStatus;
	readonly peers: string[];
	readonly epoch: number;
	readonly awareness: Awareness;
	/** Resolves when local persistence is loaded and this device is registered. */
	readonly ready: Promise<void>;
	/** Pinned trust root (mesh owner), or null before the first pairing. */
	readonly root: TrustRoot | null;
	/** `{appId}/{instance}` of this mesh ("" instance before the first pairing unless MeshOptions.instance). */
	readonly namespace: string;
	/** Own message channel of a kind (letters, digits, '-', '_', '.'), separate from the shared Y.Doc. */
	channel(kind: string): MeshChannel;
	pairHost(opts?: PairHostOptions): Promise<PairOffer>;
	pairJoin(payload: string, opts?: { confirmSas?: (code: string) => Promise<boolean> | boolean }): Promise<PairJoinResult>;
	/** This device plus every ADMITTED device (self-registered entries in the shared doc are ignored). */
	devices(): Device[];
	/** Verified role of a device (default: this one), or null if it is not admitted. */
	role(deviceId?: string): Role | null;
	revoke(deviceId: string): Promise<void>;
	leave(): void;
	destroy(): void;
	on(event: MeshEvent, cb: (data: any) => void): () => void;
}

const F_DATA = 1; // legacy unsigned data frame (only with signFrames:false)
const F_PAIR = 2;
const F_SDATA = 3; // signed data frame: plaintext = kind | sigLen(u16) | sig | body
const K_SV = 0;
const K_UPDATE = 1;
const K_AWARENESS = 2;
const K_ROTATE = 3;
const K_CHANNEL = 4; // body = nsLen(u16) | namespace | payload
const ORIGIN = Symbol("swal-mesh");
const DEV = "dev/"; // dev/<deviceId> = Device (informative only: trust comes from adm/)
const ADM_PREFIX = "adm/"; // adm/<deviceId> = Admission signed by an owner/admin, verified against the local root pin
const REV_PREFIX = "rev/"; // rev/<deviceId> = Revocation signed by the revoker (H4: replicated + persisted locally)
const ECDH_PREFIX = "ecdh/"; // ecdh/<deviceId> = { pub, sig } (sig by the device identity key)
const ROT_PREFIX = "rot:"; // rot:<epoch>:<deviceId> = { from, wrap, revoked } (pairwise-wrapped new mesh key)
const OLD_PREFIX = "old:"; // old:<epoch> = previous mesh key (b64u); only readable by current members (meta is under the NEW key)

interface RotateMsg {
	epoch: number;
	from: string;
	to: string;
	wrap: string;
	revoked: string;
}

interface LinkRec {
	link: PeerLink;
	rid: string;
	deviceId?: string;
	chain: Promise<void>;
	/** set synchronously by closeRec: never sent to, never read from */
	closing?: boolean;
	/** link on a retired epoch room: only used to hand pairwise wraps to peers that missed the rotation */
	legacy?: Legacy;
	/** signed frames from a sender whose admission has not reached us yet (bounded; replayed on trust changes) */
	held?: { frames: Array<{ d: Uint8Array; t: number }>; bytes: number };
}

const HOLD_MAX_FRAMES = 64;
const HOLD_MAX_BYTES = 8 * 1024 * 1024;
const HOLD_MS = 30_000;

/** What a device signs for a data frame: bound to the room (mesh key + epoch), the sender and the kind. */
const frameSigBytes = (rid: string, sender: string, kind: number, body: Uint8Array) =>
	concat(utf8(`swal-frame/v1|${rid}|${sender}|`), new Uint8Array([kind]), body);

interface Legacy {
	epoch: number;
	rid: string;
	material: Uint8Array;
}

export function createMesh(opts: MeshOptions): Mesh {
	const { appId, topic: topicName, doc, vault } = opts;
	const transports = opts.signaling ?? [];
	const now = opts.now ?? (() => Date.now());
	const meta = doc.getMap<any>("meta");
	const awareness = new Awareness(doc);
	const listeners = new Map<MeshEvent, Set<(d: any) => void>>();
	const emit = (e: MeshEvent, d?: unknown) => {
		for (const cb of listeners.get(e) ?? []) {
			try {
				cb(d);
			} catch {}
		}
	};

	let destroyed = false;
	let running = false;
	let meshKey: Uint8Array | null = null;
	let docMat: Uint8Array | null = null;
	let sigKey: CryptoKey | null = null;
	let dataRid = "";
	let instanceId = opts.instance ?? "";
	let epoch = 0;
	let status: MeshStatus = "off";
	const links = new Set<LinkRec>();
	// per-sender AES-GCM keys, cached PER KEY MATERIAL (never by epoch number: two meshes, or two concurrent
	// rotations, can share an epoch number). Reset by loadKeys (B3).
	let senderKeys = new WeakMap<Uint8Array, Map<string, Promise<CryptoKey>>>();
	const revokedIds = new Map<string, number>(); // deviceId -> revocation time (persisted in the local store)
	const store: MeshStore =
		opts.store ??
		vault.store ??
		(opts.persist === "idb" && typeof indexedDB !== "undefined" ? idbStore(`swal-mesh-local/${appId}/${topicName}`) : memoryStore());
	let root: TrustRoot | null = null;
	let admCache: Record<string, Admission> = {}; // verified admissions: survive tampering with the shared doc
	let ecdhOk: Record<string, string> = {}; // `${deviceId}|${identityPub}` -> verified ECDH pub
	let trusted = new Map<string, Device>(); // admitted devices other than this one
	let admittedAt = new Map<string, number>(); // `at` of each trusted device's VERIFIED admission
	let selfAdm: Admission | null = null;
	const legacy = new Map<string, Legacy>(); // retired data rid -> its epoch material
	let ecdhId: EcdhIdentity | null = null;
	const rooms = new Map<string, () => void>(); // rid -> leave
	const linkSubs: Array<() => void> = [];
	let hostSession: { s: HostPairing; rid: string } | null = null;
	let guestSession: { s: GuestPairing; rid: string } | null = null;
	let pairRids = new Set<string>();

	const maxFrame = opts.maxFrameBytes ?? DEFAULT_MAX_FRAME;
	const signFrames = opts.signFrames !== false;
	const peerIds = () => [...new Set([...links].filter((l) => l.deviceId && l.rid !== "pair" && !l.legacy && !l.closing).map((l) => l.deviceId!))];
	const setStatus = () => {
		const s: MeshStatus = !running ? "off" : peerIds().length > 0 ? "online" : "connecting";
		if (s !== status) {
			status = s;
			emit("status", s);
		}
		emit("peers", peerIds());
	};
	const err = (e: unknown) => emit("error", e);

	// ---- devices: only ADMITTED ones (H1). The 'meta' map is writable by every member, so a device entry is
	// trusted only through a signed admission chain up to the locally pinned root (or the authorizeDevice hook).
	const selfRole = (): Role | null => (root?.deviceId === vault.deviceId ? "owner" : (selfAdm?.role ?? null));
	const selfDevice = (): Device => {
		const d = meta.get(DEV + vault.deviceId) as Device | undefined;
		return {
			deviceId: vault.deviceId,
			pub: b64uEncode(vault.devicePublicKey),
			name: d?.name ?? opts.deviceName ?? "device",
			addedAt: d?.addedAt ?? 0,
			...(selfRole() ? { role: selfRole()! } : {}),
			...(selfAdm ? { admittedBy: selfAdm.by } : {}),
		};
	};
	const devices = (): Device[] => [selfDevice(), ...trusted.values()].sort((a, b) => a.addedAt - b.addedAt);
	const roleOf = (id: string): Role | null => (id === vault.deviceId ? selfRole() : (trusted.get(id)?.role ?? null));
	/** H2: rotation/revocation only from an authorized issuer. A target that is not admitted counts as a member. */
	const canRotate = async (issuer: string, target: string): Promise<boolean> => {
		if (opts.canRotate) return Boolean(await opts.canRotate(issuer, target));
		const ir = roleOf(issuer);
		const tr = target === root?.deviceId ? "owner" : (roleOf(target) ?? "member");
		return ir !== null && canRevokeRole(ir, tr);
	};
	const chainCtx = (r: TrustRoot) => ({
		vault,
		root: r,
		candidates: (id: string) => {
			const out: Admission[] = [];
			const m = meta.get(ADM_PREFIX + id) as Admission | undefined;
			if (m) out.push(m);
			if (admCache[id] && admCache[id].sig !== m?.sig) out.push(admCache[id]);
			return out;
		},
		revokedAt: (id: string) => revokedIds.get(id),
	});
	let trustChain: Promise<void> = Promise.resolve();
	const refreshTrust = () => (trustChain = trustChain.then(computeTrust).catch(err));
	const persistRevoked = () => store.set("revoked", Object.fromEntries(revokedIds));
	/** A device is cut off if revoked and not re-admitted (newer admission) afterwards. */
	const isRevoked = (id: string) => {
		const at = revokedIds.get(id);
		return at !== undefined && !(trusted.has(id) && (admittedAt.get(id) ?? -1) > at);
	};
	async function computeTrust() {
		// 1) signed revocations replicated in the doc (only valid ones count; the local map only ever grows)
		if (root) {
			const rctx = chainCtx(root);
			const rmemo = new Map<string, Promise<Admission | null>>();
			let changed = false;
			for (const k of meta.keys()) {
				if (!k.startsWith(REV_PREFIX)) continue;
				const r = meta.get(k) as Revocation;
				if (r?.target !== k.slice(REV_PREFIX.length) || (revokedIds.get(r.target) ?? -1) >= r.at) continue;
				if (!(await verifyRevocation(rctx, r, rmemo))) continue;
				revokedIds.set(r.target, r.at);
				changed = true;
			}
			if (changed) await persistRevoked();
		}
		const ids = new Set<string>(Object.keys(admCache));
		for (const k of meta.keys()) {
			if (k.startsWith(ADM_PREFIX)) ids.add(k.slice(ADM_PREFIX.length));
			else if (opts.authorizeDevice && k.startsWith(DEV)) ids.add(k.slice(DEV.length));
		}
		if (root) ids.add(root.deviceId);
		ids.delete(vault.deviceId);
		const memo = new Map<string, Promise<Admission | null>>();
		const ctx = root ? chainCtx(root) : null;
		const next = new Map<string, Device>();
		const nextAt = new Map<string, number>();
		const nextCache: Record<string, Admission> = {};
		for (const id of ids) {
			const adm = ctx ? await verifyChain(ctx, id, memo) : null;
			if (adm?.sig) nextCache[id] = adm;
			const dev = meta.get(DEV + id) as Device | undefined;
			const pub = adm?.pub ?? (opts.authorizeDevice && typeof dev?.pub === "string" ? dev.pub : undefined);
			if (!pub || !(await idMatchesPub(id, pub))) continue;
			if (opts.authorizeDevice ? !(await opts.authorizeDevice(id, b64uDecode(pub))) : !adm) continue;
			if (adm) nextAt.set(id, adm.at);
			next.set(id, {
				deviceId: id,
				pub,
				name: adm?.name || dev?.name || id,
				addedAt: adm?.at || dev?.addedAt || 0,
				...(adm ? { role: adm.role, admittedBy: adm.by } : {}),
			});
		}
		selfAdm = ctx && root?.deviceId !== vault.deviceId ? await verifyChain(ctx, vault.deviceId, memo) : null;
		if (selfAdm?.sig) nextCache[vault.deviceId] = selfAdm;
		trusted = next;
		admittedAt = nextAt;
		if (JSON.stringify(nextCache) !== JSON.stringify(admCache)) {
			admCache = nextCache;
			await store.set("adm", admCache);
		}
		// verify (and remember) each member's ECDH key now, so a later overwrite in meta cannot replace it
		for (const id of next.keys()) await peerEcdhPub(id);
		emit("devices", devices());
		replayHeld();
	}
	meta.observe(() => void refreshTrust());

	// ---- persistence ----
	let persistence: { destroy(): Promise<void> | void } | null = null;
	const ready = (async () => {
		// B1: a deviceId IS the fingerprint of the identity key; every peer enforces it, so must we
		if (!(await idMatchesPub(vault.deviceId, b64uEncode(vault.devicePublicKey)))) {
			throw new Error("vault.deviceId must be fingerprint(vault.devicePublicKey) (see web/rooms fingerprint)");
		}
		const r = (await store.get("root")) as TrustRoot | undefined;
		if (r && typeof r.deviceId === "string" && typeof r.pub === "string" && typeof r.mid === "string") root = r;
		const rv = (await store.get("revoked")) as Record<string, number> | undefined;
		for (const [id, at] of Object.entries(rv ?? {})) if (typeof at === "number") revokedIds.set(id, at);
		admCache = ((await store.get("adm")) as Record<string, Admission> | undefined) ?? {};
		ecdhOk = ((await store.get("ecdh")) as Record<string, string> | undefined) ?? {};
		if (opts.persist === "idb" && typeof indexedDB !== "undefined") {
			const { IndexeddbPersistence } = await import("y-indexeddb");
			const p = new IndexeddbPersistence(`swal-mesh/${appId}/${topicName}`, doc);
			persistence = p;
			await p.whenSynced;
		}
		if (opts.persist === "idb" && typeof indexedDB === "undefined") {
			throw new Error("persist:'idb' requested but IndexedDB is not available");
		}
		if (!meta.has(DEV + vault.deviceId)) {
			meta.set(DEV + vault.deviceId, {
				deviceId: vault.deviceId,
				pub: b64uEncode(vault.devicePublicKey),
				name: opts.deviceName ?? "device",
				addedAt: now(),
			} satisfies Device);
		}
		await publishEcdh();
		await refreshTrust();
		if (root && trusted.size > 0 && !destroyed) await start(); // already paired: resume
	})();
	ready.catch(err);

	// ---- pairwise ECDH identity (rotation wraps) ----
	async function ecdhIdentity(): Promise<EcdhIdentity> {
		return (ecdhId ??= (await vault.getEcdhIdentity?.()) ?? (await generateEcdhIdentity()));
	}
	async function publishEcdh() {
		const id = await ecdhIdentity();
		const pub = b64uEncode(id.publicKey);
		const cur = meta.get(ECDH_PREFIX + vault.deviceId) as { pub: string } | undefined;
		if (cur?.pub === pub) return;
		const sig = b64uEncode(await vault.sign(ecdhSignedBytes(vault.deviceId, pub)));
		meta.set(ECDH_PREFIX + vault.deviceId, { pub, sig });
	}
	/**
	 * ECDH public key of an ADMITTED device, verified against the identity key from its admission (never against
	 * the self-declared dev/<id> entry). A key verified once is remembered, so tampering with meta cannot swap it.
	 */
	async function peerEcdhPub(deviceId: string): Promise<Uint8Array | null> {
		const idPub = trusted.get(deviceId)?.pub;
		if (!idPub) return null;
		const slot = `${deviceId}|${idPub}`;
		const e = meta.get(ECDH_PREFIX + deviceId) as { pub: string; sig: string } | undefined;
		if (e && typeof e.pub === "string" && typeof e.sig === "string" && e.pub !== ecdhOk[slot]) {
			try {
				if (await vault.verify(b64uDecode(idPub), ecdhSignedBytes(deviceId, e.pub), b64uDecode(e.sig))) {
					ecdhOk = { ...ecdhOk, [slot]: e.pub };
					await store.set("ecdh", ecdhOk);
				}
			} catch {}
		}
		return ecdhOk[slot] ? b64uDecode(ecdhOk[slot]) : null;
	}

	// ---- keys ----
	function senderKey(material: Uint8Array, deviceId: string): Promise<CryptoKey> {
		let m = senderKeys.get(material);
		if (!m) senderKeys.set(material, (m = new Map()));
		let key = m.get(deviceId);
		if (!key) {
			if (m.size >= 4096) m.clear();
			key = deriveSenderKey(material, topicName, deviceId);
			m.set(deviceId, key);
		}
		return key;
	}
	const localNum = (x: unknown) => (typeof x === "number" && Number.isSafeInteger(x) && x >= 0 ? x : 0);
	async function persistEpoch(n: number) {
		await vault.setEpoch?.(n);
		await store.set("epoch", n);
	}
	async function loadKeys(raw?: Uint8Array) {
		senderKeys = new WeakMap(); // B3: nothing derived from a previous mesh key survives a key change
		meshKey = raw ?? (await vault.getOrCreateMeshKey());
		// B2: the epoch is device-local state (vault / local store), advanced only by a verified rotation or by the
		// authenticated pairing grant. It is NEVER read from the shared doc, which every member can write.
		epoch = Math.max(localNum(await vault.getEpoch?.()), localNum(await store.get("epoch")), epoch);
		docMat = await deriveDocMaterial(meshKey, topicName);
		sigKey = await importAesKey(await hkdf(meshKey, `swal-signal/v1|${topicName}`));
		instanceId = opts.instance ?? (root ? await fingerprint(b64uDecode(root.pub)) : "");
		dataRid = await deriveRoomId(meshKey, appId, topicName, epoch, instanceId || undefined);
	}

	// ---- link I/O: per-link ordered queue; messages above maxFrame are fragmented (H5) ----
	const outQ = new WeakMap<PeerLink, Promise<void>>();
	function sendBytes(link: PeerLink, bytes: Uint8Array, alive: () => boolean = () => true): Promise<void> {
		const next = (outQ.get(link) ?? Promise.resolve())
			.then(async () => {
				if (!alive()) return;
				for (const f of await fragment(bytes, maxFrame)) {
					if (!alive()) return;
					link.send(f);
				}
			})
			.catch(err);
		outQ.set(link, next);
		return next;
	}

	// ---- framing ----
	// Every sender seals under its OWN subkey (HKDF over the sender's deviceId); receivers derive it
	// from the deviceId in the frame header (also bound in the AAD). Wire: F_DATA | idLen | id | nonce | ct+tag.
	// With signFrames (default) the plaintext also carries the sender's identity signature over
	// (rid, sender, kind, body): F_SDATA | idLen | id | nonce | AES-GCM(kind | sigLen | sig | body).
	const signCache = new WeakMap<Uint8Array, { rid: string; kind: number; sig: Promise<Uint8Array> }>();
	function signFor(rid: string, kind: number, body: Uint8Array): Promise<Uint8Array> {
		const c = signCache.get(body); // a broadcast signs once for all links
		if (c && c.rid === rid && c.kind === kind) return c.sig;
		const sig = vault.sign(frameSigBytes(rid, vault.deviceId, kind, body));
		signCache.set(body, { rid, kind, sig });
		return sig;
	}
	async function sendFrame(rec: LinkRec, kind: number, body: Uint8Array) {
		const lg = rec.legacy;
		const mat = lg ? lg.material : docMat;
		if (!mat || rec.closing) return;
		const rid = lg ? lg.rid : dataRid;
		const key = await senderKey(mat, vault.deviceId);
		const id = utf8(vault.deviceId);
		let inner: Uint8Array;
		if (signFrames) {
			const sig = await signFor(rid, kind, body);
			inner = concat(new Uint8Array([kind, sig.length >> 8, sig.length & 0xff]), sig, body);
		} else inner = concat(new Uint8Array([kind]), body);
		const sealed = await sealUpdate(key, inner, `${rid}|${vault.deviceId}`);
		if (rec.closing) return;
		await sendBytes(rec.link, concat(new Uint8Array([signFrames ? F_SDATA : F_DATA, id.length]), id, sealed), () => !rec.closing);
	}
	const established = () =>
		[...links].filter(
			(l) => !l.closing && !l.legacy && (l.rid === dataRid || l.rid === "") && !(l.deviceId && isRevoked(l.deviceId)),
		);
	/** Synchronous: the link leaves `links` right now (the transport's onClose may fire much later). */
	function closeRec(rec: LinkRec) {
		rec.closing = true;
		links.delete(rec);
		try {
			rec.link.close();
		} catch {}
		setStatus();
	}
	const broadcast = (kind: number, body: Uint8Array, except?: LinkRec) => {
		for (const l of established()) if (l !== except) sendFrame(l, kind, body).catch(err);
	};

	// one stable sender per link: the pairing state machines identify the active link by it
	const pairSenders = new WeakMap<PeerLink, (m: any) => void>();
	function sendPair(link: PeerLink) {
		let f = pairSenders.get(link);
		if (!f) {
			f = (m: unknown) => void sendBytes(link, concat(new Uint8Array([F_PAIR]), utf8(JSON.stringify(m))));
			pairSenders.set(link, f);
		}
		return f;
	}

	const reject = (reason: string, from?: string) => emit("rejected", { reason, from });
	const heldAt = new WeakMap<Uint8Array, number>(); // first time a frame was held (kept across replays)
	function hold(rec: LinkRec, data: Uint8Array) {
		if (!rec.held) rec.held = { frames: [], bytes: 0 };
		const h = rec.held;
		const t = heldAt.get(data) ?? now();
		heldAt.set(data, t);
		h.frames.push({ d: data, t });
		h.bytes += data.length;
		while (h.frames.length > HOLD_MAX_FRAMES || h.bytes > HOLD_MAX_BYTES) h.bytes -= h.frames.shift()!.d.length;
	}
	/** Re-run held frames once the trust state changed (a pending admission may have arrived). */
	function replayHeld() {
		for (const rec of links) {
			const h = rec.held;
			if (!h || rec.closing) continue;
			rec.held = undefined;
			for (const f of h.frames) {
				if (now() - f.t > HOLD_MS) continue;
				rec.chain = rec.chain.then(() => onData(rec, f.d)).catch(err);
			}
		}
	}

	async function onData(rec: LinkRec, data: Uint8Array) {
		const lg = rec.legacy;
		const mat = lg ? lg.material : docMat;
		if (!mat || !running || rec.closing) return;
		const signed = data[0] === F_SDATA;
		if (!signed && signFrames) return reject("unsigned frame");
		const idLen = data[1];
		if (data.length < 2 + idLen) return;
		const sender = fromUtf8(data.subarray(2, 2 + idLen));
		if (!isDeviceId(sender) || isRevoked(sender)) return;
		if (rec.deviceId && rec.deviceId !== sender) return reject("frame sender does not match the link", sender);
		const rid = lg ? lg.rid : dataRid;
		let plain: Uint8Array;
		try {
			const key = await senderKey(mat, sender);
			plain = await openUpdate(key, data.subarray(2 + idLen), `${rid}|${sender}`);
		} catch {
			return; // wrong key / tampered / other epoch: drop silently
		}
		if (rec.closing) return;
		const kind = plain[0];
		let body = plain.subarray(1);
		if (signed) {
			const sigLen = plain.length >= 3 ? (plain[1] << 8) | plain[2] : -1;
			if (sigLen < 0 || plain.length < 3 + sigLen) return reject("malformed signed frame", sender);
			const sig = plain.subarray(3, 3 + sigLen);
			body = plain.subarray(3 + sigLen);
			const pub = trusted.get(sender)?.pub;
			if (!pub) {
				if (!lg) hold(rec, data); // its admission may still be on its way through another peer
				return;
			}
			let ok = false;
			try {
				ok = await vault.verify(b64uDecode(pub), frameSigBytes(rid, sender, kind, body), sig);
			} catch {}
			if (!ok) return reject("bad frame signature", sender);
			if (rec.closing) return;
		}
		if (!rec.deviceId) {
			rec.deviceId = sender;
			setStatus();
		}
		if (lg) {
			// retired room: the only thing we do is hand THIS peer its own pairwise wrap for the next epoch
			if (kind === K_SV) {
				const w = meta.get(`${ROT_PREFIX}${lg.epoch + 1}:${sender}`) as { from: string; wrap: string; revoked: string } | undefined;
				if (w) {
					const msg: RotateMsg = { epoch: lg.epoch + 1, from: w.from, to: sender, wrap: w.wrap, revoked: w.revoked };
					await sendFrame(rec, K_ROTATE, utf8(JSON.stringify(msg)));
				}
			} else if (kind === K_ROTATE) await handleRotate(body);
			return;
		}
		if (kind === K_SV) {
			await sendFrame(rec, K_UPDATE, Y.encodeStateAsUpdate(doc, body));
		} else if (kind === K_UPDATE) {
			if (opts.authorizeUpdate && !(await opts.authorizeUpdate(sender, body))) return reject("update not authorized", sender);
			if (rec.closing) return;
			Y.applyUpdate(doc, body, ORIGIN);
		} else if (kind === K_AWARENESS) {
			applyAwarenessUpdate(awareness, body, ORIGIN);
		} else if (kind === K_ROTATE) {
			await handleRotate(body);
		} else if (kind === K_CHANNEL) {
			const n = body.length >= 2 ? (body[0] << 8) | body[1] : -1;
			if (n < 0 || body.length < 2 + n) return reject("malformed channel frame", sender);
			const ns = fromUtf8(body.subarray(2, 2 + n));
			const k = ns.slice(ns.lastIndexOf("/") + 1);
			if (ns !== chanNs(k)) return reject("foreign channel", sender);
			const payload = body.subarray(2 + n);
			for (const cb of [...(chanSubs.get(k) ?? [])]) {
				try {
					cb(payload, sender);
				} catch (e) {
					err(e);
				}
			}
		}
	}

	// ---- channels: app/instance-namespaced message streams over the same encrypted + signed frames ----
	const chanSubs = new Map<string, Set<(d: Uint8Array, from: string) => void>>();
	const chanNs = (kind: string) => `${meshNamespace(appId, instanceId)}/${kind}`;
	function channel(kind: string): MeshChannel {
		if (!/^[A-Za-z0-9._-]{1,64}$/.test(kind)) throw new Error(`invalid channel kind "${kind}"`);
		const mine = new Set<(d: Uint8Array, from: string) => void>();
		return {
			get namespace() {
				return chanNs(kind);
			},
			async send(data, o = {}) {
				if (!running) throw new Error("mesh is not connected");
				const ns = utf8(chanNs(kind));
				const body = concat(new Uint8Array([ns.length >> 8, ns.length & 0xff]), ns, data);
				const targets = established().filter((l) => l.deviceId && (o.to === undefined || l.deviceId === o.to));
				await Promise.all(targets.map((l) => sendFrame(l, K_CHANNEL, body)));
			},
			onMessage(cb) {
				const set = chanSubs.get(kind) ?? new Set();
				chanSubs.set(kind, set);
				set.add(cb);
				mine.add(cb);
				return () => {
					set.delete(cb);
					mine.delete(cb);
				};
			},
			close() {
				for (const cb of mine) chanSubs.get(kind)?.delete(cb);
				mine.clear();
			},
		};
	}

	async function handleRotate(body: Uint8Array) {
		let r: RotateMsg;
		try {
			r = JSON.parse(fromUtf8(body)) as RotateMsg;
		} catch {
			return;
		}
		if (r.to !== vault.deviceId || r.epoch !== epoch + 1 || isRevoked(r.from) || r.from === r.revoked) return;
		if (typeof r.revoked !== "string" || r.revoked === vault.deviceId) return;
		const fromPub = await peerEcdhPub(r.from);
		if (!fromPub) return;
		if (!(await canRotate(r.from, r.revoked))) {
			emit("rejected", { reason: "rotation not authorized", from: r.from, revoked: r.revoked, epoch: r.epoch });
			return;
		}
		let newKey: Uint8Array;
		try {
			newKey = await unwrapMeshKey((await ecdhIdentity()).privateKey, fromPub, r.epoch, r.from, r.to, b64uDecode(r.wrap), r.revoked);
		} catch {
			emit("rejected", { reason: "rotation wrap does not authenticate", from: r.from, revoked: r.revoked, epoch: r.epoch });
			return;
		}
		if (r.epoch !== epoch + 1) return; // raced with another adoption
		await adoptRotation(newKey, r.epoch, r.revoked);
	}

	async function onPairFrame(rec: LinkRec, data: Uint8Array) {
		const msg = JSON.parse(fromUtf8(data.subarray(1)));
		const send = sendPair(rec.link);
		if (hostSession && pairRids.has(rec.rid)) await hostSession.s.handle(msg, send);
		else if (guestSession && pairRids.has(rec.rid)) await guestSession.s.handle(msg, send);
	}

	function wireLink(link: PeerLink, rid: string) {
		const isData = running && rid === dataRid;
		const lg = running && !isData ? legacy.get(rid) : undefined;
		const isPair = pairRids.has(rid);
		if (rid !== "" && !isData && !isPair && !lg) return link.close();
		const rec: LinkRec = { link, rid: isPair && !isData ? "pair" : rid, chain: Promise.resolve() };
		if (lg) rec.legacy = lg;
		if (rid === "") rec.rid = ""; // room-less (qr-sdp): frames are self-describing
		links.add(rec);
		const reasm = new Reassembler({ maxMessageBytes: opts.maxMessageBytes });
		const dispatch = (d: Uint8Array) =>
			d[0] === F_PAIR ? onPairFrame({ ...rec, rid: rid === "" ? ([...pairRids][0] ?? "") : rid }, d) : d[0] === F_DATA || d[0] === F_SDATA ? onData(rec, d) : undefined;
		link.onMessage((d) => {
			if (rec.closing) return;
			rec.chain = rec.chain
				.then(async () => {
					if (d[0] !== F_FRAG) return dispatch(d);
					const whole = await reasm.push(d);
					if (whole && whole[0] !== F_FRAG && !rec.closing) return dispatch(whole);
				})
				.catch(err);
		});
		link.onClose(() => {
			reasm.clear();
			rec.held = undefined;
			links.delete(rec);
			setStatus();
		});
		if (isPair && guestSession) guestSession.s.attach(sendPair(link));
		if (isData || (rid === "" && running)) {
			sendFrame(rec, K_SV, Y.encodeStateVector(doc)).catch(err);
			const st = awareness.getLocalState();
			if (st) sendFrame(rec, K_AWARENESS, encodeAwarenessUpdate(awareness, [doc.clientID])).catch(err);
		}
		if (rid === "" && guestSession) guestSession.s.attach(sendPair(link));
		setStatus();
	}

	// ---- rooms ----
	let subscribed = false;
	async function joinRoom(rid: string, key: CryptoKey) {
		if (rooms.has(rid)) return;
		if (!subscribed) {
			subscribed = true;
			for (const t of transports) if (t.kind === "link") linkSubs.push(t.onLink((l, r) => !destroyed && wireLink(l, r)));
		}
		const stops: Array<() => void> = [];
		rooms.set(rid, () => stops.forEach((s) => s()));
		for (const t of transports) {
			try {
				if (t.kind === "link") {
					await t.join(rid, vault.deviceId);
					stops.push(() => t.leave(rid));
				} else {
					const stop = await connectViaSignaling(t, {
						rid,
						selfId: vault.deviceId,
						key,
						rtc: opts.rtc,
						onLink: (l) => !destroyed && wireLink(l, rid),
						onError: err,
					});
					stops.push(stop);
				}
			} catch (e) {
				err(e); // a dead transport must not take the mesh down: others still run
			}
		}
	}
	function leaveRoom(rid: string) {
		rooms.get(rid)?.();
		rooms.delete(rid);
	}

	async function start() {
		if (running || destroyed) return;
		await loadKeys();
		running = true;
		setStatus();
		await joinRoom(dataRid, sigKey!);
		await syncLegacy();
	}

	function stopNetwork() {
		running = false;
		for (const rid of [...rooms.keys()]) leaveRoom(rid);
		for (const l of [...links]) closeRec(l);
		links.clear();
		legacy.clear();
		for (const u of linkSubs.splice(0)) u();
		subscribed = false;
		pairRids = new Set();
		hostSession = null;
		guestSession = null;
		setStatus();
	}

	// ---- document / awareness propagation ----
	const onDocUpdate = (u: Uint8Array, origin: unknown) => {
		if (origin !== ORIGIN && running) broadcast(K_UPDATE, u);
	};
	doc.on("update", onDocUpdate);
	const onAwareness = (c: { added: number[]; updated: number[]; removed: number[] }, origin: unknown) => {
		if (origin === ORIGIN || !running) return;
		broadcast(K_AWARENESS, encodeAwarenessUpdate(awareness, [...c.added, ...c.updated, ...c.removed]));
	};
	awareness.on("update", onAwareness);

	// ---- rotation ----
	// The new mesh key never travels under the shared (old) key: it is wrapped per remaining device with
	// ECDH(own static key, peer static key) -> HKDF(swal-rotate/v1|epoch|from|to) -> AES-GCM. The wraps are also
	// stored in meta (rot:<epoch>:<deviceId>) so a peer that was offline can fetch its own wrap later through the
	// retired-epoch room (see `legacy`); the revoked device has no wrap and cannot unwrap anyone else's.
	async function switchEpoch(newKey: Uint8Array, newEpoch: number) {
		const oldRid = dataRid;
		const old: Legacy = { epoch, rid: oldRid, material: docMat! };
		const oldKey = meshKey!;
		await vault.setMeshKey(newKey);
		await persistEpoch(newEpoch);
		epoch = newEpoch;
		await loadKeys(newKey);
		// links stay up across the rotation; the retired room stays joined ONLY to serve wraps to stragglers
		for (const l of links) if (l.rid === oldRid && !l.legacy) l.rid = dataRid;
		legacy.set(oldRid, old);
		await joinRoom(dataRid, sigKey!);
		return { oldEpoch: old.epoch, oldKey };
	}

	async function syncLegacy() {
		if (!running) return;
		for (const k of [...meta.keys()]) {
			if (!k.startsWith(OLD_PREFIX)) continue;
			const e = Number(k.slice(OLD_PREFIX.length));
			if (!Number.isInteger(e) || e >= epoch) continue;
			const raw = b64uDecode(meta.get(k) as string);
			const rid = await deriveRoomId(raw, appId, topicName, e, instanceId || undefined);
			if (legacy.has(rid) && rooms.has(rid)) continue;
			legacy.set(rid, { epoch: e, rid, material: await deriveDocMaterial(raw, topicName) });
			await joinRoom(rid, await importAesKey(await hkdf(raw, `swal-signal/v1|${topicName}`)));
		}
	}
	meta.observe((ev) => {
		if ([...ev.keysChanged].some((k) => k.startsWith(OLD_PREFIX))) void syncLegacy().catch(err);
	});

	function forget(deviceId: string, at = now()) {
		revokedIds.set(deviceId, Math.max(at, revokedIds.get(deviceId) ?? at));
		trusted.delete(deviceId);
		admittedAt.delete(deviceId);
		delete admCache[deviceId];
		void Promise.all([store.set("adm", admCache), persistRevoked()]).catch(err);
	}

	async function adoptRotation(newKey: Uint8Array, newEpoch: number, revoked: string) {
		forget(revoked);
		for (const l of [...links]) if (l.deviceId === revoked) closeRec(l);
		const { oldEpoch, oldKey } = await switchEpoch(newKey, newEpoch);
		meta.set(OLD_PREFIX + oldEpoch, b64uEncode(oldKey));
		emit("revoked", { deviceId: revoked, epoch });
	}

	async function revoke(deviceId: string) {
		await ready;
		if (deviceId === vault.deviceId) throw new Error("cannot revoke the current device");
		await refreshTrust();
		if (!meta.has(DEV + deviceId) && !trusted.has(deviceId)) throw new Error("unknown device");
		if (!(await canRotate(vault.deviceId, deviceId))) throw new Error(`not authorized to revoke ${deviceId}`);
		if (!running) await start();
		// cut the revoked device off SYNCHRONOUSLY: its link must not be reachable by anything below
		forget(deviceId);
		for (const l of [...links]) if (l.deviceId === deviceId) closeRec(l);
		const newKey = randomBytes(32);
		const newEpoch = epoch + 1;
		const rev = root
			? await signRevocation(vault, { mid: root.mid, target: deviceId, by: vault.deviceId, epoch: newEpoch, at: revokedIds.get(deviceId) ?? now() })
			: null;
		const priv = (await ecdhIdentity()).privateKey;
		const wraps = new Map<string, RotateMsg>();
		for (const d of trusted.values()) {
			if (d.deviceId === deviceId) continue;
			const pub = await peerEcdhPub(d.deviceId);
			if (!pub) {
				err(new Error(`no verified ECDH key for ${d.deviceId}: it must be re-paired after the rotation`));
				continue;
			}
			const wrap = await wrapMeshKey(priv, pub, newEpoch, vault.deviceId, d.deviceId, newKey, deviceId);
			wraps.set(d.deviceId, { epoch: newEpoch, from: vault.deviceId, to: d.deviceId, wrap, revoked: deviceId });
		}
		// 1) hand each connected remaining peer ITS OWN wrap, 2) switch, 3) publish the removal + wraps under the NEW key
		await Promise.all(
			established()
				.filter((l) => l.deviceId && l.deviceId !== deviceId && wraps.has(l.deviceId))
				.map((l) => sendFrame(l, K_ROTATE, utf8(JSON.stringify(wraps.get(l.deviceId!))))),
		);
		const { oldEpoch, oldKey } = await switchEpoch(newKey, newEpoch);
		doc.transact(() => {
			meta.delete(DEV + deviceId);
			meta.delete(ADM_PREFIX + deviceId);
			meta.delete(ECDH_PREFIX + deviceId);
			if (rev) meta.set(REV_PREFIX + deviceId, rev);
			meta.set(OLD_PREFIX + oldEpoch, b64uEncode(oldKey));
			for (const [to, m] of wraps) meta.set(`${ROT_PREFIX}${newEpoch}:${to}`, { from: m.from, wrap: m.wrap, revoked: deviceId });
		});
		emit("revoked", { deviceId, epoch });
	}

	// ---- pairing ----
	/** First pairing of a fresh mesh: this device becomes its owner (the pinned trust root). */
	async function ensureRoot(): Promise<TrustRoot> {
		if (root) return root;
		const mid = typeof meta.get("mid") === "string" ? (meta.get("mid") as string) : b64uEncode(randomBytes(16));
		meta.set("mid", mid);
		root = { mid, deviceId: vault.deviceId, pub: b64uEncode(vault.devicePublicKey) };
		await store.set("root", root);
		return root;
	}

	/** Admission chain of `id` from the local cache, up to (excluding) the root. */
	function chainOf(id: string): Admission[] {
		const out: Admission[] = [];
		for (let cur = id, i = 0; i < 8 && cur !== root?.deviceId; i++) {
			const a = admCache[cur];
			if (!a) break;
			out.push(a);
			cur = a.by;
		}
		return out;
	}

	async function pairHost(o: PairHostOptions = {}): Promise<PairOffer> {
		await ready;
		const guestRole: Role = o.role ?? "member";
		const r = await ensureRoot();
		await refreshTrust();
		const mine = selfRole();
		if (!mine || !canIssue(mine, guestRole)) throw new Error(`this device (${mine ?? "not admitted"}) cannot admit a ${guestRole}`);
		const key = await vault.getOrCreateMeshKey();
		const offer = await createPairOffer(vault, { mid: r.mid, appId, topic: topicName, now: now() });
		const rid = await derivePairRoomId(offer.pairSecret);
		const pairKey = await derivePairKey(offer.pairSecret);
		const host = new HostPairing(offer, {
			now,
			verify: (pub, data, sig) => vault.verify(pub, data, sig),
			onSas: (p: SasPrompt) => emit("sas", { role: "host", ...p }),
			buildGrant: async (guest): Promise<GrantBody> => {
				// B1: the ack already proved possession of guest.pub and deviceId = fingerprint(pub). Never admit a
				// device under the identity of this host, of the root, or of a member admitted with another key.
				if (guest.deviceId === vault.deviceId || guest.deviceId === r.deviceId) throw new Error("guest claims the host/root identity");
				const known = trusted.get(guest.deviceId)?.pub ?? admCache[guest.deviceId]?.pub;
				if (known !== undefined && known !== guest.pub) throw new Error("deviceId already admitted with another key");
				const adm = await signAdmission(vault, {
					mid: r.mid,
					deviceId: guest.deviceId,
					pub: guest.pub,
					name: guest.name,
					role: guestRole,
					by: vault.deviceId,
					at: now(),
				});
				const dev: Device = { ...guest, addedAt: adm.at, role: guestRole, admittedBy: vault.deviceId };
				const extra = o.extra ? await o.extra(dev) : undefined;
				if (opts.authorizeDevice && !(await opts.authorizeDevice(guest.deviceId, b64uDecode(guest.pub)))) {
					throw new Error("device not authorized by the mesh policy");
				}
				revokedIds.delete(guest.deviceId); // explicit re-admission (its new admission post-dates the revocation)
				await persistRevoked();
				admCache[guest.deviceId] = adm;
				trusted.set(guest.deviceId, dev);
				admittedAt.set(guest.deviceId, adm.at);
				doc.transact(() => {
					meta.delete(REV_PREFIX + guest.deviceId);
					meta.set(ADM_PREFIX + guest.deviceId, adm);
					meta.set(DEV + guest.deviceId, { deviceId: dev.deviceId, pub: dev.pub, name: dev.name, addedAt: dev.addedAt });
				});
				await store.set("adm", admCache);
				return {
					meshKey: b64uEncode(key),
					epoch,
					mid: r.mid,
					snapshot: b64uEncode(Y.encodeStateAsUpdate(doc)),
					hostDevice: selfDevice(),
					root: r,
					admissions: [adm, ...chainOf(vault.deviceId)],
					...(extra !== undefined ? { extra } : {}),
				};
			},
			onPaired: (d) => {
				emit("paired", trusted.get(d.deviceId) ?? d);
				endPairing(rid);
				void start().catch(err);
			},
			onFail: (reason) => {
				emit("error", new Error(`pairing failed: ${reason}`));
				endPairing(rid);
			},
		});
		hostSession = { s: host, rid };
		pairRids.add(rid);
		await joinRoom(rid, pairKey);
		const timer = setTimeout(() => endPairing(rid), offer.payload.exp - now() + 1000);
		const endPairingOnce = () => clearTimeout(timer);
		(host as any)._end = endPairingOnce;
		return {
			payload: offer.encoded,
			expiresAt: offer.payload.exp,
			cancel: () => {
				host.cancel();
				endPairing(rid);
			},
		};
	}

	function endPairing(rid: string) {
		(hostSession?.s as any)?._end?.();
		leaveRoom(rid);
		pairRids.delete(rid);
		// let the last frame (grant, possibly fragmented) flush before dropping the pairing links
		const pairLinks = [...links].filter((l) => l.rid === "pair");
		for (const l of pairLinks) {
			const drained = Promise.race([outQ.get(l.link) ?? Promise.resolve(), new Promise((r) => setTimeout(r, 10_000))]);
			void drained.then(() => setTimeout(() => l.link.close(), 500));
		}
		if (hostSession?.rid === rid) hostSession = null;
		if (guestSession?.rid === rid) guestSession = null;
		setStatus();
	}

	const MOVE_MESH_ERR =
		"this device belongs to another mesh: to join a different one, create a new Mesh with a fresh Y.Doc";
	/** Only this device's own bookkeeping (dev/<self>, ecdh/<self>) and no shared content at all. */
	function docIsFresh(): boolean {
		for (const [name, t] of doc.share) {
			if (name === "meta") {
				for (const k of meta.keys()) if (k !== DEV + vault.deviceId && k !== ECDH_PREFIX + vault.deviceId) return false;
				continue;
			}
			const ty = t as unknown as { _start: unknown; _map: Map<string, unknown> };
			if (ty._start !== null || ty._map.size > 0) return false;
		}
		return true;
	}

	async function pairJoin(encoded: string, o: { confirmSas?: (code: string) => Promise<boolean> | boolean } = {}) {
		await ready;
		const p: PairPayload = decodePairPayload(encoded);
		if (p.appId !== appId || p.topic !== topicName) throw new Error("pairing payload is for a different app/topic");
		// B3: a device moving to ANOTHER mesh would merge this mesh's doc into it (and keep serving it). Only a fresh
		// doc may change meshes: create a new Mesh with a new Y.Doc for that.
		const moving = root !== null && root.mid !== p.mid;
		if (moving && !docIsFresh()) throw new Error(MOVE_MESH_ERR);
		// ...and while moving, the old mesh must not fill the fresh doc: go offline from it (resumed on failure)
		const resumeOld = moving && running;
		if (resumeOld) stopNetwork();
		const confirm =
			o.confirmSas ??
			((code: string) =>
				new Promise<boolean>((resolve) => emit("sas", { role: "guest", code, confirm: () => resolve(true), reject: () => resolve(false) })));
		const guest = await GuestPairing.create(p, vault, {
			name: opts.deviceName ?? "device",
			onSas: async (code) => Boolean(await confirm(code)),
			now: now(),
		});
		const rid = await derivePairRoomId(b64uDecode(p.pairSecret));
		guestSession = { s: guest, rid };
		pairRids.add(rid);
		await joinRoom(rid, await derivePairKey(b64uDecode(p.pairSecret)));
		const timeout = setTimeout(() => guest.fail(new Error("pairing timed out")), Math.max(1000, p.exp - now()));
		try {
			const g = await guest.result;
			clearTimeout(timeout);
			// the trust root and our admission arrive over the SAS-authenticated session; the chain must be valid and
			// lead to the very host key that signed the QR payload
			if (!g.root || !Array.isArray(g.admissions)) throw new Error("pairing grant carries no admission (host too old?)");
			const grantAdm = new Map<string, Admission[]>();
			for (const a of g.admissions) grantAdm.set(a?.deviceId, [...(grantAdm.get(a?.deviceId) ?? []), a]);
			const gctx = { vault, root: g.root, candidates: (id: string) => grantAdm.get(id) ?? [], revokedAt: () => undefined };
			const memo = new Map<string, Promise<Admission | null>>();
			const mine = await verifyChain(gctx, vault.deviceId, memo);
			if (!mine || mine.pub !== b64uEncode(vault.devicePublicKey)) throw new Error("pairing grant: invalid admission for this device");
			const issuer = await verifyChain(gctx, mine.by, memo);
			if (!issuer || issuer.pub !== p.dpk) throw new Error("pairing grant: admission not issued by the paired host");
			if (g.root.mid !== p.mid || g.mid !== p.mid) throw new Error("pairing grant: mesh id does not match the pairing code");
			const switching = root?.mid !== g.root.mid;
			if (switching && root && !docIsFresh()) throw new Error(MOVE_MESH_ERR);
			// leave the current network BEFORE touching keys or the doc: nothing of one mesh may reach the other
			if (running) stopNetwork();
			if (switching) {
				admCache = {};
				ecdhOk = {};
				revokedIds.clear();
				trusted = new Map();
				admittedAt = new Map();
				selfAdm = null;
				legacy.clear();
				await store.set("ecdh", ecdhOk);
				await persistRevoked();
			}
			root = g.root;
			await store.set("root", root);
			for (const list of grantAdm.values()) for (const a of list) if (a.deviceId !== g.root.deviceId) admCache[a.deviceId] = a;
			await store.set("adm", admCache);
			const key = b64uDecode(g.meshKey);
			if (!Number.isSafeInteger(g.epoch) || g.epoch < 0) throw new Error("pairing grant: bad epoch");
			await vault.setMeshKey(key);
			await persistEpoch(g.epoch);
			epoch = g.epoch;
			Y.applyUpdate(doc, b64uDecode(g.snapshot), ORIGIN);
			doc.transact(() => {
				meta.set(ADM_PREFIX + vault.deviceId, mine);
				meta.set(DEV + vault.deviceId, {
					deviceId: vault.deviceId,
					pub: b64uEncode(vault.devicePublicKey),
					name: opts.deviceName ?? "device",
					addedAt: mine.at,
				} satisfies Device);
			});
			await publishEcdh();
			await refreshTrust();
			endPairing(rid);
			emit("paired", g.hostDevice);
			await start();
			return { host: g.hostDevice, extra: g.extra };
		} catch (e) {
			clearTimeout(timeout);
			endPairing(rid);
			if (resumeOld && !running && root?.mid !== p.mid) void start().catch(err);
			throw e;
		}
	}

	return {
		get status() {
			return status;
		},
		get peers() {
			return peerIds();
		},
		get epoch() {
			return epoch;
		},
		get root() {
			return root;
		},
		get namespace() {
			return meshNamespace(appId, instanceId);
		},
		channel,
		role(deviceId = vault.deviceId) {
			return deviceId === vault.deviceId ? selfRole() : (trusted.get(deviceId)?.role ?? null);
		},
		awareness,
		ready,
		pairHost,
		pairJoin,
		devices,
		revoke,
		leave() {
			stopNetwork();
		},
		destroy() {
			if (destroyed) return;
			destroyed = true;
			stopNetwork();
			doc.off("update", onDocUpdate);
			removeAwarenessStates(awareness, [doc.clientID], ORIGIN);
			awareness.destroy();
			for (const t of transports) t.close();
			void persistence?.destroy();
			listeners.clear();
		},
		on(event, cb) {
			let set = listeners.get(event);
			if (!set) listeners.set(event, (set = new Set()));
			set.add(cb);
			return () => void set!.delete(cb);
		},
	};
}
