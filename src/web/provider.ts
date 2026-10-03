import * as Y from "yjs";
import { Awareness, applyAwarenessUpdate, encodeAwarenessUpdate, removeAwarenessStates } from "y-protocols/awareness";
import {
	type Admission,
	type ChainContext,
	type Revocation,
	type Role,
	type TrustRoot,
	canIssue,
	canRevokeRole,
	idMatchesPub,
	isDeviceId,
	isEpoch,
	isRevocation,
	MAX_EPOCH,
	MAX_EPOCH_SKIP,
	signAdmission,
	signRevocation,
	verifyChain,
	verifyRevocation,
} from "./admission.js";
import { deriveDocMaterial, deriveSenderKey, hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { type ByteBudget, DEFAULT_MAX_FRAME, DEFAULT_MAX_MESSAGE, F_FRAG, Reassembler, fragment } from "./fragment.js";
import {
	type EcdhIdentity,
	type RotRecord,
	ecdhSignedBytes,
	generateEcdhIdentity,
	isRotRecord,
	rotationId,
	unwrapMeshKey,
	wrapMeshKey,
} from "./rotation.js";
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
import { b64uDecode, b64uEncode, concat, equalBytes, fromUtf8, randomBytes, utf8 } from "./util.js";
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
	 * May `issuer` revoke `target` (which rotates the mesh key for everybody)? Checked before a local revoke() and,
	 * when given, for every incoming rotation. Default: built-in roles (owner > admin > member; nobody revokes the
	 * owner) for a local revoke(); an incoming rotation needs an owner/admin issuer AND a valid signed revocation of
	 * every device it cuts off.
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
const F_SDATA = 3; // signed data frame: plaintext = kind | sess(8) | seq(u32) | sigLen(u16) | sig | body
const K_SV = 0;
const K_UPDATE = 1;
const K_AWARENESS = 2;
const K_ROTATE = 3;
const K_CHANNEL = 4; // body = nsLen(u16) | namespace | payload
const K_HELLO = 5; // body = nonce(16): fresh challenge of this link (S1)
const K_AUTH = 6; // body = peer's nonce(16) | epoch(u32), signed: the sender is live on THIS link (S1)
const NONCE_BYTES = 16;
/** SF4: per link, at most this many challenges sent and answered */
const HANDSHAKE_MAX = 8;
/** Replay window per sender session: seqs at most this far behind the highest one are still accepted once. */
const REPLAY_WINDOW = 1024;
const ORIGIN = Symbol("swal-mesh");
const DEV = "dev/"; // dev/<deviceId> = Device (informative only: trust comes from adm/)
const ADM_PREFIX = "adm/"; // adm/<deviceId> = Admission signed by an owner/admin, verified against the local root pin
const REV_PREFIX = "rev/"; // rev/<deviceId>:<epoch> = Revocation signed by the revoker (H4: replicated + persisted locally)
const revKey = (r: { target: string; epoch: number }) => `${REV_PREFIX}${r.target}:${r.epoch}`;
const REVOKED_KEY = "revoked/v2"; // local store: deviceId -> revocation epochs (v1 held wall-clock times)
const ECDH_PREFIX = "ecdh/"; // ecdh/<deviceId> = { pub, sig } (sig by the device identity key)
const ROTREC_PREFIX = "rotrec:"; // rotrec:<rotId> = RotRecord (public part of a rotation, same for every recipient)
const ROT_PREFIX = "rot:"; // rot:<rotId>:<deviceId> = that rotation's new key, wrapped pairwise for deviceId
const OLD_PREFIX = "old:"; // old:<rid> = { e: epoch, k: retired mesh key (b64u) }; meta travels under the CURRENT key
/** Retired keys tried on (and used to seal) rotation frames, so devices on another branch/epoch still get them. */
const RETIRED_TRY = 4;
const MAX_CANDIDATES = 16;

/** K_ROTATE body: the shared rotation record plus the recipient's own pairwise wrap. */
interface RotateMsg {
	rot: RotRecord;
	to: string;
	wrap: string;
}
type Rot = RotRecord & { id: string };
/** Total order of rotations (B4): higher epoch first, then the lower rotation id. Deterministic on every device. */
const betterRot = (a: { epoch: number; id: string }, b: { epoch: number; id: string }) =>
	a.epoch !== b.epoch ? a.epoch > b.epoch : a.id < b.id;

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
	/** S1: our challenge on this link; the peer must sign it back (K_AUTH) before anything else is accepted */
	nonce?: Uint8Array;
	/** S1: the peer answered our challenge: `deviceId` is authenticated for this link, with this sender session */
	authed?: boolean;
	peerSess?: string;
	/** S5: raise this link's reassembly limits once it is authenticated */
	lift?: () => void;
	/** we answered the peer's challenge */
	authSent?: boolean;
	/** SF4: handshake messages seen/sent on this link (re-sent after trust changes, capped) */
	hellosIn?: number;
	hellosOut?: number;
	answers?: number;
	started?: boolean;
}

const HOLD_MAX_FRAMES = 64;
const HOLD_MAX_BYTES = 8 * 1024 * 1024;
/** S5: held frames of ALL links together */
const HOLD_TOTAL_BYTES = 16 * 1024 * 1024;
/** S5: largest message reassembled on a link before it is authenticated, and for all such links together */
const PRE_AUTH_MAX = 1024 * 1024;
const PRE_AUTH_TOTAL = 8 * 1024 * 1024;
/** S5: largest pairing message (JSON); the grant no longer carries the doc, which arrives by normal sync */
const PAIR_MAX = 256 * 1024;
const HOLD_MS = 30_000;

const u32 = (n: number) => {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, false);
	return b;
};
/**
 * What a device signs for a data frame: bound to the room (mesh key + epoch), the sender, the kind and a per-sender
 * session + sequence number (S1: receivers drop duplicates and replays).
 */
const frameSigBytes = (rid: string, sender: string, kind: number, sess: Uint8Array, seq: number, body: Uint8Array) =>
	concat(utf8(`swal-frame/v2|${rid}|${sender}|`), new Uint8Array([kind]), sess, u32(seq), body);

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
	// deviceId -> epochs of its valid revocations (B6: epochs, never clocks; persisted in the local store)
	const revokedIds = new Map<string, number[]>();
	const store: MeshStore =
		opts.store ??
		vault.store ??
		(opts.persist === "idb" && typeof indexedDB !== "undefined" ? idbStore(`swal-mesh-local/${appId}/${topicName}`) : memoryStore());
	let root: TrustRoot | null = null;
	let admCache: Record<string, Admission> = {}; // verified admissions: survive tampering with the shared doc
	let ecdhOk: Record<string, string> = {}; // `${deviceId}|${identityPub}` -> verified ECDH pub
	let trusted = new Map<string, Device>(); // admitted devices other than this one
	let admittedAt = new Map<string, number>(); // epoch of each trusted device's VERIFIED admission
	let selfAdm: Admission | null = null;
	const legacy = new Map<string, Legacy>(); // retired data rid -> its epoch material
	let curRot: Rot | null = null; // rotation that produced the current key (null: epoch 0 / unknown)
	const cands = new Map<string, { rec: Rot; key: Uint8Array }>(); // verified rotations not adopted (yet)
	const revRecs = new Map<string, Revocation[]>(); // verified signed revocations per target (justify re-rotations)
	let rotChain: Promise<unknown> = Promise.resolve();
	/** Every key change (own rotation, adoption, conflict resolution) runs one at a time. */
	function serialRot<T>(f: () => Promise<T>): Promise<T> {
		const run = rotChain.then(f);
		rotChain = run.catch(() => {});
		return run;
	}
	let ecdhId: EcdhIdentity | null = null;
	const rooms = new Map<string, () => void>(); // rid -> leave
	const linkSubs: Array<() => void> = [];
	let hostSession: { s: HostPairing; rid: string } | null = null;
	let guestSession: { s: GuestPairing; rid: string } | null = null;
	let pairRids = new Set<string>();

	const maxFrame = opts.maxFrameBytes ?? DEFAULT_MAX_FRAME;
	const signFrames = opts.signFrames !== false;
	const peerIds = () => [
		...new Set(
			[...links]
				.filter((l) => l.deviceId && l.rid !== "pair" && !l.legacy && !l.closing && !isRevoked(l.deviceId))
				.map((l) => l.deviceId!),
		),
	];
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
	const chainCtx = (r: TrustRoot): ChainContext => ({
		vault,
		root: r,
		epoch,
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
	const persistRevoked = async () => store.set(REVOKED_KEY, Object.fromEntries(revokedIds));
	/** Record a valid revocation of `id` effective from epoch `ep`. Returns true if it is new. */
	function addRevocation(id: string, ep: number): boolean {
		const list = revokedIds.get(id) ?? [];
		if (list.includes(ep)) return false;
		revokedIds.set(id, [...list, ep].sort((x, y) => x - y).slice(-64));
		return true;
	}
	/** A device is cut off if revoked and not re-admitted afterwards (an admission issued at or after the revocation epoch). */
	const isRevoked = (id: string) => {
		const revs = revokedIds.get(id);
		if (!revs?.length) return false;
		return !(trusted.has(id) && (admittedAt.get(id) ?? -1) >= revs[revs.length - 1]);
	};
	async function computeTrust() {
		// 1) signed revocations replicated in the doc (only valid ones count; the local map only ever grows)
		if (root) {
			const rctx = chainCtx(root);
			let changed = false;
			for (const k of meta.keys()) {
				if (!k.startsWith(REV_PREFIX)) continue;
				const r = meta.get(k) as Revocation;
				if (!isRevocation(r) || k !== revKey(r) || revokedIds.get(r.target)?.includes(r.epoch)) continue;
				if (!(await verifyRevocation(rctx, r))) continue;
				keepRevRecord(r);
				changed = addRevocation(r.target, r.epoch) || changed;
			}
			if (changed) {
				await persistRevoked();
				for (const l of [...links]) if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
				void serialRot(coverCheck).catch(err); // a revoked device may hold the current key: re-key (B4)
			}
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
			if (adm) nextAt.set(id, adm.epoch);
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
		// a revoked device keeps its (now void) admission: revocations it signed before are verified "as of" then (B4/B6)
		for (const [id, a] of Object.entries(admCache)) if (!nextCache[id] && revokedIds.has(id)) nextCache[id] = a;
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
		const rv = (await store.get(REVOKED_KEY)) as Record<string, unknown> | undefined;
		for (const [id, eps] of Object.entries(rv ?? {})) {
			if (Array.isArray(eps)) for (const e of eps) if (Number.isSafeInteger(e) && e >= 1) addRevocation(id, e);
		}
		admCache = ((await store.get("adm")) as Record<string, Admission> | undefined) ?? {};
		const cr = (await store.get("rot")) as Rot | undefined;
		if (isRotRecord(cr) && typeof cr.id === "string" && cr.id === (await rotationId(cr))) curRot = cr;
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
		if (!m) {
			m = new Map();
			senderKeys.set(material, m);
		}
		let key = m.get(deviceId);
		if (!key) {
			if (m.size >= 4096) m.clear();
			key = deriveSenderKey(material, topicName, deviceId);
			m.set(deviceId, key);
		}
		return key;
	}
	const localNum = (x: unknown) => (isEpoch(x) ? x : 0); // SF1: an out-of-range local value is ignored
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
		if (curRot && curRot.epoch !== epoch) curRot = null;
	}

	// ---- link I/O: per-link ordered queue; messages above maxFrame are fragmented (H5) ----
	const outQ = new WeakMap<PeerLink, Promise<void>>();
	function sendBytes(link: PeerLink, bytes: Uint8Array, alive: () => boolean = () => true): Promise<void> {
		const next = (outQ.get(link) ?? Promise.resolve())
			.then(async () => {
				if (!alive()) return;
				for (const f of await fragment(bytes, maxFrame)) {
					if (link.drain) await link.drain(); // BL3: paced by the peer instead of piling up in memory
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
	type Signed = { sig: Uint8Array; sess: Uint8Array; seq: number };
	const signCache = new WeakMap<Uint8Array, { rid: string; kind: number; p: Promise<Signed> }>();
	let selfSess = randomBytes(8); // this instance's sender session (a restart is a new session)
	let selfSeq = 0;
	function signFor(rid: string, kind: number, body: Uint8Array): Promise<Signed> {
		const c = signCache.get(body); // a broadcast signs once (same seq) for all links
		if (c && c.rid === rid && c.kind === kind) return c.p;
		if (selfSeq >= 0xffffffff) {
			selfSess = randomBytes(8);
			selfSeq = 0;
		}
		const sess = selfSess;
		const seq = ++selfSeq;
		const p = vault.sign(frameSigBytes(rid, vault.deviceId, kind, sess, seq, body)).then((sig) => ({ sig, sess, seq }));
		signCache.set(body, { rid, kind, p });
		return p;
	}
	// receiver side of S1: highest seq + recently seen seqs per (sender, session)
	const replay = new Map<string, { max: number; seen: Set<number> }>();
	function freshSeq(sender: string, sess: string, seq: number): boolean {
		const k = `${sender}|${sess}`;
		let w = replay.get(k);
		if (!w) {
			if (replay.size >= 4096) replay.delete(replay.keys().next().value as string);
			w = { max: 0, seen: new Set() };
			replay.set(k, w);
		}
		if (seq + REPLAY_WINDOW <= w.max || w.seen.has(seq)) return false;
		w.seen.add(seq);
		if (seq > w.max) w.max = seq;
		if (w.seen.size > 2 * REPLAY_WINDOW) for (const x of w.seen) if (x + REPLAY_WINDOW <= w.max) w.seen.delete(x);
		return true;
	}
	function sendFrame(rec: LinkRec, kind: number, body: Uint8Array) {
		const lg = rec.legacy;
		return sendFrameWith(rec, kind, body, lg ? lg.material : docMat, lg ? lg.rid : dataRid);
	}
	/** Recent retired keys (newest first): rotation frames are also sealed under them, and receivers try them. */
	const retiredKeys = () => [...legacy.values()].sort((x, y) => y.epoch - x.epoch).slice(0, RETIRED_TRY);
	/** A rotation frame must reach peers still on the previous key or on a concurrent branch: seal it under each. */
	async function sendRotate(rec: LinkRec, msg: RotateMsg) {
		const body = utf8(JSON.stringify(msg));
		if (rec.legacy) return sendFrame(rec, K_ROTATE, body);
		await sendFrameWith(rec, K_ROTATE, body, docMat, dataRid);
		for (const r of retiredKeys()) await sendFrameWith(rec, K_ROTATE, body, r.material, r.rid);
	}
	async function sendFrameWith(rec: LinkRec, kind: number, body: Uint8Array, mat: Uint8Array | null, rid: string) {
		if (!mat || rec.closing) return;
		const key = await senderKey(mat, vault.deviceId);
		const id = utf8(vault.deviceId);
		let inner: Uint8Array;
		if (signFrames) {
			const { sig, sess, seq } = await signFor(rid, kind, body);
			inner = concat(new Uint8Array([kind]), sess, u32(seq), new Uint8Array([sig.length >> 8, sig.length & 0xff]), sig, body);
		} else inner = concat(new Uint8Array([kind]), body);
		const sealed = await sealUpdate(key, inner, `${rid}|${vault.deviceId}`);
		if (rec.closing) return;
		await sendBytes(rec.link, concat(new Uint8Array([signFrames ? F_SDATA : F_DATA, id.length]), id, sealed), () => !rec.closing);
	}
	const established = () =>
		[...links].filter(
			(l) =>
				!l.closing &&
				!l.legacy &&
				(!signFrames || l.authed) &&
				(l.rid === dataRid || l.rid === "") &&
				!(l.deviceId && isRevoked(l.deviceId)),
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
	let heldTotal = 0; // S5: bytes held over all links
	function dropHeld(rec: LinkRec) {
		if (rec.held) heldTotal -= rec.held.bytes;
		rec.held = undefined;
	}
	function hold(rec: LinkRec, data: Uint8Array) {
		if (heldTotal + data.length > HOLD_TOTAL_BYTES) return; // S5: global cap (the sender resyncs later)
		if (!rec.held) rec.held = { frames: [], bytes: 0 };
		const h = rec.held;
		const t = heldAt.get(data) ?? now();
		heldAt.set(data, t);
		h.frames.push({ d: data, t });
		h.bytes += data.length;
		heldTotal += data.length;
		while (h.frames.length > HOLD_MAX_FRAMES || h.bytes > HOLD_MAX_BYTES) {
			const n = (h.frames.shift() as { d: Uint8Array }).d.length;
			h.bytes -= n;
			heldTotal -= n;
		}
	}
	/** Re-run held frames once the trust state changed (a pending admission may have arrived). */
	function replayHeld() {
		// SF4: held handshake frames may have expired meanwhile: challenge every unauthenticated link again
		if (signFrames) for (const rec of links) if (!rec.authed && rec.rid !== "pair") resendHello(rec);
		for (const rec of links) {
			const h = rec.held;
			if (!h || rec.closing) continue;
			dropHeld(rec);
			for (const f of h.frames) {
				if (now() - f.t > HOLD_MS) continue;
				rec.chain = rec.chain.then(() => onData(rec, f.d)).catch(err);
			}
		}
	}

	async function onData(rec: LinkRec, data: Uint8Array) {
		const lg = rec.legacy;
		if (!running || rec.closing || data.length < 2) return;
		const signed = data[0] === F_SDATA;
		if (!signed && signFrames) return reject("unsigned frame");
		const idLen = data[1];
		if (data.length < 2 + idLen) return;
		const sender = fromUtf8(data.subarray(2, 2 + idLen));
		if (!isDeviceId(sender)) return;
		if (rec.deviceId && rec.deviceId !== sender) return reject("frame sender does not match the link", sender);
		const revoked = isRevoked(sender);
		// signed frames from a sender whose admission has not reached us yet: hold them (still encrypted, no key derived)
		if (signed && !revoked && !trusted.has(sender)) {
			if (!lg) hold(rec, data);
			return;
		}
		// the link's key first; on a live link also the recent retired keys, which may only carry rotations (B4)
		const tries = lg ? [{ material: lg.material, rid: lg.rid }] : [{ material: docMat, rid: dataRid }, ...retiredKeys()];
		let plain: Uint8Array | null = null;
		let rid = "";
		let retired = false;
		for (let i = 0; i < tries.length && !plain; i++) {
			const t = tries[i];
			if (!t.material) continue;
			try {
				plain = await openUpdate(await senderKey(t.material, sender), data.subarray(2 + idLen), `${t.rid}|${sender}`);
				rid = t.rid;
				retired = i > 0;
			} catch {} // wrong key / tampered / other epoch: try the next one, else drop silently
		}
		if (!plain || rec.closing || plain.length < 1) return;
		const kind = plain[0];
		let body = plain.subarray(1);
		let sess = "";
		if (signed) {
			if (plain.length < 15) return reject("malformed signed frame", sender);
			const sessBytes = plain.subarray(1, 9);
			const seq = new DataView(plain.buffer, plain.byteOffset + 9, 4).getUint32(0, false);
			const sigLen = (plain[13] << 8) | plain[14];
			if (plain.length < 15 + sigLen) return reject("malformed signed frame", sender);
			const sig = plain.subarray(15, 15 + sigLen);
			body = plain.subarray(15 + sigLen);
			sess = b64uEncode(sessBytes);
			if (revoked) {
				// a revoked device is never listened to... except, on a LIVE link, for the revocations its rotation carries
				// that it signed concurrently with its own revocation (B4 union). Never through a retired room (SF2): a
				// revoked device keeps the old key and could otherwise back-date revocations of everybody.
				if (kind === K_ROTATE && !lg) await serialRot(() => rotationEvidence(body, sender));
				return;
			}
			const pub = trusted.get(sender)?.pub;
			if (!pub) return;
			let ok = false;
			try {
				ok = await vault.verify(b64uDecode(pub), frameSigBytes(rid, sender, kind, sessBytes, seq, body), sig);
			} catch {}
			if (!ok) return reject("bad frame signature", sender);
			if (rec.closing) return;
			// S1: a link carries nothing but its handshake until the peer signed OUR fresh challenge on it
			if (kind === K_HELLO) {
				if (retired || body.length !== NONCE_BYTES) return;
				rec.hellosIn = (rec.hellosIn ?? 0) + 1;
				if ((rec.answers ?? 0) < HANDSHAKE_MAX) await answerHello(rec, body);
				// SF4: a repeated challenge means our earlier messages may have been lost (e.g. held and expired while
				// the peer was not yet admitted here): challenge again too
				if (rec.hellosIn > 1 && !rec.authed) resendHello(rec);
				return;
			}
			if (kind === K_AUTH) {
				if (retired || rec.authed || !rec.nonce) return;
				const ep = rec.legacy ? rec.legacy.epoch : epoch;
				const okAuth =
					body.length === NONCE_BYTES + 4 &&
					equalBytes(body.subarray(0, NONCE_BYTES), rec.nonce) &&
					new DataView(body.buffer, body.byteOffset + NONCE_BYTES, 4).getUint32(0, false) === ep;
				if (!okAuth) return reject("bad link authentication", sender);
				rec.deviceId = sender;
				rec.authed = true;
				rec.peerSess = sess;
				rec.lift?.();
				setStatus();
				return maybeStart(rec);
			}
			if (!rec.authed || sess !== rec.peerSess || !freshSeq(sender, sess, seq)) return; // replay / other link
		} else if (revoked) return;
		if (retired) {
			if (kind === K_ROTATE) await serialRot(() => handleRotate(body));
			return;
		}
		if (!rec.deviceId) {
			rec.deviceId = sender; // legacy unsigned wire only: the link is bound to its first sender
			rec.lift?.();
			setStatus();
		}
		if (lg) {
			// retired room: the only thing we do is hand THIS peer its own pairwise wraps of later rotations
			if (kind === K_SV) for (const m of await storedRotationsFor(sender, lg.epoch)) await sendRotate(rec, m);
			else if (kind === K_ROTATE) await serialRot(() => handleRotate(body));
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
			await serialRot(() => handleRotate(body));
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

	// ---- rotation messages (B4: concurrent rotations converge deterministically) ----
	function parseRotate(body: Uint8Array): RotateMsg | null {
		try {
			const m = JSON.parse(fromUtf8(body)) as RotateMsg;
			return m && isRotRecord(m.rot) && typeof m.to === "string" && typeof m.wrap === "string" ? m : null;
		} catch {
			return null;
		}
	}
	function keepRevRecord(r: Revocation) {
		const list = revRecs.get(r.target) ?? [];
		if (!list.some((x) => x.sig === r.sig)) revRecs.set(r.target, [...list, r].slice(-4));
	}
	/** Verify and record the signed revocations a rotation carries. They count whatever happens to its key. */
	const badRevs = new Set<string>(); // SF2/R1b: signatures of records that did not verify (never checked twice)
	async function ingestRevs(revs: readonly unknown[], max = 16): Promise<boolean> {
		if (!root) return false;
		let changed = false;
		for (const r of revs.slice(0, max)) {
			if (!isRevocation(r) || revokedIds.get(r.target)?.includes(r.epoch) || badRevs.has(r.sig)) continue;
			if (!(await verifyRevocation(chainCtx(root), r))) {
				if (badRevs.size >= 4096) badRevs.clear();
				badRevs.add(r.sig);
				continue;
			}
			keepRevRecord(r);
			// note V2: republish what we verified, so devices that never saw the rotation carrying it learn it too
			if (!meta.has(revKey(r))) meta.set(revKey(r), r);
			changed = addRevocation(r.target, r.epoch) || changed;
		}
		if (changed) {
			await persistRevoked();
			for (const l of [...links]) if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
			void refreshTrust();
		}
		return changed;
	}
	const evidenceSeen = new Map<string, number>(); // SF2: evidence frames accepted per revoked sender
	/**
	 * A rotation from a device we already consider revoked: only the revocations IT signed at the epoch of its own
	 * revocation, of devices that rotation cuts off, are taken into account (what it may have done concurrently).
	 */
	async function rotationEvidence(body: Uint8Array, sender: string) {
		const m = parseRotate(body);
		if (!m || m.rot.from !== sender) return;
		const n = evidenceSeen.get(sender) ?? 0;
		if (n >= 4) return; // a handful per revoked device is all a concurrent rotation needs
		evidenceSeen.set(sender, n + 1);
		const own = revokedIds.get(sender) ?? [];
		const revs = m.rot.revs.filter(
			(r) => isRevocation(r) && r.by === sender && own.includes(r.epoch) && m.rot.revoked.includes(r.target),
		);
		if (await ingestRevs(revs, 8)) await coverCheck();
	}
	/** Its issuer was revoked at an epoch <= the rotation's: the rotation is void (its key must not be used). */
	function rotIssuerRevoked(r: { from: string; epoch: number }): boolean {
		if (r.from === root?.deviceId || r.from === vault.deviceId) return false;
		const since = trusted.has(r.from) ? (admittedAt.get(r.from) ?? -1) : -1;
		return (revokedIds.get(r.from) ?? []).some((e) => e > since && e <= r.epoch);
	}
	/** Default: issued by the owner or an admin, and every target has a valid signed revocation (epoch <= rotation). */
	async function rotationAuthorized(r: RotRecord): Promise<boolean> {
		if (opts.canRotate) {
			for (const t of r.revoked) if (!(await opts.canRotate(r.from, t))) return false;
			return true;
		}
		const role = r.from === root?.deviceId ? "owner" : trusted.get(r.from)?.role;
		if (role !== "owner" && role !== "admin") return false;
		return r.revoked.every((t) => t !== root?.deviceId && (revokedIds.get(t) ?? []).some((e) => e <= r.epoch));
	}

	async function handleRotate(body: Uint8Array) {
		const m = parseRotate(body);
		if (!m) return;
		const rot = m.rot;
		await ingestRevs(rot.revs);
		const me = vault.deviceId;
		const id = await rotationId(rot);
		if (m.to !== me || rot.from === me || rot.revoked.includes(me) || !rot.to.includes(me)) return coverCheck();
		if (curRot?.id === id || cands.has(id) || rot.epoch < epoch || rotIssuerRevoked(rot)) return coverCheck();
		if (rot.epoch > epoch + MAX_EPOCH_SKIP) {
			// SF1: an admin cannot push everybody to an epoch near an integer edge (or strand them far ahead)
			emit("rejected", { reason: "rotation epoch too far ahead", from: rot.from, epoch: rot.epoch });
			return;
		}
		const fromPub = await peerEcdhPub(rot.from);
		if (!fromPub) return coverCheck();
		const info = { from: rot.from, revoked: rot.revoked, epoch: rot.epoch };
		let newKey: Uint8Array;
		try {
			newKey = await unwrapMeshKey((await ecdhIdentity()).privateKey, fromPub, id, rot.from, me, m.wrap);
		} catch {
			emit("rejected", { reason: "rotation wrap does not authenticate", ...info });
			return;
		}
		if (!(await rotationAuthorized(rot))) {
			emit("rejected", { reason: "rotation not authorized", ...info });
			return;
		}
		cands.set(id, { rec: { ...rot, id }, key: newKey });
		await converge();
	}

	/**
	 * Adopt the best valid rotation we know (highest epoch, then lowest id), then make sure no revoked device holds the
	 * resulting key. Every device applies the same rule to the same set of rotations, so all of them end up on one key.
	 */
	async function converge() {
		// genesis/unknown, or a void current rotation (issuer revoked), loses to any valid rotation of its epoch
		const cur = { epoch, id: curRot && !rotIssuerRevoked(curRot) ? curRot.id : "\uffff" };
		let best: { rec: Rot; key: Uint8Array } | null = null;
		for (const [id, c] of cands) {
			if (c.rec.epoch < epoch || rotIssuerRevoked(c.rec)) {
				if (c.rec.epoch < epoch) cands.delete(id);
				continue;
			}
			if (betterRot(c.rec, best ? best.rec : cur)) best = c;
		}
		if (best) await adopt(best);
		while (cands.size > MAX_CANDIDATES) cands.delete(cands.keys().next().value as string);
		await coverCheck();
	}

	async function adopt(c: { rec: Rot; key: Uint8Array }) {
		const { oldEpoch, oldKey, oldRid } = await switchEpoch(c.key, c.rec.epoch);
		curRot = c.rec;
		await store.set("rot", curRot);
		for (const [id, x] of cands) if (id === c.rec.id || x.rec.epoch < epoch) cands.delete(id);
		if (opts.canRotate) for (const t of c.rec.revoked) forget(t, c.rec.epoch); // hook mode: the rotation is the record
		for (const l of [...links]) if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
		meta.set(OLD_PREFIX + oldRid, { e: oldEpoch, k: b64uEncode(oldKey) });
		void refreshTrust();
		for (const t of c.rec.revoked) emit("revoked", { deviceId: t, epoch });
	}

	/**
	 * Union of concurrent revocations (B4): if the current key went to a device that is now validly revoked (it lost a
	 * tie-break, or its revocation arrived later), or its issuer was revoked, an owner/admin re-keys at epoch + 1.
	 */
	async function coverCheck() {
		if (!running || !root || !curRot) return;
		const me = vault.deviceId;
		const role = selfRole();
		if (!opts.canRotate && role !== "owner" && role !== "admin") return;
		const exposed = new Set(curRot.to.filter((t) => t !== me && isRevoked(t)));
		if (curRot.from !== me && rotIssuerRevoked(curRot)) exposed.add(curRot.from);
		if (opts.canRotate) for (const t of [...exposed]) if (!(await opts.canRotate(me, t))) exposed.delete(t);
		if (exposed.size > 0) await rotate([...exposed], false);
	}

	/** Wraps of stored rotations a straggler (still on the retired room of epoch `from`) is a recipient of, best first. */
	async function storedRotationsFor(deviceId: string, from: number): Promise<RotateMsg[]> {
		const out: Array<RotateMsg & { id: string }> = [];
		for (const k of meta.keys()) {
			if (!k.startsWith(ROTREC_PREFIX)) continue;
			const id = k.slice(ROTREC_PREFIX.length);
			const rot = meta.get(k);
			const wrap = meta.get(`${ROT_PREFIX}${id}:${deviceId}`);
			// SF1: a straggler can only adopt up to MAX_EPOCH_SKIP ahead: serve it in steps; never past our own epoch
			if (!isRotRecord(rot) || rot.epoch < from || rot.epoch > from + MAX_EPOCH_SKIP || rot.epoch > epoch) continue;
			if (typeof wrap !== "string" || !rot.to.includes(deviceId)) continue;
			// SF3: the shared doc is writable by every member: serve only rotations that verify here
			if (id !== (await rotationId(rot)) || !(await servableRotation(rot))) continue;
			out.push({ rot, to: deviceId, wrap, id });
		}
		out.sort((x, y) => (betterRot({ epoch: x.rot.epoch, id: x.id }, { epoch: y.rot.epoch, id: y.id }) ? -1 : 1));
		return out.slice(0, 8).map(({ id: _id, ...msg }) => msg);
	}
	/** SF3: issued by the root or a verified admin that was not void then, cutting off validly revoked devices. */
	async function servableRotation(r: RotRecord): Promise<boolean> {
		if (rotIssuerRevoked(r)) return false;
		if (opts.canRotate) {
			for (const t of r.revoked) if (!(await opts.canRotate(r.from, t))) return false;
			return true;
		}
		const role = r.from === root?.deviceId ? "owner" : r.from === vault.deviceId ? selfRole() : admCache[r.from]?.role;
		if (role !== "owner" && role !== "admin") return false;
		return r.revoked.every((t) => t !== root?.deviceId && (revokedIds.get(t) ?? []).some((e) => e <= r.epoch));
	}

	async function onPairFrame(rec: LinkRec, data: Uint8Array) {
		if (data.length > PAIR_MAX) return reject("pairing message too large"); // S5
		let msg: unknown;
		try {
			msg = JSON.parse(fromUtf8(data.subarray(1)));
		} catch {
			return;
		}
		if (!msg || typeof msg !== "object") return;
		const send = sendPair(rec.link);
		const m = msg as Parameters<HostPairing["handle"]>[0];
		if (hostSession && pairRids.has(rec.rid)) await hostSession.s.handle(m, send);
		else if (guestSession && pairRids.has(rec.rid)) await guestSession.s.handle(m, send);
	}

	const preAuthBudget: ByteBudget = { used: 0, max: PRE_AUTH_TOTAL };

	/** S1: challenge the peer of a fresh data link; data flows once both sides answered each other's challenge. */
	function startHandshake(rec: LinkRec) {
		rec.nonce = randomBytes(NONCE_BYTES);
		rec.hellosOut = 1;
		sendFrame(rec, K_HELLO, rec.nonce).catch(err);
	}
	/** SF4: same challenge again, at most HANDSHAKE_MAX times per link. */
	function resendHello(rec: LinkRec) {
		if (!rec.nonce || rec.authed || rec.closing || (rec.hellosOut ?? 0) >= HANDSHAKE_MAX) return;
		rec.hellosOut = (rec.hellosOut ?? 0) + 1;
		sendFrame(rec, K_HELLO, rec.nonce).catch(err);
	}
	async function answerHello(rec: LinkRec, peerNonce: Uint8Array) {
		rec.answers = (rec.answers ?? 0) + 1;
		rec.authSent = true;
		await sendFrame(rec, K_AUTH, concat(peerNonce, u32(rec.legacy ? rec.legacy.epoch : epoch)));
		maybeStart(rec);
	}
	function maybeStart(rec: LinkRec) {
		if (!rec.authed || !rec.authSent || rec.started || rec.closing) return;
		rec.started = true;
		if (rec.legacy) {
			// retired room (BL1): the peer may be a straggler, or a partition that rotated on its own. Offer it the stored
			// rotations it can unwrap; it converges (and re-keys if needed) and offers us its own the same way. Bounded:
			// once per authenticated link, at most 8 rotations.
			const peer = rec.deviceId as string;
			const lg = rec.legacy;
			void (async () => {
				for (const m of await storedRotationsFor(peer, lg.epoch)) await sendRotate(rec, m);
			})().catch(err);
			return;
		}
		sendFrame(rec, K_SV, Y.encodeStateVector(doc)).catch(err);
		if (awareness.getLocalState()) sendFrame(rec, K_AWARENESS, encodeAwarenessUpdate(awareness, [doc.clientID])).catch(err);
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
		// S5: until the link is authenticated it may reassemble at most 1 MiB, charged to a budget shared by all
		// unauthenticated links; afterwards the configured limit applies
		const reasm = new Reassembler({ maxMessageBytes: PRE_AUTH_MAX, maxPendingBytes: PRE_AUTH_MAX, shared: preAuthBudget });
		rec.lift = () =>
			reasm.setLimits({ maxMessageBytes: opts.maxMessageBytes ?? DEFAULT_MAX_MESSAGE, maxPendingBytes: opts.maxMessageBytes ?? DEFAULT_MAX_MESSAGE, shared: null });
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
			dropHeld(rec);
			links.delete(rec);
			setStatus();
		});
		if (isPair && guestSession) guestSession.s.attach(sendPair(link));
		if (signFrames && (isData || lg || (rid === "" && running))) startHandshake(rec);
		else if (isData || (rid === "" && running)) {
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
	// ECDH(own static key, peer static key) -> HKDF(swal-rotate/v3|rotId|from|to) -> AES-GCM, where rotId hashes the
	// rotation record (epoch, issuer, targets, recipients, nonce). Record and wraps are also stored in meta
	// (rotrec:<rotId>, rot:<rotId>:<deviceId>) so a peer that was offline can fetch its own wrap later through a
	// retired room (see `legacy`); a revoked device has no wrap and cannot unwrap anyone else's.
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
		legacy.delete(dataRid);
		await joinRoom(dataRid, sigKey!);
		return { oldEpoch: old.epoch, oldKey, oldRid };
	}

	async function syncLegacy() {
		if (!running) return;
		for (const k of [...meta.keys()]) {
			if (!k.startsWith(OLD_PREFIX)) continue;
			const v = meta.get(k) as { e?: unknown; k?: unknown } | undefined;
			const e = v?.e;
			if (typeof e !== "number" || !Number.isSafeInteger(e) || e < 0 || e > epoch || typeof v?.k !== "string") continue;
			let raw: Uint8Array;
			try {
				raw = b64uDecode(v.k);
			} catch {
				continue;
			}
			if (raw.length !== 32) continue;
			const rid = await deriveRoomId(raw, appId, topicName, e, instanceId || undefined);
			if (rid === dataRid || (legacy.has(rid) && rooms.has(rid))) continue;
			legacy.set(rid, { epoch: e, rid, material: await deriveDocMaterial(raw, topicName) });
			await joinRoom(rid, await importAesKey(await hkdf(raw, `swal-signal/v1|${topicName}`)));
		}
	}
	meta.observe((ev) => {
		if ([...ev.keysChanged].some((k) => k.startsWith(OLD_PREFIX))) void syncLegacy().catch(err);
	});

	/** Cut `deviceId` off locally from epoch `ep` on (B6: the revocation epoch, no clock). */
	function forget(deviceId: string, ep: number) {
		addRevocation(deviceId, ep);
		trusted.delete(deviceId);
		admittedAt.delete(deviceId);
		void persistRevoked().catch(err);
	}

	/**
	 * Re-key at epoch + 1 for every admitted, non-revoked device except `targets`. `fresh`: a new revocation of the
	 * targets (signed now); otherwise a re-rotation for devices already validly revoked that still hold the key (B4).
	 */
	async function rotate(targets: string[], fresh: boolean) {
		const me = vault.deviceId;
		const newEpoch = epoch + 1;
		if (newEpoch > MAX_EPOCH) throw new Error("epoch limit reached: re-create the mesh");
		const newKey = randomBytes(32);
		const revs: Revocation[] = [];
		for (const t of targets) {
			if (fresh && root) {
				const r = await signRevocation(vault, { mid: root.mid, target: t, by: me, epoch: newEpoch });
				if (await verifyRevocation(chainCtx(root), r)) keepRevRecord(r);
				else revs.push(r); // not valid under the built-in ladder (custom canRotate): still sent, receivers decide
			}
			if (fresh) forget(t, newEpoch);
			revs.push(...(revRecs.get(t) ?? []));
		}
		for (const l of [...links]) if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
		const priv = (await ecdhIdentity()).privateKey;
		const pubs = new Map<string, Uint8Array>();
		for (const d of trusted.values()) {
			if (targets.includes(d.deviceId) || isRevoked(d.deviceId)) continue;
			const pub = await peerEcdhPub(d.deviceId);
			if (pub) pubs.set(d.deviceId, pub);
			else err(new Error(`no verified ECDH key for ${d.deviceId}: it must be re-paired after the rotation`));
		}
		const rec: RotRecord = {
			v: 1,
			epoch: newEpoch,
			from: me,
			revoked: [...targets].sort(),
			to: [...pubs.keys()].sort(),
			n: b64uEncode(randomBytes(16)),
			revs,
		};
		const id = await rotationId(rec);
		const wraps = new Map<string, string>();
		for (const [to, pub] of pubs) wraps.set(to, await wrapMeshKey(priv, pub, id, me, to, newKey));
		// 1) hand each connected recipient ITS OWN wrap (under every recent key), 2) switch, 3) publish under the NEW key
		const sends: Promise<void>[] = [];
		for (const l of [...links]) {
			const w = !l.closing && l.deviceId ? wraps.get(l.deviceId) : undefined;
			if (l.deviceId && w) sends.push(sendRotate(l, { rot: rec, to: l.deviceId, wrap: w }));
		}
		await Promise.all(sends);
		await adopt({ rec: { ...rec, id }, key: newKey });
		doc.transact(() => {
			if (fresh) {
				for (const t of targets) {
					// its admission stays: void from now on (B6), still needed to verify what it signed before
					meta.delete(DEV + t);
					meta.delete(ECDH_PREFIX + t);
				}
			}
			for (const r of revs) meta.set(revKey(r), r);
			meta.set(ROTREC_PREFIX + id, rec);
			for (const [to, w] of wraps) meta.set(`${ROT_PREFIX}${id}:${to}`, w);
		});
	}

	async function revoke(deviceId: string) {
		await ready;
		if (deviceId === vault.deviceId) throw new Error("cannot revoke the current device");
		await refreshTrust();
		if (!meta.has(DEV + deviceId) && !trusted.has(deviceId)) throw new Error("unknown device");
		if (!(await canRotate(vault.deviceId, deviceId))) throw new Error(`not authorized to revoke ${deviceId}`);
		if (!running) await start();
		// cut the revoked device off SYNCHRONOUSLY: its link must not be reachable by anything below
		forget(deviceId, epoch + 1);
		for (const l of [...links]) if (l.deviceId === deviceId) closeRec(l);
		await serialRot(() => rotate([deviceId], true));
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
		const offer = await createPairOffer(vault, { mid: r.mid, root: r.deviceId, appId, topic: topicName, now: now() });
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
					epoch, // B6: valid from this epoch on; a revocation at a later epoch voids it (no clock involved)
					at: now(), // display only
				});
				const dev: Device = { ...guest, addedAt: adm.at, role: guestRole, admittedBy: vault.deviceId };
				const extra = o.extra ? await o.extra(dev) : undefined;
				if (opts.authorizeDevice && !(await opts.authorizeDevice(guest.deviceId, b64uDecode(guest.pub)))) {
					throw new Error("device not authorized by the mesh policy");
				}
				// explicit re-admission: valid because it is issued at an epoch >= every known revocation of the guest
				// (revocation records stay: they keep voiding the OLD admissions, whoever replays them)
				const revs = revokedIds.get(guest.deviceId);
				if (revs?.length && revs[revs.length - 1] > epoch) throw new Error("guest is being revoked: pair it after the rotation");
				admCache[guest.deviceId] = adm;
				trusted.set(guest.deviceId, dev);
				admittedAt.set(guest.deviceId, adm.epoch);
				doc.transact(() => {
					meta.set(ADM_PREFIX + guest.deviceId, adm);
					meta.set(DEV + guest.deviceId, { deviceId: dev.deviceId, pub: dev.pub, name: dev.name, addedAt: dev.addedAt });
				});
				await store.set("adm", admCache);
				return {
					meshKey: b64uEncode(key),
					epoch,
					mid: r.mid,
					hostDevice: selfDevice(),
					root: r,
					admissions: [adm, ...chainOf(vault.deviceId)],
					...(curRot ? { rot: curRot } : {}),
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

	const ROOT_MISMATCH_ERR = "pairing refused: this mesh id is pinned to another owner key";
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
		// S6: trust on first use. The QR (signed by the host) names the root; a device never re-pins another key for
		// a mesh id it already knows
		if (root && root.mid === p.mid && root.deviceId !== p.root) throw new Error(ROOT_MISMATCH_ERR);
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
			if (!isEpoch(g.epoch)) throw new Error("pairing grant: bad epoch");
			const grantAdm = new Map<string, Admission[]>();
			for (const a of g.admissions) grantAdm.set(a?.deviceId, [...(grantAdm.get(a?.deviceId) ?? []), a]);
			const gctx: ChainContext = { vault, root: g.root, epoch: g.epoch, candidates: (id: string) => grantAdm.get(id) ?? [], revokedAt: () => undefined };
			const memo = new Map<string, Promise<Admission | null>>();
			const mine = await verifyChain(gctx, vault.deviceId, memo);
			if (!mine || mine.pub !== b64uEncode(vault.devicePublicKey)) throw new Error("pairing grant: invalid admission for this device");
			const issuer = await verifyChain(gctx, mine.by, memo);
			if (!issuer || issuer.pub !== p.dpk) throw new Error("pairing grant: admission not issued by the paired host");
			if (g.root.mid !== p.mid || g.mid !== p.mid) throw new Error("pairing grant: mesh id does not match the pairing code");
			if (g.root.deviceId !== p.root) throw new Error("pairing grant: trust root does not match the pairing code");
			if (root && root.mid === g.root.mid && (root.deviceId !== g.root.deviceId || root.pub !== g.root.pub))
				throw new Error(ROOT_MISMATCH_ERR);
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
			await vault.setMeshKey(key);
			await persistEpoch(g.epoch);
			epoch = g.epoch;
			// the rotation that produced this key (if any): lets this device take part in tie-breaks of its epoch
			const gr = g.rot as Rot | undefined;
			curRot = isRotRecord(gr) && gr.epoch === g.epoch && gr.id === (await rotationId(gr)) ? gr : null;
			cands.clear();
			await store.set("rot", curRot);
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
