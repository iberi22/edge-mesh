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
	revocationBytes,
	verifyRevocation,
} from "./admission.js";
import { deriveDocMaterial, deriveSenderKey, hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { type ByteBudget, DEFAULT_MAX_FRAME, DEFAULT_MAX_MESSAGE, F_FRAG, Reassembler, fragment } from "./fragment.js";
import {
	type EcdhIdentity,
	type KemIdentity,
	type RotRecord,
	ecdhSignedBytes,
	generateEcdhIdentity,
	isEcdhPublicKey,
	isRotRecord,
	rotationId,
	rotationPreId,
	rotationSigBytes,
	MAX_ROT_MEMBERS,
	wrapsHash,
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
	hostProofBytes,
} from "./pairing.js";
import {
	identityVerify,
	kemEncapsulate,
	kemKeygen,
	ML_DSA_PUBLIC_KEY_BYTES,
	ML_KEM_PUBLIC_KEY_BYTES,
	ML_KEM_SECRET_KEY_BYTES,
} from "./pq.js";
import { derivePairRoomId, deriveRoomId, fingerprint, meshNamespace } from "./rooms.js";
import { type MeshStore, idbStore, memoryStore } from "./store.js";
import type { Device, PeerLink, RtcOptions, SigTransport, VaultClient } from "./types.js";
import { b64uDecode, b64uEncode, bs, concat, equalBytes, fromUtf8, randomBytes, utf8 } from "./util.js";
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
	/**
	 * Rejoin the pinned mesh on start (default true). Pass `false` with a fresh `Y.Doc` to move this device to another
	 * mesh with `pairJoin` while the old one may still be reachable: otherwise the new instance resumes the old mesh
	 * and its doc fills with the old mesh's data, which `pairJoin` then refuses to carry over.
	 */
	resume?: boolean;
	/** A data link whose handshake (S1) has not completed after this long is closed (note 9). Default 120 s. */
	handshakeTimeoutMs?: number;
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
	/**
	 * Revoke a device: its writes and links are cut at once. Only owner devices re-key the mesh; after an admin's
	 * revocation `rekeyPending` stays true until an owner device is online and has re-keyed (UI: "pendiente de que el
	 * dueño se conecte"): until then the revoked device still holds the current mesh key.
	 */
	revoke(deviceId: string): Promise<void>;
	/** A known revocation has not been followed by an owner re-key yet (the revoked device may still read new data). */
	readonly rekeyPending: boolean;
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
/** finding 4: bytes of bulk data waiting for one link beyond the message in progress (then the link is closed) */
const MAX_OUTSTANDING = 16 * 1024 * 1024;
/** SF4: per link, at most this many challenges sent and answered */
const HANDSHAKE_MAX = 8;
/** frames kept per link while waiting for the peer's K_AUTH (also bounded by PRE_AUTH_MAX bytes) */
const EARLY_MAX_FRAMES = 32;
/** Replay window per sender session: seqs at most this far behind the highest one are still accepted once. */
const REPLAY_WINDOW = 1024;
const ORIGIN = Symbol("swal-mesh");
const DEV = "dev/"; // dev/<deviceId> = Device (informative only: trust comes from adm/)
const ADM_PREFIX = "adm/"; // adm/<deviceId> = Admission signed by an owner/admin, verified against the local root pin
const REV_PREFIX = "rev/"; // rev/<deviceId>:<epoch> = Revocation signed by the revoker (H4: replicated + persisted locally)
const revKey = (r: { target: string; epoch: number }) => `${REV_PREFIX}${r.target}:${r.epoch}`;
/** local store: every signed revocation record kept (the revoked set is recomputed from them) */
const REVRECORDS_KEY = "revrecords";
/** local store: cuts not backed by a built-in-valid record (custom `canRotate` hook) */
const LOCALCUTS_KEY = "localcuts";
/**
 * R4-B1: pending revocation REQUESTS are bounded per issuer (an admin cannot crowd out anybody else's records); beyond
 * the cap the issuer's newest are set aside (and retried once the owner executes some). EXECUTED revocations (by the
 * owner, or cut by an adopted owner rotation) are kept for good as compact tombstones (`executed`), never evicted.
 */
const MAX_PENDING_PER_ISSUER = 64;
/** Revocation records a rotation carries and a receiver reads (R4-B2: the same bound on both ends). */
const REVS_CARRIED = 16;
/** Full records of executed revocations kept to carry/republish; the fact itself lives on in the tombstones. */
const MAX_SETTLED_RECORDS = 256;
/** local store: executed revocations, deviceId -> [[epoch, record hash ("" if cut by a rotation alone)]] */
const EXECUTED_KEY = "revexecuted";
/** A hybrid wrap is base64url(ML-KEM-768 ciphertext 1088 B || AES-GCM(32 B) 60 B) = 1531 characters. */
const MAX_WRAP_CHARS = 1600;
const KEX_KEY = "kex"; // device-local store: verified key-agreement keys (the pre-PQC "ecdh" entry is ignored)
const ECDH_PREFIX = "ecdh/"; // ecdh/<deviceId> = { pub, kem, sig }: P-256 + ML-KEM-768 keys, sig by the ML-DSA identity
const ROTREC_PREFIX = "rotrec:"; // rotrec:<rotId> = RotRecord (public part of a rotation, same for every recipient)
const ROT_PREFIX = "rot:"; // rot:<rotId>:<deviceId> = that rotation's new key, wrapped pairwise for deviceId
/** SF5: retired keys this device itself held, kept in its LOCAL store (never read from the shared doc) */
const RETIRED_KEY = "retired";
const MAX_RETIRED = 16;
/** Retired keys tried on (and used to seal) rotation frames, so devices on another branch/epoch still get them. */
const RETIRED_TRY = 4;
const MAX_CANDIDATES = 16;

/** K_ROTATE body: the shared rotation record plus the recipient's own pairwise wrap. */
interface RotateMsg {
	rot: RotRecord;
	to: string;
	wrap: string;
	/**
	 * Every recipient's pairwise wrap (each opens only for its addressee): lets any device that adopted the rotation
	 * relay it to recipients the issuer has no link to (partial topologies, healed partitions).
	 */
	wraps?: Record<string, string>;
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
	/** SF4: some held frame of this link was dropped (expired / caps): its handshake may need to be redone */
	lostHeld?: boolean;
	/** frames that arrived before we authenticated the peer (its state-vector pull may race our K_AUTH): replayed after */
	early?: { frames: Uint8Array[]; bytes: number };
	/** a key the peer demonstrably holds (its last handshake frame came under it): rotations are also sealed under it */
	common?: { material: Uint8Array; rid: string; epoch: number };
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
	const localNum = (x: unknown) => (isEpoch(x) ? x : 0); // SF1: an out-of-range local value is ignored
	let status: MeshStatus = "off";
	const links = new Set<LinkRec>();
	// per-sender AES-GCM keys, cached PER KEY MATERIAL (never by epoch number: two meshes, or two concurrent
	// rotations, can share an epoch number). Reset by loadKeys (B3).
	let senderKeys = new WeakMap<Uint8Array, Map<string, Promise<CryptoKey>>>();
	// deviceId -> epochs of its valid revocations (B6: epochs, never clocks). DERIVED: recomputed from every known
	// revocation record (`revStore`) in epoch order, so a record that is no longer valid drops out (round 3, B2)
	const revokedIds = new Map<string, number[]>();
	// every signed revocation record seen (shared doc, owner rotations, own), keyed by the hash of the whole record
	const revStore = new Map<string, Revocation>();
	/** R4-B1: executed revocations (tombstones): permanent, independent of the bounded pool of requests */
	const executed = new Map<string, Array<[number, string]>>();
	/** requests set aside because their issuer is over its cap (retried when the owner executes some) */
	const overCap = new Set<string>();
	// local cuts that are not backed by a record valid under the built-in ladder (custom `canRotate` hook)
	const localCuts = new Map<string, number[]>();
	const store: MeshStore =
		opts.store ??
		vault.store ??
		(opts.persist === "idb" && typeof indexedDB !== "undefined" ? idbStore(`swal-mesh-local/${appId}/${topicName}`) : memoryStore());
	let root: TrustRoot | null = null;
	let admCache: Record<string, Admission> = {}; // verified admissions: survive tampering with the shared doc
	// `${deviceId}|${identityPub}` -> verified key-agreement keys (ECDH P-256 + ML-KEM-768, base64url)
	let ecdhOk: Record<string, { pub: string; kem: string }> = {};
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
	let kemId: KemIdentity | null = null;
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
	// a device revoked a moment ago is never listed, even before the trust state is recomputed
	const devices = (): Device[] =>
		[selfDevice(), ...[...trusted.values()].filter((d) => !isRevoked(d.deviceId))].sort((a, b) => a.addedAt - b.addedAt);
	const roleOf = (id: string): Role | null =>
		id === vault.deviceId ? selfRole() : isRevoked(id) ? null : (trusted.get(id)?.role ?? null);
	/** H2: rotation/revocation only from an authorized issuer. A target that is not admitted counts as a member. */
	const canRotate = async (issuer: string, target: string): Promise<boolean> => {
		if (opts.canRotate) return Boolean(await opts.canRotate(issuer, target));
		const ir = roleOf(issuer);
		const tr = target === root?.deviceId ? "owner" : (roleOf(target) ?? "member");
		return ir !== null && canRevokeRole(ir, tr);
	};
	// signature checks of trust records (admissions, revocations) are memoized: they are re-evaluated often
	const sigMemo = new Map<string, Promise<boolean>>();
	// ML-DSA-65 verification (AGENTS.md §2) is ~2 ms: memoize it for the chain checks, which repeat
	const memoVerify = (pub: Uint8Array, data: Uint8Array, sig: Uint8Array): Promise<boolean> => {
		const k = `${b64uEncode(pub)}|${b64uEncode(sig)}|${b64uEncode(data)}`;
		let p = sigMemo.get(k);
		if (!p) {
			if (sigMemo.size >= 8192) sigMemo.clear();
			p = Promise.resolve(identityVerify(pub, data, sig));
			sigMemo.set(k, p);
		}
		return p;
	};
	const chainCtx = (r: TrustRoot): ChainContext => ({
		verify: memoVerify,
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
	const persistRevoked = async () => {
		await store.set(REVRECORDS_KEY, [...revStore.values()]);
		await store.set(EXECUTED_KEY, Object.fromEntries(executed));
		await store.set(LOCALCUTS_KEY, Object.fromEntries(localCuts));
	};
	const recHash = async (r: Revocation) =>
		b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", bs(utf8(JSON.stringify([r.v, r.mid, r.target, r.by, r.epoch, r.sig]))))));
	/** Records that can never count (malformed for this mesh, or a bad signature by a known issuer), by RECORD hash (B1). */
	const badRevs = new Set<string>();
	/**
	 * Keep a signed revocation record if its issuer is the root or a verified admission and the signature verifies.
	 * Whether it COUNTS is decided by recomputeRevoked (issuer valid as of the epoch before, role ladder).
	 */
	async function addRecord(x: unknown): Promise<boolean> {
		if (!root || !isRevocation(x)) return false;
		const r: Revocation = { v: x.v, mid: x.mid, target: x.target, by: x.by, epoch: x.epoch, sig: x.sig };
		const h = await recHash(r);
		if (revStore.has(h) || badRevs.has(h) || overCap.has(h)) return false;
		const bad = () => {
			if (badRevs.size >= 4096) badRevs.clear();
			badRevs.add(h);
			return false;
		};
		if (r.mid !== root.mid || r.target === root.deviceId || r.by === r.target || !isDeviceId(r.target)) return bad();
		const pub = r.by === root.deviceId ? root.pub : admCache[r.by]?.pub;
		if (!pub) return false; // issuer not known (yet): not cached, the record comes back with the doc
		const { sig, ...body } = r;
		let ok = false;
		try {
			ok = await memoVerify(b64uDecode(pub), revocationBytes(body), b64uDecode(sig));
		} catch {}
		if (!ok) return bad();
		revStore.set(h, r);
		if (r.by === root.deviceId) settleRevocation(r.target, r.epoch, h); // the owner's own decision: final
		if (!boundRecords(r.by, h)) return false;
		// note V2: republish what we verified, so devices that never saw where it came from learn it too
		if (!meta.has(revKey(r))) meta.set(revKey(r), r);
		return true;
	}
	const isSettled = (r: Revocation) => (executed.get(r.target) ?? []).some(([e]) => e === r.epoch);
	/**
	 * R4-B1: bound the pool. An issuer keeps at most MAX_PENDING_PER_ISSUER unexecuted requests (its newest beyond that
	 * are set aside); executed records beyond MAX_SETTLED_RECORDS leave the pool (their tombstone stays). Never evicts
	 * an unexecuted request of another issuer. Returns whether `h` is still in the pool.
	 */
	function boundRecords(issuer: string, h: string): boolean {
		const mine = [...revStore.entries()].filter(([, x]) => x.by === issuer && !isSettled(x));
		while (issuer !== root?.deviceId && mine.length > MAX_PENDING_PER_ISSUER) {
			let k = 0; // the newest: highest epoch, latest arrival on ties
			for (let i = 1; i < mine.length; i++) if ((mine[i] as [string, Revocation])[1].epoch >= (mine[k] as [string, Revocation])[1].epoch) k = i;
			const [drop] = mine.splice(k, 1)[0] as [string, Revocation];
			revStore.delete(drop);
			overCap.add(drop);
		}
		const settled = [...revStore.entries()].filter(([, x]) => isSettled(x));
		if (settled.length > MAX_SETTLED_RECORDS) {
			settled.sort((x, y) => x[1].epoch - y[1].epoch);
			for (const [k] of settled.slice(0, settled.length - MAX_SETTLED_RECORDS)) revStore.delete(k);
		}
		return revStore.has(h);
	}
	/**
	 * R4-B1: record an executed revocation for good (compact: epoch + record hash), unpin the device's key-agreement keys
	 * (nothing is ever wrapped for it again, whatever the pool of requests holds), and let requests set aside retry.
	 */
	function settleRevocation(target: string, ep: number, h: string): boolean {
		const l = executed.get(target) ?? [];
		if (l.some(([e]) => e === ep)) return false;
		executed.set(target, [...l, [ep, h] as [number, string]].sort((x, y) => x[0] - y[0]).slice(-64));
		const pins = Object.keys(ecdhOk).filter((k) => k.startsWith(`${target}|`));
		if (pins.length) {
			ecdhOk = Object.fromEntries(Object.entries(ecdhOk).filter(([k]) => !pins.includes(k)));
			void store.set(KEX_KEY, ecdhOk);
		}
		overCap.clear();
		return true;
	}
	/**
	 * B2: the revoked set is a pure function of the known records. Records are evaluated in epoch order: one of epoch R
	 * counts if its issuer was valid as of R - 1 given the records of earlier epochs (and the ladder allowed it). So a
	 * revocation signed by an admin that was itself revoked before, learned only later, drops out again.
	 */
	async function recomputeRevoked(): Promise<boolean> {
		if (!root) return false;
		const acc = new Map<string, number[]>();
		const add = (id: string, ep: number) => {
			const l = acc.get(id) ?? [];
			if (!l.includes(ep)) acc.set(id, [...l, ep].sort((x, y) => x - y).slice(-64));
		};
		for (const [id, eps] of localCuts) for (const e of eps) add(id, e);
		for (const [id, eps] of executed) for (const [e] of eps) add(id, e);
		const ctx: ChainContext = { ...chainCtx(root), revokedAt: (id) => acc.get(id) };
		const recs = [...revStore.values()].sort((x, y) => x.epoch - y.epoch);
		const nextRecs = new Map<string, Revocation[]>();
		for (let i = 0; i < recs.length; ) {
			const ep = (recs[i] as Revocation).epoch;
			const group: Revocation[] = [];
			while (i < recs.length && (recs[i] as Revocation).epoch === ep) group.push(recs[i++] as Revocation);
			const memo = new Map<string, Promise<Admission | null>>();
			const ok: Revocation[] = [];
			for (const r of group) if (await verifyRevocation(ctx, r, memo)) ok.push(r);
			for (const r of ok) {
				add(r.target, r.epoch);
				nextRecs.set(r.target, [...(nextRecs.get(r.target) ?? []), r].slice(-4));
			}
		}
		revRecs.clear();
		for (const [k, v] of nextRecs) revRecs.set(k, v);
		const same =
			acc.size === revokedIds.size && [...acc].every(([k, v]) => JSON.stringify(v) === JSON.stringify(revokedIds.get(k)));
		if (same) return false;
		revokedIds.clear();
		for (const [k, v] of acc) revokedIds.set(k, v);
		return true;
	}
	/** After the revoked set changed: cut links, persist, and (owner) re-key. */
	async function applyRevoked() {
		await persistRevoked();
		for (const l of [...links]) if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
		void serialRot(ownerRekey).catch(err);
	}
	/** A device is cut off if revoked and not re-admitted afterwards (an admission issued at or after the revocation epoch). */
	const isRevoked = (id: string) => {
		const revs = revokedIds.get(id);
		if (!revs?.length) return false;
		return !(trusted.has(id) && (admittedAt.get(id) ?? -1) >= revs[revs.length - 1]);
	};
	async function computeTrust() {
		// 1) signed revocation records replicated in the doc; the revoked set is recomputed from all known records
		if (root) {
			for (const k of meta.keys()) {
				if (!k.startsWith(REV_PREFIX)) continue;
				const r = meta.get(k) as Revocation;
				if (isRevocation(r) && k === revKey(r)) await addRecord(r);
			}
			if (await recomputeRevoked()) await applyRevoked();
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
		if (vault.devicePublicKey.length !== ML_DSA_PUBLIC_KEY_BYTES)
			throw new Error("vault.devicePublicKey must be an ML-DSA-65 public key (1952 bytes; ECDSA identities are no longer accepted)");
		if (!(await idMatchesPub(vault.deviceId, b64uEncode(vault.devicePublicKey)))) {
			throw new Error("vault.deviceId must be deviceIdOf(vault.devicePublicKey)");
		}
		const r = (await store.get("root")) as TrustRoot | undefined;
		if (r && typeof r.deviceId === "string" && typeof r.pub === "string" && typeof r.mid === "string") root = r;
		admCache = ((await store.get("adm")) as Record<string, Admission> | undefined) ?? {};
		const recs = (await store.get(REVRECORDS_KEY)) as unknown[] | undefined;
		for (const r of Array.isArray(recs) ? recs : []) if (isRevocation(r)) revStore.set(await recHash(r), r);
		const ex = (await store.get(EXECUTED_KEY)) as Record<string, unknown> | undefined;
		for (const [id, eps] of Object.entries(ex ?? {})) {
			if (!isDeviceId(id) || !Array.isArray(eps)) continue;
			const ok = eps.filter((x): x is [number, string] => Array.isArray(x) && isEpoch(x[0]) && typeof x[1] === "string");
			if (ok.length) executed.set(id, ok.slice(-64));
		}
		const lc = (await store.get(LOCALCUTS_KEY)) as Record<string, unknown> | undefined;
		for (const [id, eps] of Object.entries(lc ?? {})) {
			if (Array.isArray(eps)) localCuts.set(id, eps.filter((e) => isEpoch(e) && e >= 1) as number[]);
		}
		const cr = (await store.get("rot")) as Rot | undefined;
		if (isRotRecord(cr) && typeof cr.id === "string" && cr.id === (await rotationId(cr))) curRot = cr;
		ecdhOk = ((await store.get(KEX_KEY)) as typeof ecdhOk | undefined) ?? {};
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
		epoch = Math.max(localNum(await vault.getEpoch?.()), localNum(await store.get("epoch")), epoch); // known before start
		// already paired: resume (unless the app is about to move this device to another mesh, see `resume`)
		if (opts.resume !== false && root && trusted.size > 0 && !destroyed) await start();
	})();
	ready.catch(err);

	// ---- pairwise ECDH identity (rotation wraps) ----
	async function ecdhIdentity(): Promise<EcdhIdentity> {
		return (ecdhId ??= (await vault.getEcdhIdentity?.()) ?? (await generateEcdhIdentity()));
	}
	async function kemIdentity(): Promise<KemIdentity> {
		if (!kemId) {
			const k = (await vault.getKemIdentity?.()) ?? kemKeygen();
			if (k.publicKey.length !== ML_KEM_PUBLIC_KEY_BYTES || k.secretKey.length !== ML_KEM_SECRET_KEY_BYTES)
				throw new Error("vault.getKemIdentity must return an ML-KEM-768 key pair");
			kemId = k;
		}
		return kemId;
	}
	async function publishEcdh() {
		const id = await ecdhIdentity();
		const pub = b64uEncode(id.publicKey);
		const kem = b64uEncode((await kemIdentity()).publicKey);
		const cur = meta.get(ECDH_PREFIX + vault.deviceId) as { pub: string; kem?: string } | undefined;
		if (cur?.pub === pub && cur.kem === kem) return;
		const sig = b64uEncode(await vault.sign(ecdhSignedBytes(vault.deviceId, pub, kem)));
		meta.set(ECDH_PREFIX + vault.deviceId, { pub, kem, sig });
	}
	/**
	 * ECDH public key of an ADMITTED device, verified against the identity key from its admission (never against
	 * the self-declared dev/<id> entry). A key verified once is remembered, so tampering with meta cannot swap it.
	 */
	async function peerEcdhPub(deviceId: string): Promise<{ pub: Uint8Array; kem: Uint8Array } | null> {
		const idPub = trusted.get(deviceId)?.pub;
		if (!idPub) return null;
		const slot = `${deviceId}|${idPub}`;
		const e = meta.get(ECDH_PREFIX + deviceId) as { pub: string; kem: string; sig: string } | undefined;
		const cur = ecdhOk[slot];
		if (
			e &&
			typeof e.pub === "string" &&
			typeof e.kem === "string" &&
			typeof e.sig === "string" &&
			(e.pub !== cur?.pub || e.kem !== cur?.kem)
		) {
			try {
				const kem = b64uDecode(e.kem);
				if (
					kem.length === ML_KEM_PUBLIC_KEY_BYTES &&
					(await isEcdhPublicKey(b64uDecode(e.pub))) &&
					identityVerify(b64uDecode(idPub), ecdhSignedBytes(deviceId, e.pub, e.kem), b64uDecode(e.sig))
				) {
					// FIPS 203 input check (modulus) once, here, like the P-256 point check above: a member must not be able
					// to break the owner's re-keying by vouching for a malformed key (wrapping would throw on it)
					kemEncapsulate(kem);
					ecdhOk = { ...ecdhOk, [slot]: { pub: e.pub, kem: e.kem } };
					await store.set(KEX_KEY, ecdhOk);
				}
			} catch {}
		}
		const k = ecdhOk[slot];
		return k ? { pub: b64uDecode(k.pub), kem: b64uDecode(k.kem) } : null;
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
	const outBytes = new WeakMap<PeerLink, number>(); // finding 4: bytes accepted for a link, not handed over yet
	function sendBytes(link: PeerLink, bytes: Uint8Array, alive: () => boolean = () => true): Promise<void> {
		const pending = outBytes.get(link) ?? 0;
		// finding 4: a peer that drains far slower than we produce must not make us buffer without bound. A single
		// message of any size (up to maxMessageBytes) may wait alone; beyond MAX_OUTSTANDING of backlog the link is
		// closed (the peer resyncs from state vectors when it reconnects).
		if (pending > 0 && pending + bytes.length > MAX_OUTSTANDING) {
			err(new Error(`link ${link.id}: more than ${MAX_OUTSTANDING} bytes waiting for a slow peer: closing it`));
			for (const r of [...links]) if (r.link === link) closeRec(r);
			try {
				link.close();
			} catch {}
			return Promise.resolve();
		}
		outBytes.set(link, pending + bytes.length);
		const next = (outQ.get(link) ?? Promise.resolve())
			.then(async () => {
				try {
					if (!alive()) return;
					for (const f of await fragment(bytes, maxFrame)) {
						if (link.drain) await link.drain(); // BL3: paced by the peer instead of piling up in memory
						if (!alive()) return;
						link.send(f);
					}
				} finally {
					outBytes.set(link, Math.max(0, (outBytes.get(link) ?? 0) - bytes.length));
				}
			})
			.catch(err);
		outQ.set(link, next);
		return next;
	}
	/**
	 * finding 4: control frames (rotations, link handshake) never wait behind bulk data nor on drain(): handed to the
	 * link at once (`sendPriority` puts them at the next message boundary of the link's own queue when it has one).
	 */
	async function sendPriority(link: PeerLink, bytes: Uint8Array) {
		for (const f of await fragment(bytes, maxFrame)) (link.sendPriority ?? link.send).call(link, f);
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
	const retiredKeys = (n = RETIRED_TRY) => [...legacy.values()].sort((x, y) => y.epoch - x.epoch).slice(0, n);
	/** A rotation frame must reach peers still on the previous key or on a concurrent branch: seal it under each. */
	async function sendRotate(rec: LinkRec, msg: RotateMsg) {
		const body = utf8(JSON.stringify(msg));
		if (rec.legacy) return sendFrameWith(rec, K_ROTATE, body, rec.legacy.material, rec.legacy.rid, true);
		await sendFrameWith(rec, K_ROTATE, body, docMat, dataRid, true);
		const recent = retiredKeys();
		for (const r of recent) await sendFrameWith(rec, K_ROTATE, body, r.material, r.rid, true);
		// a key this peer is known to hold, if it is neither our current one nor among the recent ones above
		const c = rec.common;
		if (c && c.rid !== dataRid && !recent.some((r) => r.rid === c.rid)) await sendFrameWith(rec, K_ROTATE, body, c.material, c.rid, true);
	}
	async function sendFrameWith(
		rec: LinkRec,
		kind: number,
		body: Uint8Array,
		mat: Uint8Array | null,
		rid: string,
		priority = false,
	) {
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
		const frame = concat(new Uint8Array([signFrames ? F_SDATA : F_DATA, id.length]), id, sealed);
		if (priority) return sendPriority(rec.link, frame);
		await sendBytes(rec.link, frame, () => !rec.closing);
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
		if (heldTotal + data.length > HOLD_TOTAL_BYTES) {
			rec.lostHeld = true; // S5: global cap (the sender resyncs later; SF4 re-challenges the link)
			return;
		}
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
			rec.lostHeld = true;
		}
	}
	/** Re-run held frames once the trust state changed (a pending admission may have arrived). */
	function replayHeld() {
		for (const rec of links) {
			const h = rec.held;
			if (!h || rec.closing) continue;
			dropHeld(rec);
			for (const f of h.frames) {
				if (now() - f.t > HOLD_MS) {
					rec.lostHeld = true;
					continue;
				}
				rec.chain = rec.chain.then(() => onData(rec, f.d)).catch(err);
			}
		}
		// SF4: a link that lost held frames (expired or over the caps) may have lost its handshake: challenge again
		if (signFrames) {
			for (const rec of links) {
				if (!rec.lostHeld || rec.authed || rec.rid === "pair") continue;
				rec.lostHeld = false;
				resendHello(rec);
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
		const tries: Array<{ material: Uint8Array | null; rid: string; epoch: number }> = lg
			? [lg]
			: [{ material: docMat, rid: dataRid, epoch }, ...retiredKeys(MAX_RETIRED)];
		let plain: Uint8Array | null = null;
		let rid = "";
		let retired = false;
		let via: { material: Uint8Array; rid: string; epoch: number } | null = null; // the key this frame came under
		for (let i = 0; i < tries.length && !plain; i++) {
			const t = tries[i];
			if (!t.material) continue;
			try {
				plain = await openUpdate(await senderKey(t.material, sender), data.subarray(2 + idLen), `${t.rid}|${sender}`);
				rid = t.rid;
				retired = i > 0;
				via = { material: t.material, rid: t.rid, epoch: t.epoch };
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
			if (revoked) return; // a revoked device is never listened to (its revocation requests travel as doc records)
			const pub = trusted.get(sender)?.pub;
			if (!pub) return;
			let ok = false;
			try {
				ok = identityVerify(b64uDecode(pub), frameSigBytes(rid, sender, kind, sessBytes, seq, body), sig);
			} catch {}
			if (!ok) return reject("bad frame signature", sender);
			if (rec.closing) return;
			// S1: a link carries nothing but its handshake until the peer signed OUR fresh challenge on it
			// the handshake may arrive under one of our recent retired keys (a key switch raced with it, or the peer is on
			// another branch): it is then bound to THAT key's room and epoch, and answered under the same key
			if (kind === K_HELLO) {
				if (body.length !== NONCE_BYTES || !via) return;
				rec.common = via;
				rec.hellosIn = (rec.hellosIn ?? 0) + 1;
				if ((rec.answers ?? 0) < HANDSHAKE_MAX) await answerHello(rec, body, sender, via);
				// SF4: a repeated challenge means our earlier messages may have been lost (e.g. held and expired while
				// the peer was not yet admitted here): challenge again too
				if (rec.hellosIn > 1 && !rec.authed) resendHello(rec);
				return;
			}
			if (kind === K_AUTH) {
				if (rec.authed || !rec.nonce || !via) return;
				const ep = via.epoch;
				const okAuth =
					body.length > NONCE_BYTES + 4 &&
					equalBytes(body.subarray(0, NONCE_BYTES), rec.nonce) &&
					new DataView(body.buffer, body.byteOffset + NONCE_BYTES, 4).getUint32(0, false) === ep &&
					fromUtf8(body.subarray(NONCE_BYTES + 4)) === vault.deviceId;
				if (!okAuth) return reject("bad link authentication", sender);
				rec.common = via;
				rec.deviceId = sender;
				rec.authed = true;
				rec.peerSess = sess;
				rec.lift?.();
				setStatus();
				const early = rec.early?.frames ?? [];
				rec.early = undefined;
				for (const f of early) rec.chain = rec.chain.then(() => onData(rec, f)).catch(err);
				return maybeStart(rec);
			}
			if (!rec.authed) {
				// the peer authenticated us first and already talks: keep a few frames until its K_AUTH reaches us
				if (!rec.early) rec.early = { frames: [], bytes: 0 };
				const e = rec.early;
				if (e.frames.length < EARLY_MAX_FRAMES && e.bytes + data.length <= PRE_AUTH_MAX) {
					e.frames.push(data);
					e.bytes += data.length;
				}
				return;
			}
			if (sess !== rec.peerSess || !freshSeq(sender, sess, seq)) return; // replay / other link
		} else if (revoked) return;
		if (retired) {
			if (kind === K_ROTATE) await serialRot(() => handleRotate(body));
			// (d) an authenticated peer still talks under one of our retired keys: it missed a rotation. Offer it the
			// stored rotations from that key's epoch (once per link and current rotation).
			else if (via && rec.authed) offerRotations(rec, sender, via.epoch);
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
			if (!m || !isRotRecord(m.rot) || typeof m.to !== "string" || typeof m.wrap !== "string" || m.wrap.length > MAX_WRAP_CHARS)
				return null;
			const w = m.wraps;
			const okWraps =
				w === undefined ||
				(typeof w === "object" &&
					w !== null &&
					!Array.isArray(w) &&
					Object.entries(w).every(([k, v]) => m.rot.to.includes(k) && typeof v === "string" && v.length <= MAX_WRAP_CHARS));
			return okWraps ? m : null;
		} catch {
			return null;
		}
	}
	/** Its issuer is not the owner, or was revoked at an epoch <= the rotation's: the rotation is void. */
	function rotIssuerRevoked(r: { from: string; epoch: number }): boolean {
		return r.from !== root?.deviceId;
	}
	/** The owner's ML-DSA-65 signature over the rotation id (memoized: relays repeat the same record). */
	const rotSigOk = new Map<string, boolean>();
	function rotationSigned(r: RotRecord, id: string): boolean {
		if (!root || r.from !== root.deviceId || typeof r.sig !== "string") return false;
		const k = `${id}|${r.sig}`;
		let ok = rotSigOk.get(k);
		if (ok === undefined) {
			try {
				ok = identityVerify(b64uDecode(root.pub), rotationSigBytes(id), b64uDecode(r.sig));
			} catch {
				ok = false;
			}
			if (rotSigOk.size >= 1024) rotSigOk.clear();
			rotSigOk.set(k, ok);
		}
		return ok;
	}
	/**
	 * R4-B2: the owner decides who a rotation cuts off. Only owner devices re-key and every rotation carries the owner's
	 * ML-DSA-65 signature over its id (record + wraps, checked before this), so its cut list is authoritative: a receiver
	 * never needs to have seen the revocation records behind it (an offline member may never get them: the retired room
	 * does not sync the doc). Records a rotation carries (`revs`, at most REVS_CARRIED) are only learned. A custom
	 * `canRotate` hook still vets every target.
	 */
	async function rotationAuthorized(r: RotRecord): Promise<boolean> {
		if (r.from !== root?.deviceId || r.revoked.includes(root.deviceId)) return false;
		if (opts.canRotate) {
			for (const t of r.revoked) if (!(await opts.canRotate(r.from, t))) return false;
		}
		return true;
	}

	async function handleRotate(body: Uint8Array) {
		const m = parseRotate(body);
		if (!m) return;
		const rot = m.rot;
		// round 3: only the owner (the mesh root) re-keys. Anything else is rejected before any of it is processed.
		if (!root || rot.from !== root.deviceId) {
			emit("rejected", { reason: "rotation not from the owner", from: rot.from, epoch: rot.epoch });
			return;
		}
		const id = await rotationId(rot);
		if (!rotationSigned(rot, id)) {
			emit("rejected", { reason: "rotation signature invalid", from: rot.from, epoch: rot.epoch });
			return;
		}
		let added = false;
		for (const r of rot.revs.slice(0, REVS_CARRIED)) added = (await addRecord(r)) || added;
		if (added && (await recomputeRevoked())) await applyRevoked();
		const me = vault.deviceId;
		// finding 5: a wrap map is used (relayed) only if it is exactly the set the owner committed to
		const mapOk = m.wraps !== undefined && (await wrapsHash(m.wraps)) === rot.wh;
		if (curRot?.id === id) {
			if (mapOk && m.wraps) relayRotation(curRot, m.wraps); // a good copy after a corrupted one still goes on
			return;
		}
		if (m.to !== me || rot.from === me || rot.revoked.includes(me) || !rot.to.includes(me)) return;
		if (cands.has(id) || rot.epoch < epoch) return;
		if (rot.epoch > epoch + MAX_EPOCH_SKIP) {
			// SF1: nobody is pushed to an epoch near an integer edge (or stranded far ahead)
			emit("rejected", { reason: "rotation epoch too far ahead", from: rot.from, epoch: rot.epoch });
			return;
		}
		const fromPub = await peerEcdhPub(rot.from);
		if (!fromPub) return;
		const info = { from: rot.from, revoked: rot.revoked, epoch: rot.epoch };
		let newKey: Uint8Array;
		try {
			newKey = await unwrapMeshKey(
				(await ecdhIdentity()).privateKey,
				(await kemIdentity()).secretKey,
				fromPub.pub,
				await rotationPreId(rot),
				rot.from,
				me,
				m.wrap,
			);
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
		if (curRot?.id === id) {
			if (mapOk && m.wraps) relayRotation(curRot, m.wraps);
			else void relayFromMeta(); // corrupted or missing map: relay once the owner's own wraps are in meta
		}
	}
	/** Relay the current rotation with the wrap set stored in meta (written by the owner), if it matches `wh`. */
	async function relayFromMeta() {
		const cur = curRot;
		if (!cur) return;
		const wraps: Record<string, string> = {};
		for (const t of cur.to) {
			const w = meta.get(`${ROT_PREFIX}${cur.id}:${t}`);
			if (typeof w !== "string") return;
			wraps[t] = w;
		}
		if ((await wrapsHash(wraps)) === cur.wh && curRot?.id === cur.id) relayRotation(cur, wraps);
	}
	meta.observe((ev) => {
		const cur = curRot;
		if (cur && [...ev.keysChanged].some((k) => k.startsWith(`${ROT_PREFIX}${cur.id}:`))) void relayFromMeta().catch(err);
	});
	const offered = new Set<string>();
	function offerRotations(rec: LinkRec, peer: string, from: number) {
		const k = `${curRot?.id ?? epoch}|${peer}|${from}`;
		if (offered.has(k)) return;
		if (offered.size >= 4096) offered.clear();
		offered.add(k);
		void (async () => {
			for (const m of await storedRotationsFor(peer, from)) await sendRotate(rec, m);
		})().catch(err);
	}
	/** Relayed (rotation, peer) pairs: each adopted rotation is passed on at most once per peer. */
	const relayed = new Set<string>();
	/** Hand an adopted rotation to connected recipients (the owner may have no link to them). */
	function relayRotation(rot: Rot, wraps: Record<string, string>) {
		for (const l of [...links]) {
			const p = l.deviceId;
			if (!p || l.closing || p === rot.from || p === vault.deviceId || !rot.to.includes(p) || !wraps[p]) continue;
			const k = `${rot.id}|${p}`;
			if (relayed.has(k)) continue;
			if (relayed.size >= 4096) relayed.clear();
			relayed.add(k);
			const { id: _id, ...rec } = rot;
			sendRotate(l, { rot: rec, to: p, wrap: wraps[p], wraps }).catch(err);
		}
	}

	/**
	 * Adopt the best valid rotation we know (highest epoch, then lowest id). Only owner-identity devices issue them, so
	 * concurrency only exists between devices of the owner; every device applies the same rule to the same set.
	 */
	async function converge() {
		const cur = { epoch, id: curRot ? curRot.id : "\uffff" }; // genesis/unknown loses to any rotation of its epoch
		let best: { rec: Rot; key: Uint8Array } | null = null;
		for (const [id, c] of cands) {
			if (c.rec.epoch < epoch) {
				cands.delete(id);
				continue;
			}
			if (betterRot(c.rec, best ? best.rec : cur)) best = c;
		}
		if (best) await adopt(best);
		while (cands.size > MAX_CANDIDATES) cands.delete(cands.keys().next().value as string);
		await ownerRekey();
	}

	async function adopt(c: { rec: Rot; key: Uint8Array }) {
		// (c) the rotation we leave stays a candidate (same epoch): nothing is lost if the choice has to be revisited
		if (curRot && meshKey && curRot.epoch === c.rec.epoch && curRot.id !== c.rec.id) cands.set(curRot.id, { rec: curRot, key: meshKey });
		const { oldEpoch, oldKey, oldRid } = await switchEpoch(c.key, c.rec.epoch);
		curRot = c.rec;
		await store.set("rot", curRot);
		cands.delete(c.rec.id);
		for (const [id, x] of cands) if (x.rec.epoch < epoch) cands.delete(id);
		// R4-B1: what an owner rotation cut off is executed for good (tombstone; the epoch of the record that justified
		// it when known, else the rotation's)
		let settledAny = false;
		for (const t of c.rec.revoked) {
			const rec = (revRecs.get(t) ?? []).filter((r) => r.epoch <= c.rec.epoch).pop();
			settledAny = settleRevocation(t, rec ? rec.epoch : c.rec.epoch, rec ? await recHash(rec) : "") || settledAny;
		}
		if (settledAny) {
			await recomputeRevoked();
			await persistRevoked();
		}
		if (opts.canRotate) {
			// hook mode: the rotation itself is the record of who is cut off
			for (const t of c.rec.revoked) {
				const l = localCuts.get(t) ?? [];
				if (!l.includes(c.rec.epoch)) localCuts.set(t, [...l, c.rec.epoch]);
			}
			if (await recomputeRevoked()) await persistRevoked();
		}
		for (const l of [...links]) if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
		await rememberRetired(oldEpoch, oldKey, oldRid);
		void refreshTrust();
		for (const t of c.rec.revoked) emit("revoked", { deviceId: t, epoch });
	}

	/** Devices that may hold the current key although they are validly revoked (the owner must re-key without them). */
	function exposedRevoked(): string[] {
		const me = vault.deviceId;
		// before any rotation, only a device that was ever admitted can hold the key (made-up ids in requests cannot)
		const hadKey = (t: string) => trusted.has(t) || admCache[t] !== undefined || meta.has(ADM_PREFIX + t);
		return [...revokedIds.keys()].filter((t) => t !== me && isRevoked(t) && (curRot ? curRot.to.includes(t) : hadKey(t)));
	}
	/** A revocation is known here whose device the current key has not been taken away from yet (UI: pending owner). */
	const rekeyPending = () => exposedRevoked().length > 0;
	/**
	 * Owner devices only: re-key at epoch + 1 without every verified revoked device that may hold the current key (a
	 * revocation by an admin is a request the owner executes here), and (b) to include members admitted before the
	 * current rotation that it left out (e.g. their ECDH key was not known yet).
	 */
	async function ownerRekey() {
		if (!running || !root || root.deviceId !== vault.deviceId) return;
		const exposed = exposedRevoked();
		const missed = curRot
			? [...trusted.keys()].filter(
					(t) => !isRevoked(t) && !curRot?.to.includes(t) && (admittedAt.get(t) ?? Number.POSITIVE_INFINITY) < (curRot?.epoch ?? 0),
				)
			: [];
		const missedWithKey: string[] = [];
		for (const t of missed) if (await peerEcdhPub(t)) missedWithKey.push(t);
		if (exposed.length === 0 && missedWithKey.length === 0) return;
		// R4-S3: no rotation lists more devices than a receiver accepts: cut them in several rotations (each one already
		// leaves out every revoked device; the later ones list the rest so receivers record them as executed)
		const sorted = [...exposed].sort();
		for (let i = 0; i === 0 || i < sorted.length; i += MAX_ROT_MEMBERS) {
			if (!running || destroyed) return;
			await rotate(sorted.slice(i, i + MAX_ROT_MEMBERS));
		}
	}

	/** Wraps of stored rotations a straggler (still on a key of epoch `from`) is a recipient of, best first. */
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
			if (id !== (await rotationId(rot)) || !rotationSigned(rot, id) || !(await rotationAuthorized(rot))) continue;
			out.push({ rot, to: deviceId, wrap, id });
		}
		out.sort((x, y) => (betterRot({ epoch: x.rot.epoch, id: x.id }, { epoch: y.rot.epoch, id: y.id }) ? -1 : 1));
		return out.slice(0, 8).map(({ id: _id, ...msg }) => msg);
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
		// note 9: an unauthenticated link holds budgets (pre-auth reassembly, held frames): it does not stay forever
		const t = setTimeout(() => {
			if (!rec.authed && !rec.closing) {
				reject("link handshake timed out", rec.deviceId);
				closeRec(rec);
			}
		}, opts.handshakeTimeoutMs ?? 120_000);
		(t as { unref?: () => void }).unref?.();
		rec.link.onClose(() => clearTimeout(t));
		rec.hellosOut = 1;
		const lg = rec.legacy;
		sendFrameWith(rec, K_HELLO, rec.nonce, lg ? lg.material : docMat, lg ? lg.rid : dataRid, true).catch(err);
	}
	/** SF4: same challenge again, at most HANDSHAKE_MAX times per link. */
	function resendHello(rec: LinkRec) {
		if (!rec.nonce || rec.authed || rec.closing || (rec.hellosOut ?? 0) >= HANDSHAKE_MAX) return;
		rec.hellosOut = (rec.hellosOut ?? 0) + 1;
		const nonce = rec.nonce;
		// under the current AND the recent retired keys: the peer may still be on (or have switched from) any of them
		void (async () => {
			const lg = rec.legacy;
			await sendFrameWith(rec, K_HELLO, nonce, lg ? lg.material : docMat, lg ? lg.rid : dataRid, true);
			if (!lg) for (const r of retiredKeys()) await sendFrameWith(rec, K_HELLO, nonce, r.material, r.rid, true);
		})().catch(err);
	}
	async function answerHello(
		rec: LinkRec,
		peerNonce: Uint8Array,
		peer: string,
		via: { material: Uint8Array; rid: string; epoch: number },
	) {
		rec.answers = (rec.answers ?? 0) + 1;
		rec.authSent = true;
		// bound to the challenger and to the key the challenge came under (sealed under that same key)
		await sendFrameWith(rec, K_AUTH, concat(peerNonce, u32(via.epoch), utf8(peer)), via.material, via.rid, true);
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
		// the peer may be on another key of this epoch (its handshake crossed a key switch): offer the rotation we
		// are on if it is a recipient; one record, ignored if already known
		const cur = curRot;
		const peer = rec.deviceId as string;
		if (cur && cur.to.includes(peer)) {
			void (async () => {
				const m = (await storedRotationsFor(peer, cur.epoch)).find((x) => x.rot.n === cur.n && x.rot.from === cur.from);
				if (m) await sendRotate(rec, m);
			})().catch(err);
		}
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
		// an owner device executes what is pending at once (a revocation recorded before a restart, or a re-key
		// interrupted by the app tearing the mesh down): those trigger no new event once the device is back
		void serialRot(ownerRekey).catch(err);
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
	// The new mesh key never travels under the shared (old) key: it is wrapped per remaining device with a hybrid
	// key, HKDF(ML-KEM-768 secret || ECDH(own static key, peer static key), swal-rotate/v4|preId|from|to) -> AES-GCM,
	// where preId hashes the rotation record (epoch, issuer, targets, recipients, nonce); the owner signs the final id. Record and wraps are also stored in meta
	// (rotrec:<rotId>, rot:<rotId>:<deviceId>) so a peer that was offline can fetch its own wrap later through a
	// retired room (see `legacy`); a revoked device has no wrap and cannot unwrap anyone else's.
	async function switchEpoch(newKey: Uint8Array, newEpoch: number) {
		// a re-key still in flight when the app destroyed the mesh must not overwrite the vault: the next instance on
		// the same vault would start from a key nobody else ever received
		if (destroyed) throw new Error("mesh destroyed during a key change");
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
		// SF5: a bounded number of retired rooms (the oldest are left)
		while (legacy.size > MAX_RETIRED) {
			const oldest = [...legacy.values()].sort((x, y) => x.epoch - y.epoch)[0] as Legacy;
			legacy.delete(oldest.rid);
			leaveRoom(oldest.rid);
		}
		await joinRoom(dataRid, sigKey!);
		return { oldEpoch: old.epoch, oldKey, oldRid };
	}

	/** SF5: persist a key this device retired, so a restart keeps serving stragglers from that room. */
	async function rememberRetired(e: number, key: Uint8Array, rid: string) {
		const list = ((await store.get(RETIRED_KEY)) as Array<{ e: number; k: string; rid: string }> | undefined) ?? [];
		const next = [...list.filter((x) => x.rid !== rid), { e, k: b64uEncode(key), rid }].slice(-MAX_RETIRED);
		await store.set(RETIRED_KEY, next);
	}

	/** SF5: rejoin the rooms of keys this device retired (from its local store; the shared doc is never trusted). */
	async function syncLegacy() {
		if (!running) return;
		const list = ((await store.get(RETIRED_KEY)) as Array<{ e?: unknown; k?: unknown }> | undefined) ?? [];
		for (const v of list.slice(-MAX_RETIRED)) {
			const e = v?.e;
			if (!isEpoch(e) || e > epoch || typeof v?.k !== "string") continue;
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

	/**
	 * Owner only: re-key at epoch + 1 for every admitted, non-revoked device. `targets` are the revoked devices this
	 * rotation takes the key away from (their signed revocations travel with it).
	 */
	async function rotate(targets: string[]) {
		const me = vault.deviceId;
		if (root?.deviceId !== me) throw new Error("only the owner re-keys the mesh");
		const newEpoch = epoch + 1;
		if (newEpoch > MAX_EPOCH) throw new Error("epoch limit reached: re-create the mesh");
		const newKey = randomBytes(32);
		// R4-B2: carry what receivers read (REVS_CARRIED): one record per target, informative only (the cut list is
		// authoritative through the owner's signature)
		const revs: Revocation[] = [];
		for (const t of targets) {
			const r = (revRecs.get(t) ?? [])[0];
			if (r && revs.length < REVS_CARRIED) revs.push(r);
		}
		for (const l of [...links]) if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
		const priv = (await ecdhIdentity()).privateKey;
		const pubs = new Map<string, { pub: Uint8Array; kem: Uint8Array }>();
		for (const d of trusted.values()) {
			if (targets.includes(d.deviceId) || isRevoked(d.deviceId)) continue;
			const pub = await peerEcdhPub(d.deviceId);
			if (pub) pubs.set(d.deviceId, pub);
			else err(new Error(`no verified ECDH key for ${d.deviceId} yet: it gets the key with a later rotation`));
		}
		// R4-S3: a rotation receivers would drop as malformed must never be adopted here (the owner would end alone)
		if (targets.length > MAX_ROT_MEMBERS || pubs.size > MAX_ROT_MEMBERS)
			throw new Error(
				`re-key refused: ${pubs.size} recipients and ${targets.length} cut devices; a rotation carries at most ${MAX_ROT_MEMBERS} of each`,
			);
		const rec: RotRecord = {
			v: 1,
			epoch: newEpoch,
			from: me,
			revoked: [...targets].sort(),
			to: [...pubs.keys()].sort(),
			n: b64uEncode(randomBytes(16)),
			revs,
			wh: "",
		};
		// wraps are bound to the pre-id; the final id also commits to the whole wrap set (finding 5)
		const pid = await rotationPreId(rec);
		const wraps = new Map<string, string>();
		for (const [to, k] of pubs) wraps.set(to, await wrapMeshKey(priv, k.pub, k.kem, pid, me, to, newKey));
		// (every key in `pubs` passed the ML-KEM input check in peerEcdhPub, so no recipient can make this throw)
		rec.wh = await wrapsHash(Object.fromEntries(wraps));
		const id = await rotationId(rec);
		// the owner signs the id (record + wrap set) with its ML-DSA-65 identity: the rotation does not rest on P-256 alone
		rec.sig = b64uEncode(await vault.sign(rotationSigBytes(id)));
		if (destroyed) return; // torn down while signing: publish nothing, keep the vault as it was
		if (!isRotRecord(rec)) throw new Error("re-key refused: the rotation record would be malformed for receivers");
		// 1) hand each connected recipient ITS OWN wrap (under every recent key), 2) switch, 3) publish under the NEW key
		const sends: Promise<void>[] = [];
		for (const l of [...links]) {
			const w = !l.closing && l.deviceId ? wraps.get(l.deviceId) : undefined;
			if (l.deviceId && w) sends.push(sendRotate(l, { rot: rec, to: l.deviceId, wrap: w, wraps: Object.fromEntries(wraps) }));
		}
		await Promise.all(sends);
		await adopt({ rec: { ...rec, id }, key: newKey });
		doc.transact(() => {
			for (const t of targets) {
				// its admission stays: void from now on (B6), still needed to verify what it signed before
				meta.delete(DEV + t);
				meta.delete(ECDH_PREFIX + t);
			}
			for (const r of revs) meta.set(revKey(r), r);
			meta.set(ROTREC_PREFIX + id, rec);
			for (const [to, w] of wraps) meta.set(`${ROT_PREFIX}${id}:${to}`, w);
		});
	}

	/**
	 * Revoke a device. Its writes and links are cut here at once, and a signed revocation record goes into the shared
	 * doc. On the owner the mesh is re-keyed right away; on an admin it is a REQUEST that the next owner device online
	 * executes (until then `rekeyPending` is true: the revoked device still holds the current key).
	 */
	async function revoke(deviceId: string) {
		await ready;
		if (deviceId === vault.deviceId) throw new Error("cannot revoke the current device");
		await refreshTrust();
		if (!meta.has(DEV + deviceId) && !trusted.has(deviceId)) throw new Error("unknown device");
		if (!(await canRotate(vault.deviceId, deviceId))) throw new Error(`not authorized to revoke ${deviceId}`);
		if (!running) await start();
		const r = root ? await signRevocation(vault, { mid: root.mid, target: deviceId, by: vault.deviceId, epoch: epoch + 1 }) : null;
		if (r) {
			await addRecord(r);
			if (!meta.has(revKey(r))) meta.set(revKey(r), r);
		}
		await recomputeRevoked();
		if (!isRevoked(deviceId)) {
			// a custom `canRotate` allowed it although the built-in ladder does not: a local cut
			const l = localCuts.get(deviceId) ?? [];
			localCuts.set(deviceId, [...l, epoch + 1]);
			await recomputeRevoked();
		}
		await persistRevoked();
		// cut the revoked device off SYNCHRONOUSLY: its link must not be reachable by anything below
		for (const l of [...links]) if (l.deviceId === deviceId || (l.deviceId && isRevoked(l.deviceId))) closeRec(l);
		void refreshTrust();
		emit("revoked", { deviceId, epoch, pending: root?.deviceId !== vault.deviceId });
		await serialRot(ownerRekey);
	}

	// ---- pairing ----
	/** First pairing of a fresh mesh: this device becomes its owner (the pinned trust root). */
	async function ensureRoot(): Promise<TrustRoot> {
		if (root) return root;
		// a NEW mesh id, never one read from the shared doc (anybody could have copied another mesh's id there)
		const mid = b64uEncode(randomBytes(16));
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
			verify: identityVerify,
			prove: async (transcript) => ({
				pub: b64uEncode(vault.devicePublicKey),
				sig: b64uEncode(await vault.sign(hostProofBytes(transcript, vault.deviceId, b64uEncode(vault.devicePublicKey)))),
			}),
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
					// receivers only read the first 16 revocations of a rotation (handleRotate); with ML-DSA-65 each is ~4.6 KB,
					// so a rotation that cut many devices at once would otherwise push the grant past PAIR_MAX
					...(curRot ? { rot: { ...curRot, revs: curRot.revs.slice(0, REVS_CARRIED) } } : {}),
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
			const gctx: ChainContext = { verify: memoVerify, root: g.root, epoch: g.epoch, candidates: (id: string) => grantAdm.get(id) ?? [], revokedAt: () => undefined };
			const memo = new Map<string, Promise<Admission | null>>();
			const mine = await verifyChain(gctx, vault.deviceId, memo);
			if (!mine || mine.pub !== b64uEncode(vault.devicePublicKey)) throw new Error("pairing grant: invalid admission for this device");
			// the host proved (inside the session) that it holds hostId's ML-DSA key; the admission must come from it
			if (mine.by !== p.hostId) throw new Error("pairing grant: admission not issued by the paired host");
			const issuer = await verifyChain(gctx, mine.by, memo);
			if (!issuer || issuer.pub !== g.hostProof?.pub) throw new Error("pairing grant: admission not issued by the paired host");
			if (g.root.mid !== p.mid || g.mid !== p.mid) throw new Error("pairing grant: mesh id does not match the pairing code");
			if (g.root.deviceId !== p.root) throw new Error("pairing grant: trust root does not match the pairing code");
			if (root && root.mid === g.root.mid && (root.deviceId !== g.root.deviceId || root.pub !== g.root.pub))
				throw new Error(ROOT_MISMATCH_ERR);
			const switching = root?.mid !== g.root.mid;
			if (switching && root && !docIsFresh()) throw new Error(MOVE_MESH_ERR);
			// same mesh: never step back to an older epoch (and its older key) because the host lags behind us
			if (!switching && root && g.epoch < epoch) throw new Error(`pairing refused: the host is at epoch ${g.epoch}, this device at ${epoch}`);
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
				revRecs.clear();
				badRevs.clear();
				revStore.clear();
				localCuts.clear();
				executed.clear();
				overCap.clear();
				replay.clear();
				cands.clear();
				curRot = null;
				await store.set(RETIRED_KEY, []);
				await store.set(KEX_KEY, ecdhOk);
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
			// root is g.root (pinned above): the owner's signature must verify, like for any received rotation
			curRot = isRotRecord(gr) && gr.epoch === g.epoch && gr.id === (await rotationId(gr)) && rotationSigned(gr, gr.id) ? gr : null;
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
		get rekeyPending() {
			return rekeyPending();
		},
		get namespace() {
			return meshNamespace(appId, instanceId);
		},
		channel,
		role(deviceId = vault.deviceId) {
			return roleOf(deviceId);
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
