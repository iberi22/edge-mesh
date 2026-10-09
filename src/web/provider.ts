import {
	Awareness,
	applyAwarenessUpdate,
	encodeAwarenessUpdate,
	removeAwarenessStates,
} from "y-protocols/awareness";
import * as Y from "yjs";
import {
	canIssue,
	idMatchesPub,
	isDeviceId,
	isEpoch,
	MAX_EPOCH,
	MAX_EPOCH_SKIP,
	type Role,
	type TrustRoot,
} from "./admission.js";
import {
	deriveDocMaterial,
	deriveSenderKey,
	hkdf,
	importAesKey,
	openUpdate,
	sealUpdate,
} from "./crypto.js";
import {
	type ByteBudget,
	DEFAULT_MAX_FRAME,
	DEFAULT_MAX_MESSAGE,
	F_FRAG,
	fragment,
	Reassembler,
} from "./fragment.js";
import {
	createPairOffer,
	decodePairPayload,
	derivePairKey,
	type GrantBody,
	GuestPairing,
	HostPairing,
	hostProofBytes,
	type PairPayload,
	type SasPrompt,
} from "./pairing.js";
import {
	identityVerify,
	kemKeygen,
	ML_DSA_PUBLIC_KEY_BYTES,
	ML_KEM_PUBLIC_KEY_BYTES,
	ML_KEM_SECRET_KEY_BYTES,
} from "./pq.js";
import {
	derivePairRoomId,
	deriveRoomId,
	fingerprint,
	meshNamespace,
} from "./rooms.js";
import {
	type EcdhIdentity,
	generateEcdhIdentity,
	type KemIdentity,
	MAX_ROT_MEMBERS,
	MAX_ROT_REFS,
	type RotDoc,
	rotationId,
	rotationPreId,
	rotationSigBytes,
	unwrapMeshKey,
	wrapMeshKey,
	wrapsHash,
} from "./rotation.js";
import {
	MAX_MEMBERS_PER_ADMIN,
	type SecDoc,
	SecurityState,
	vaultSigner,
} from "./secstate.js";
import { idbStore, type MeshStore, memoryStore } from "./store.js";
import type { TrustStore } from "./trust/store.js";
import type { TrustSchema } from "./trust/types.js";
import type {
	Device,
	PeerLink,
	RtcOptions,
	SigTransport,
	VaultClient,
} from "./types.js";
import {
	b64uDecode,
	b64uEncode,
	concat,
	equalBytes,
	fromUtf8,
	randomBytes,
	utf8,
} from "./util.js";
import { connectViaSignaling } from "./webrtc.js";

export type MeshStatus = "off" | "connecting" | "online";
export type MeshEvent =
	| "status"
	| "peers"
	| "devices"
	| "sas"
	| "paired"
	| "revoked"
	| "rejected"
	| "error";

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
	 * Device-local store for the security state (pinned root, signed grants, revocations, key records, rotations).
	 * Default: `vault.store`, else IndexedDB when persist:'idb', else memory (a reloaded device then has to be paired
	 * again). Nothing of it lives in the shared Y.Doc.
	 */
	store?: MeshStore;
	/**
	 * Schema of the mesh's web/trust store (round 5: the single source of membership and authority). Default
	 * `MESH_SCHEMA` (module "mesh", roles "admin"/"member"). An app may pass its own schema (it must keep the module
	 * "mesh" and the roles "admin" and "member") to issue its own permissions into the same store (`mesh.security`).
	 */
	trustSchema?: TrustSchema;
	/**
	 * Extra membership filter on top of the signed grants: called for every device the trust store makes a member,
	 * with its identity key. Only devices it accepts receive rotation wraps and appear in `devices()`.
	 */
	authorizeDevice?: (
		deviceId: string,
		devicePub: Uint8Array,
	) => boolean | Promise<boolean>;
	/**
	 * Extra policy for revocations: may `issuer` revoke `target`? Checked before a local revoke() (on top of web/trust:
	 * the owner revokes anybody, an admin the devices it admitted) and for every device an incoming owner rotation cuts.
	 */
	canRotate?: (issuer: string, target: string) => boolean | Promise<boolean>;
	/**
	 * Data authorization hook: called before applying every incoming Yjs update with the AUTHENTICATED peer that
	 * delivered it (with signFrames on). Default: allow. Note that a sync reply may carry other members' changes:
	 * `sender` is the delivering device, not necessarily the author (per-author authorization needs a signed log).
	 * A refused update is dropped and reported as a 'rejected' event.
	 */
	authorizeUpdate?: (
		sender: string,
		update: Uint8Array,
	) => boolean | Promise<boolean>;
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

/** Read access to the mesh's security state, plus adding documents (e.g. app-issued grants, a backup). */
export interface MeshSecurity {
	/** Membership and authority (web/trust). */
	readonly trust: TrustStore;
	/** Every security document held (grants, revocations, key records, recent owner rotations). */
	docs(): Promise<SecDoc[]>;
	/** Verified owner rotations kept (the most recent ones), oldest first. */
	rotations(): Array<RotDoc & { id: string }>;
	/** Key-agreement keys of a device (base64url), or null if unknown. */
	keyAgreement(deviceId: string): { ecdh: string; kem: string } | null;
	/** Grant ids executed (cut) by owner rotations. */
	executedCuts(): string[];
	/** Add a signed document (verified like any received one) and hand it to the mesh. */
	add(doc: unknown): Promise<{ status: string; id?: string; reason?: string }>;
	/** Several documents at once (any order; e.g. a backup). */
	addMany(
		docs: readonly unknown[],
	): Promise<Array<{ status: string; id?: string; reason?: string }>>;
	/** Sign a grant with this device's identity (owner, or an admin for members). Not added: pass it to `add`. */
	issueGrant(
		subjectPub: string,
		opts: { role: "admin" | "member"; name?: string },
	): Promise<unknown>;
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
	pairJoin(
		payload: string,
		opts?: { confirmSas?: (code: string) => Promise<boolean> | boolean },
	): Promise<PairJoinResult>;
	/** This device plus every device a valid signed grant makes a member (and the owner). */
	devices(): Device[];
	/** Verified role of a device (default: this one), or null if it is not a member. */
	role(deviceId?: string): Role | null;
	/**
	 * Revoke a device: signs web/trust revocations of its grants (the owner: all of them; an admin: the ones it issued,
	 * directly or below), and its writes and links are cut at once everywhere. Only owner devices re-key the mesh; after
	 * an admin's revocation `rekeyPending` stays true until an owner device is online and has re-keyed (UI: "pendiente
	 * de que el dueño se conecte"): until then the revoked device still holds the current mesh key. `heads` (web/oplog
	 * `headIds()`) keep the device's op history up to there; without them none of its ops stays authorized.
	 */
	revoke(
		deviceId: string,
		opts?: {
			heads?: Readonly<Record<string, number | { seq: number; id: string }>>;
			reason?: string;
		},
	): Promise<void>;
	/**
	 * Owner only: give devices that lost membership through a revoked admin (revocations cascade) a grant of their own
	 * from the owner. They get the current key with the next re-key.
	 */
	reanchor(deviceIds: string[]): Promise<void>;
	/** Security state (round 5: signed documents outside the Y.Doc), or null before the first pairing. */
	readonly security: MeshSecurity | null;
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
// kind 3 (pre-round-5 rotation frames) is retired: such frames are ignored
const K_CHANNEL = 4; // body = nsLen(u16) | namespace | payload
const K_HELLO = 5; // body = nonce(16): fresh challenge of this link (S1)
const K_AUTH = 6; // body = peer's nonce(16) | epoch(u32), signed: the sender is live on THIS link (S1)
/** round 5: security documents (JSON {t:"inv",ids} | {t:"want",ids} | {t:"docs",docs}), also under retired keys */
const K_TRUST = 7;
const NONCE_BYTES = 16;
/** finding 4: bytes of bulk data waiting for one link beyond the message in progress (then the link is closed) */
const MAX_OUTSTANDING = 16 * 1024 * 1024;
/** SF4: per link, at most this many challenges sent and answered */
const HANDSHAKE_MAX = 8;
/** frames kept per link while waiting for the peer's K_AUTH (also bounded by PRE_AUTH_MAX bytes) */
const EARLY_MAX_FRAMES = 32;
/**
 * R4-S1: signature checks a link may cause before it authenticates (handshake frames only; a legit peer needs at most
 * HANDSHAKE_MAX challenges under up to 1 + RETIRED_TRY keys plus HANDSHAKE_MAX answers = 48). Beyond: the link closes.
 */
const HS_VERIFY_MAX = 64;
/**
 * R5-S2: the same limits across links. Handshake frames already verified on ANY link are dropped unverified (a global
 * window), one claimed identity may cost at most HS_VERIFY_PER_ID checks per minute over all links, a room holds at
 * most MAX_UNAUTH_PER_ROOM links that have not authenticated (MAX_UNAUTH_PER_PEER per announced peer), frames kept
 * before a peer's K_AUTH share EARLY_TOTAL bytes, and in a retired room a sender is answered at most
 * LEGACY_ANSWERS_PER_MIN times per minute (and never challenged again: stragglers come back by themselves).
 */
const HS_VERIFY_PER_ID = 128;
const MAX_UNAUTH_PER_ROOM = 32;
const MAX_UNAUTH_PER_PEER = 2;
const EARLY_TOTAL = 4 * 1024 * 1024;
const LEGACY_ANSWERS_PER_MIN = 2;
/** Replay window per sender session: seqs at most this far behind the highest one are still accepted once. */
const REPLAY_WINDOW = 1024;
const ORIGIN = Symbol("swal-mesh");
/** round 5: trust-channel limits (per message / per peer) */
const TRUST_INV_MAX = 20_000;
const TRUST_WANT_MAX = 2048;
const TRUST_DOCS_MAX = 256;
const TRUST_BATCH_BYTES = 512 * 1024;
/** documents served to one peer per minute, and failed documents accepted from one sender per minute */
const TRUST_SERVE_PER_MIN = 8192;
const TRUST_FAIL_PER_MIN = 64;
/** R4-S2: bounded caches drop their least recently used entry instead of being cleared all at once. */
class Lru<K, V> {
	private m = new Map<K, V>();
	constructor(private readonly cap: number) {}
	get(k: K): V | undefined {
		const v = this.m.get(k);
		if (v !== undefined) {
			this.m.delete(k);
			this.m.set(k, v);
		}
		return v;
	}
	has(k: K): boolean {
		return this.get(k) !== undefined;
	}
	set(k: K, v: V): void {
		this.m.delete(k);
		this.m.set(k, v);
		if (this.m.size > this.cap) this.m.delete(this.m.keys().next().value as K);
	}
	clear(): void {
		this.m.clear();
	}
}
/** SF5: retired keys this device itself held, kept in its LOCAL store (never read from the shared doc) */
const RETIRED_KEY = "retired";
const MAX_RETIRED = 16;
/** Retired keys tried on (and used to seal) rotation frames, so devices on another branch/epoch still get them. */
const RETIRED_TRY = 4;
const MAX_CANDIDATES = 16;

type Rot = RotDoc & { id: string };
/** Total order of rotations (B4): higher epoch first, then the lower rotation id. Deterministic on every device. */
const betterRot = (
	a: { epoch: number; id: string },
	b: { epoch: number; id: string },
) => (a.epoch !== b.epoch ? a.epoch > b.epoch : a.id < b.id);

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
	/** R4-S1: handshake frames verified on this link before it authenticated, and their (sender, session, seq) */
	hsChecks?: number;
	hsSeen?: Set<string>;
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
const frameSigBytes = (
	rid: string,
	sender: string,
	kind: number,
	sess: Uint8Array,
	seq: number,
	body: Uint8Array,
) =>
	concat(
		utf8(`swal-frame/v2|${rid}|${sender}|`),
		new Uint8Array([kind]),
		sess,
		u32(seq),
		body,
	);

interface Legacy {
	epoch: number;
	rid: string;
	material: Uint8Array;
}

export function createMesh(opts: MeshOptions): Mesh {
	const { appId, topic: topicName, doc, vault } = opts;
	const transports = opts.signaling ?? [];
	const now = opts.now ?? (() => Date.now());
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
	const store: MeshStore =
		opts.store ??
		vault.store ??
		(opts.persist === "idb" && typeof indexedDB !== "undefined"
			? idbStore(`swal-mesh-local/${appId}/${topicName}`)
			: memoryStore());
	let root: TrustRoot | null = null;
	/** round 5: the security state (signed documents, web/trust membership); null until a root is pinned */
	let sec: SecurityState | null = null;
	const selfPub = b64uEncode(vault.devicePublicKey);
	const signer = vaultSigner(vault, selfPub);
	let trusted = new Map<string, Device>(); // members other than this one (and the owner), from the security state
	const legacy = new Map<string, Legacy>(); // retired data rid -> its epoch material
	let curRot: Rot | null = null; // rotation that produced the current key (null: epoch 0 / unknown)
	let curRotId: string | null = null; // its id, kept even before the document itself has arrived (pairing grant)
	const cands = new Map<string, { rec: Rot; key: Uint8Array }>(); // verified rotations not adopted (yet)
	const unwrapFailed = new Set<string>(); // rotations whose wrap for us did not open (reported once)
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
				.filter(
					(l) =>
						l.deviceId &&
						l.rid !== "pair" &&
						!l.legacy &&
						!l.closing &&
						!isRevoked(l.deviceId),
				)
				.map((l) => l.deviceId!),
		),
	];
	const setStatus = () => {
		const s: MeshStatus = !running
			? "off"
			: peerIds().length > 0
				? "online"
				: "connecting";
		if (s !== status) {
			status = s;
			emit("status", s);
		}
		emit("peers", peerIds());
	};
	const err = (e: unknown) => emit("error", e);

	// ---- devices: members by signed web/trust grants (round 5). Nothing in the shared doc counts. ----
	const selfRole = (): Role | null =>
		root?.deviceId === vault.deviceId
			? "owner"
			: (sec?.roleOf(vault.deviceId) ?? null);
	const selfDevice = (): Device => {
		const g = sec?.memberGrant(vault.deviceId);
		return {
			deviceId: vault.deviceId,
			pub: selfPub,
			name: g?.name ?? opts.deviceName ?? "device",
			addedAt: g?.issuedAt ?? 0,
			...(selfRole() ? { role: selfRole()! } : {}),
			...(g ? { admittedBy: g.issuer } : {}),
		};
	};
	/** A device that had a grant and has none left that makes it a member (revoked, or cut by the owner). */
	const isRevoked = (id: string) => sec?.isOut(id) ?? false;
	// a device revoked a moment ago is never listed, even before the trust state is recomputed
	const devices = (): Device[] =>
		[
			selfDevice(),
			...[...trusted.values()].filter((d) => !isRevoked(d.deviceId)),
		].sort((a, b) => a.addedAt - b.addedAt);
	const roleOf = (id: string): Role | null =>
		id === vault.deviceId
			? selfRole()
			: isRevoked(id)
				? null
				: (trusted.get(id)?.role ?? null);

	let trustChain: Promise<void> = Promise.resolve();
	/**
	 * R4-S2: one trust pass at most waits behind the running one. Every change of the security state asks for a pass;
	 * those that arrive while one is queued share it (it starts after them, so it sees their documents).
	 */
	let trustQueued: Promise<void> | null = null;
	const refreshTrust = (): Promise<void> => {
		if (trustQueued) return trustQueued;
		const run = trustChain.then(() => {
			trustQueued = null;
			return computeTrust();
		});
		trustQueued = run.catch(err);
		trustChain = trustQueued;
		return trustQueued;
	};
	async function computeTrust() {
		const next = new Map<string, Device>();
		if (sec && root) {
			if (root.deviceId !== vault.deviceId)
				next.set(root.deviceId, {
					deviceId: root.deviceId,
					pub: root.pub,
					name: ownerName ?? "owner",
					addedAt: 0,
					role: "owner",
				});
			for (const m of sec.members()) {
				if (m.deviceId === vault.deviceId) continue;
				if (
					opts.authorizeDevice &&
					!(await opts.authorizeDevice(m.deviceId, b64uDecode(m.pub)))
				)
					continue;
				next.set(m.deviceId, {
					deviceId: m.deviceId,
					pub: m.pub,
					name: m.grant.name || m.deviceId,
					addedAt: m.grant.issuedAt,
					role: m.role,
					admittedBy: m.grant.issuer,
				});
			}
		}
		trusted = next;
		for (const l of [...links])
			if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
		emit("devices", devices());
		replayHeld();
		if (sec && running) {
			void serialRot(considerRotations).catch(err);
		}
	}

	// ---- persistence ----
	let persistence: { destroy(): Promise<void> | void } | null = null;
	let ownerName: string | null = null;
	/** Open (or switch to) the security state of the pinned root, and follow its changes. */
	let secUnsub: (() => void) | null = null;
	async function openSecurity(r: TrustRoot) {
		secUnsub?.();
		sec = await SecurityState.open({
			root: r,
			store,
			schema: opts.trustSchema,
			now,
		});
		secUnsub = sec.onChange(() => void refreshTrust());
	}
	const ready = (async () => {
		// B1: a deviceId IS the fingerprint of the identity key; every peer enforces it, so must we
		if (vault.devicePublicKey.length !== ML_DSA_PUBLIC_KEY_BYTES)
			throw new Error(
				"vault.devicePublicKey must be an ML-DSA-65 public key (1952 bytes; ECDSA identities are no longer accepted)",
			);
		if (!(await idMatchesPub(vault.deviceId, selfPub))) {
			throw new Error(
				"vault.deviceId must be deviceIdOf(vault.devicePublicKey)",
			);
		}
		const r = (await store.get("root")) as TrustRoot | undefined;
		if (
			r &&
			typeof r.deviceId === "string" &&
			typeof r.pub === "string" &&
			typeof r.mid === "string"
		)
			root = r;
		const on = await store.get("ownerName");
		if (typeof on === "string") ownerName = on;
		const cr = await store.get("rotId");
		if (typeof cr === "string") curRotId = cr;
		if (root) {
			await openSecurity(root);
			const c = curRotId ? sec!.rotation(curRotId) : undefined;
			if (c) curRot = c;
		}
		if (opts.persist === "idb" && typeof indexedDB !== "undefined") {
			const { IndexeddbPersistence } = await import("y-indexeddb");
			const p = new IndexeddbPersistence(
				`swal-mesh/${appId}/${topicName}`,
				doc,
			);
			persistence = p;
			await p.whenSynced;
		}
		if (opts.persist === "idb" && typeof indexedDB === "undefined") {
			throw new Error("persist:'idb' requested but IndexedDB is not available");
		}
		if (sec) await publishKex();
		await refreshTrust();
		epoch = Math.max(
			localNum(await vault.getEpoch?.()),
			localNum(await store.get("epoch")),
			epoch,
		); // known before start
		// already paired: resume (unless the app is about to move this device to another mesh, see `resume`)
		if (opts.resume !== false && root && trusted.size > 0 && !destroyed)
			await start();
	})();
	ready.catch(err);

	// ---- key-agreement identity (rotation wraps) ----
	async function ecdhIdentity(): Promise<EcdhIdentity> {
		if (!ecdhId) {
			ecdhId =
				(await vault.getEcdhIdentity?.()) ?? (await generateEcdhIdentity());
		}
		return ecdhId;
	}
	async function kemIdentity(): Promise<KemIdentity> {
		if (!kemId) {
			const k = (await vault.getKemIdentity?.()) ?? kemKeygen();
			if (
				k.publicKey.length !== ML_KEM_PUBLIC_KEY_BYTES ||
				k.secretKey.length !== ML_KEM_SECRET_KEY_BYTES
			)
				throw new Error(
					"vault.getKemIdentity must return an ML-KEM-768 key pair",
				);
			kemId = k;
		}
		return kemId;
	}
	/** This device's key-agreement record (a signed document; a new one only when the keys changed). */
	async function publishKex() {
		if (!sec) return;
		const ecdh = b64uEncode((await ecdhIdentity()).publicKey);
		const kem = b64uEncode((await kemIdentity()).publicKey);
		const cur = sec.keyAgreement(vault.deviceId);
		if (cur?.ecdh === ecdh && cur.kem === kem) return;
		await addLocal([await sec.kexRecord(signer, ecdh, kem)]);
	}
	/** Key-agreement keys of a device, from its signed record (members only use those of members). */
	function kexOf(
		deviceId: string,
	): { pub: Uint8Array; kem: Uint8Array } | null {
		const k = sec?.keyAgreement(deviceId);
		return k ? { pub: b64uDecode(k.ecdh), kem: b64uDecode(k.kem) } : null;
	}

	// ---- keys ----
	function senderKey(
		material: Uint8Array,
		deviceId: string,
	): Promise<CryptoKey> {
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
		epoch = Math.max(
			localNum(await vault.getEpoch?.()),
			localNum(await store.get("epoch")),
			epoch,
		);
		docMat = await deriveDocMaterial(meshKey, topicName);
		sigKey = await importAesKey(
			await hkdf(meshKey, `swal-signal/v1|${topicName}`),
		);
		instanceId =
			opts.instance ?? (root ? await fingerprint(b64uDecode(root.pub)) : "");
		dataRid = await deriveRoomId(
			meshKey,
			appId,
			topicName,
			epoch,
			instanceId || undefined,
		);
		if (curRot && curRot.epoch !== epoch) curRot = null;
	}

	// ---- link I/O: per-link ordered queue; messages above maxFrame are fragmented (H5) ----
	const outQ = new WeakMap<PeerLink, Promise<void>>();
	const outBytes = new WeakMap<PeerLink, number>(); // finding 4: bytes accepted for a link, not handed over yet
	function sendBytes(
		link: PeerLink,
		bytes: Uint8Array,
		alive: () => boolean = () => true,
	): Promise<void> {
		const pending = outBytes.get(link) ?? 0;
		// finding 4: a peer that drains far slower than we produce must not make us buffer without bound. A single
		// message of any size (up to maxMessageBytes) may wait alone; beyond MAX_OUTSTANDING of backlog the link is
		// closed (the peer resyncs from state vectors when it reconnects).
		if (pending > 0 && pending + bytes.length > MAX_OUTSTANDING) {
			err(
				new Error(
					`link ${link.id}: more than ${MAX_OUTSTANDING} bytes waiting for a slow peer: closing it`,
				),
			);
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
					outBytes.set(
						link,
						Math.max(0, (outBytes.get(link) ?? 0) - bytes.length),
					);
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
		for (const f of await fragment(bytes, maxFrame))
			(link.sendPriority ?? link.send).call(link, f);
	}

	// ---- framing ----
	// Every sender seals under its OWN subkey (HKDF over the sender's deviceId); receivers derive it
	// from the deviceId in the frame header (also bound in the AAD). Wire: F_DATA | idLen | id | nonce | ct+tag.
	// With signFrames (default) the plaintext also carries the sender's identity signature over
	// (rid, sender, kind, body): F_SDATA | idLen | id | nonce | AES-GCM(kind | sigLen | sig | body).
	type Signed = { sig: Uint8Array; sess: Uint8Array; seq: number };
	const signCache = new WeakMap<
		Uint8Array,
		{ rid: string; kind: number; p: Promise<Signed> }
	>();
	let selfSess = randomBytes(8); // this instance's sender session (a restart is a new session)
	let selfSeq = 0;
	function signFor(
		rid: string,
		kind: number,
		body: Uint8Array,
	): Promise<Signed> {
		const c = signCache.get(body); // a broadcast signs once (same seq) for all links
		if (c && c.rid === rid && c.kind === kind) return c.p;
		if (selfSeq >= 0xffffffff) {
			selfSess = randomBytes(8);
			selfSeq = 0;
		}
		const sess = selfSess;
		const seq = ++selfSeq;
		const p = vault
			.sign(frameSigBytes(rid, vault.deviceId, kind, sess, seq, body))
			.then((sig) => ({ sig, sess, seq }));
		signCache.set(body, { rid, kind, p });
		return p;
	}
	// receiver side of S1: highest seq + recently seen seqs per (sender, session)
	const replay = new Map<string, { max: number; seen: Set<number> }>();
	/** R4-S1: the same test as freshSeq, without recording: run BEFORE the signature check (recorded after it). */
	function seqFresh(sender: string, sess: string, seq: number): boolean {
		const w = replay.get(`${sender}|${sess}`);
		return !w || !(seq + REPLAY_WINDOW <= w.max || w.seen.has(seq));
	}
	function freshSeq(sender: string, sess: string, seq: number): boolean {
		const k = `${sender}|${sess}`;
		let w = replay.get(k);
		if (!w) {
			if (replay.size >= 4096)
				replay.delete(replay.keys().next().value as string);
			w = { max: 0, seen: new Set() };
			replay.set(k, w);
		}
		if (seq + REPLAY_WINDOW <= w.max || w.seen.has(seq)) return false;
		w.seen.add(seq);
		if (seq > w.max) w.max = seq;
		if (w.seen.size > 2 * REPLAY_WINDOW)
			for (const x of w.seen) if (x + REPLAY_WINDOW <= w.max) w.seen.delete(x);
		return true;
	}
	function sendFrame(rec: LinkRec, kind: number, body: Uint8Array) {
		const lg = rec.legacy;
		return sendFrameWith(
			rec,
			kind,
			body,
			lg ? lg.material : docMat,
			lg ? lg.rid : dataRid,
		);
	}
	/** Recent retired keys (newest first): rotation frames are also sealed under them, and receivers try them. */
	const retiredKeys = (n = RETIRED_TRY) =>
		[...legacy.values()].sort((x, y) => y.epoch - x.epoch).slice(0, n);
	/**
	 * A rotation must reach peers still on the previous key or on a concurrent branch: its security-document frame is
	 * sealed under the current key, the recent retired ones and the key the peer is known to hold.
	 */
	async function sendTrustEverywhere(rec: LinkRec, body: Uint8Array) {
		if (rec.legacy)
			return sendFrameWith(
				rec,
				K_TRUST,
				body,
				rec.legacy.material,
				rec.legacy.rid,
				true,
			);
		await sendFrameWith(rec, K_TRUST, body, docMat, dataRid, true);
		const recent = retiredKeys();
		for (const r of recent)
			await sendFrameWith(rec, K_TRUST, body, r.material, r.rid, true);
		const c = rec.common;
		if (c && c.rid !== dataRid && !recent.some((r) => r.rid === c.rid))
			await sendFrameWith(rec, K_TRUST, body, c.material, c.rid, true);
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
			inner = concat(
				new Uint8Array([kind]),
				sess,
				u32(seq),
				new Uint8Array([sig.length >> 8, sig.length & 0xff]),
				sig,
				body,
			);
		} else inner = concat(new Uint8Array([kind]), body);
		const sealed = await sealUpdate(key, inner, `${rid}|${vault.deviceId}`);
		if (rec.closing) return;
		const frame = concat(
			new Uint8Array([signFrames ? F_SDATA : F_DATA, id.length]),
			id,
			sealed,
		);
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
		for (const l of established())
			if (l !== except) sendFrame(l, kind, body).catch(err);
	};

	// one stable sender per link: the pairing state machines identify the active link by it
	const pairSenders = new WeakMap<PeerLink, (m: any) => void>();
	function sendPair(link: PeerLink) {
		let f = pairSenders.get(link);
		if (!f) {
			f = (m: unknown) =>
				void sendBytes(
					link,
					concat(new Uint8Array([F_PAIR]), utf8(JSON.stringify(m))),
				);
			pairSenders.set(link, f);
		}
		return f;
	}

	const reject = (reason: string, from?: string) =>
		emit("rejected", { reason, from });
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
	/** R5-S2: frames that arrived before the peer's K_AUTH, kept sealed; all links share EARLY_TOTAL bytes. */
	let earlyTotal = 0;
	function keepEarly(rec: LinkRec, data: Uint8Array) {
		if (!rec.early) rec.early = { frames: [], bytes: 0 };
		const e = rec.early;
		if (
			e.frames.length < EARLY_MAX_FRAMES &&
			e.bytes + data.length <= PRE_AUTH_MAX &&
			earlyTotal + data.length <= EARLY_TOTAL
		) {
			e.frames.push(data);
			e.bytes += data.length;
			earlyTotal += data.length;
		}
	}
	function dropEarly(rec: LinkRec) {
		if (rec.early) earlyTotal -= rec.early.bytes;
		rec.early = undefined;
	}
	/** R5-S2: handshake frames verified on any link (sender|session|seq) */
	const hsGlobal = new Lru<string, true>(8192);
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
		if (rec.deviceId && rec.deviceId !== sender)
			return reject("frame sender does not match the link", sender);
		const revoked = isRevoked(sender);
		// signed frames from a sender whose admission has not reached us yet: hold them (still encrypted, no key derived)
		if (signed && !revoked && !trusted.has(sender)) {
			if (!lg) hold(rec, data);
			return;
		}
		// the link's key first; on a live link also the recent retired keys, which may only carry rotations (B4)
		const tries: Array<{
			material: Uint8Array | null;
			rid: string;
			epoch: number;
		}> = lg
			? [lg]
			: [
					{ material: docMat, rid: dataRid, epoch },
					...retiredKeys(MAX_RETIRED),
				];
		let plain: Uint8Array | null = null;
		let rid = "";
		let retired = false;
		let via: { material: Uint8Array; rid: string; epoch: number } | null = null; // the key this frame came under
		for (let i = 0; i < tries.length && !plain; i++) {
			const t = tries[i];
			if (!t.material) continue;
			try {
				plain = await openUpdate(
					await senderKey(t.material, sender),
					data.subarray(2 + idLen),
					`${t.rid}|${sender}`,
				);
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
			const seq = new DataView(plain.buffer, plain.byteOffset + 9, 4).getUint32(
				0,
				false,
			);
			const sigLen = (plain[13] << 8) | plain[14];
			if (plain.length < 15 + sigLen)
				return reject("malformed signed frame", sender);
			const sig = plain.subarray(15, 15 + sigLen);
			body = plain.subarray(15 + sigLen);
			sess = b64uEncode(sessBytes);
			if (revoked) return; // a revoked device is never listened to
			const pub = trusted.get(sender)?.pub;
			if (!pub) return;
			// R4-S1: everything that can be decided without the (2 ms) signature check is decided first
			const hsKey = `${sender}|${sess}|${seq}`;
			if (rec.authed) {
				if (sess !== rec.peerSess || !seqFresh(sender, sess, seq)) return; // replay / other link
			} else if (kind !== K_HELLO && kind !== K_AUTH) {
				// the peer authenticated us first and already talks: keep a few frames (unverified, still sealed) until its
				// K_AUTH reaches us; they are verified once, when they are run again after it
				keepEarly(rec, data);
				return;
			} else {
				// a replayed handshake frame (on this link or any other): dropped unverified
				if (rec.hsSeen?.has(hsKey) || hsGlobal.has(hsKey)) return;
				rec.hsChecks = (rec.hsChecks ?? 0) + 1;
				if (
					rec.hsChecks > HS_VERIFY_MAX ||
					!budget(budgets.hs, sender, 1, HS_VERIFY_PER_ID)
				) {
					reject("too many handshake frames", sender);
					return closeRec(rec);
				}
			}
			let ok = false;
			try {
				ok = identityVerify(
					b64uDecode(pub),
					frameSigBytes(rid, sender, kind, sessBytes, seq, body),
					sig,
				);
			} catch {}
			if (!ok) return reject("bad frame signature", sender);
			if (rec.closing) return;
			if (!rec.authed) {
				if (!rec.hsSeen) rec.hsSeen = new Set();
				if (rec.hsSeen.size < 2 * HS_VERIFY_MAX) rec.hsSeen.add(hsKey);
				hsGlobal.set(hsKey, true);
			} else if (kind === K_HELLO || kind === K_AUTH)
				freshSeq(sender, sess, seq); // (other kinds: recorded below)
			// S1: a link carries nothing but its handshake until the peer signed OUR fresh challenge on it
			// the handshake may arrive under one of our recent retired keys (a key switch raced with it, or the peer is on
			// another branch): it is then bound to THAT key's room and epoch, and answered under the same key
			if (kind === K_HELLO) {
				if (body.length !== NONCE_BYTES || !via) return;
				rec.common = via;
				rec.hellosIn = (rec.hellosIn ?? 0) + 1;
				// R5-S2: in a retired room a sender is answered a couple of times per minute at most (whatever the links)
				const mayAnswer =
					!rec.legacy ||
					budget(
						budgets.legacyAnswer,
						`${rec.rid}|${sender}`,
						1,
						LEGACY_ANSWERS_PER_MIN,
					);
				if ((rec.answers ?? 0) < HANDSHAKE_MAX && mayAnswer)
					await answerHello(rec, body, sender, via);
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
					new DataView(body.buffer, body.byteOffset + NONCE_BYTES, 4).getUint32(
						0,
						false,
					) === ep &&
					fromUtf8(body.subarray(NONCE_BYTES + 4)) === vault.deviceId;
				if (!okAuth) return reject("bad link authentication", sender);
				rec.common = via;
				rec.deviceId = sender;
				rec.authed = true;
				rec.peerSess = sess;
				rec.lift?.();
				setStatus();
				const early = rec.early?.frames ?? [];
				dropEarly(rec);
				for (const f of early)
					rec.chain = rec.chain.then(() => onData(rec, f)).catch(err);
				return maybeStart(rec);
			}
			if (!rec.authed) {
				// the peer authenticated us first and already talks: keep a few frames until its K_AUTH reaches us
				keepEarly(rec, data);
				return;
			}
			if (sess !== rec.peerSess || !freshSeq(sender, sess, seq)) return; // replay / other link
		} else if (revoked) return;
		if (retired) {
			// security documents travel under any key the peer may hold (a straggler, a peer on another branch)
			if (kind === K_TRUST && via) await handleTrust(rec, body, sender, via);
			// (d) an authenticated peer still talks under one of our retired keys: it missed a rotation. Offer it the
			// stored rotations from that key's epoch (once per link and current rotation).
			else if (via && rec.authed) offerRotations(rec, sender, via);
			return;
		}
		if (!rec.deviceId) {
			rec.deviceId = sender; // legacy unsigned wire only: the link is bound to its first sender
			rec.lift?.();
			setStatus();
		}
		if (lg) {
			// retired room: only security documents (the peer catches up with the rotations and revocations it missed)
			if (kind === K_TRUST) await handleTrust(rec, body, sender, lg);
			return;
		}
		if (kind === K_SV) {
			await sendFrame(rec, K_UPDATE, Y.encodeStateAsUpdate(doc, body));
		} else if (kind === K_UPDATE) {
			if (opts.authorizeUpdate && !(await opts.authorizeUpdate(sender, body)))
				return reject("update not authorized", sender);
			if (rec.closing) return;
			Y.applyUpdate(doc, body, ORIGIN);
		} else if (kind === K_AWARENESS) {
			applyAwarenessUpdate(awareness, body, ORIGIN);
		} else if (kind === K_TRUST) {
			await handleTrust(rec, body, sender, {
				material: docMat as Uint8Array,
				rid: dataRid,
				epoch,
			});
		} else if (kind === K_CHANNEL) {
			const n = body.length >= 2 ? (body[0] << 8) | body[1] : -1;
			if (n < 0 || body.length < 2 + n)
				return reject("malformed channel frame", sender);
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
	const chanSubs = new Map<
		string,
		Set<(d: Uint8Array, from: string) => void>
	>();
	const chanNs = (kind: string) =>
		`${meshNamespace(appId, instanceId)}/${kind}`;
	function channel(kind: string): MeshChannel {
		if (!/^[A-Za-z0-9._-]{1,64}$/.test(kind))
			throw new Error(`invalid channel kind "${kind}"`);
		const mine = new Set<(d: Uint8Array, from: string) => void>();
		return {
			get namespace() {
				return chanNs(kind);
			},
			async send(data, o = {}) {
				if (!running) throw new Error("mesh is not connected");
				const ns = utf8(chanNs(kind));
				const body = concat(
					new Uint8Array([ns.length >> 8, ns.length & 0xff]),
					ns,
					data,
				);
				const targets = established().filter(
					(l) => l.deviceId && (o.to === undefined || l.deviceId === o.to),
				);
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

	// ---- security documents: the trust channel (round 5) ----
	// Every device holds the same append-only set of signed documents and exchanges it with every authenticated peer:
	// `inv` (the keys it holds), `want` (keys it lacks), `docs`. A new document is announced to every link. Rotations
	// are also pushed whole, under every key a peer may still hold.
	type TrustKey = { material: Uint8Array | null; rid: string; epoch: number };
	const linkKey = (l: LinkRec): TrustKey =>
		l.legacy ?? { material: docMat, rid: dataRid, epoch };
	const budgets = {
		serve: new Map<string, { t: number; n: number }>(),
		fail: new Map<string, { t: number; n: number }>(),
		hs: new Map<string, { t: number; n: number }>(),
		legacyAnswer: new Map<string, { t: number; n: number }>(),
	};
	/** Per-peer budget over a sliding minute; false when `n` more would exceed `max`. */
	function budget(
		m: Map<string, { t: number; n: number }>,
		peer: string,
		n: number,
		max: number,
	): boolean {
		const t = now();
		let b = m.get(peer);
		if (!b || t - b.t > 60_000) {
			b = { t, n: 0 };
			m.delete(peer);
			m.set(peer, b);
			if (m.size > 4096) m.delete(m.keys().next().value as string);
		}
		if (b.n + n > max) return false;
		b.n += n;
		return true;
	}
	function sendTrust(rec: LinkRec, msg: unknown, key: TrustKey) {
		const body = utf8(JSON.stringify(msg));
		if (rec.legacy)
			return sendFrameWith(
				rec,
				K_TRUST,
				body,
				rec.legacy.material,
				rec.legacy.rid,
				true,
			);
		return sendFrameWith(rec, K_TRUST, body, key.material, key.rid, true);
	}
	/** Documents in batches (count and bytes bounded). */
	async function sendDocs(
		rec: LinkRec,
		docs: readonly unknown[],
		key: TrustKey,
	) {
		let batch: unknown[] = [];
		let bytes = 0;
		for (const d of docs) {
			const n = JSON.stringify(d).length;
			if (
				batch.length &&
				(batch.length >= TRUST_DOCS_MAX || bytes + n > TRUST_BATCH_BYTES)
			) {
				await sendTrust(rec, { t: "docs", docs: batch }, key);
				batch = [];
				bytes = 0;
			}
			batch.push(d);
			bytes += n;
		}
		if (batch.length) await sendTrust(rec, { t: "docs", docs: batch }, key);
	}
	/** Tell every authenticated peer (but `except`) about new documents. */
	function announce(keys: readonly string[], except?: LinkRec) {
		if (!keys.length) return;
		for (const l of [...links]) {
			if (
				l === except ||
				l.closing ||
				l.rid === "pair" ||
				!l.deviceId ||
				isRevoked(l.deviceId)
			)
				continue;
			if (signFrames && !l.authed) continue;
			void sendTrust(l, { t: "inv", ids: keys }, linkKey(l)).catch(err);
		}
	}
	/** Add documents made or received here, and announce the new ones. */
	async function addLocal(
		docs: readonly unknown[],
		except?: LinkRec,
		from?: string,
	) {
		if (!sec) return [];
		// R6-S2b: `from` is the peer that sent these documents, so the trust store can charge its waiting slots to it
		const outs = await sec.addMany(docs, { from });
		announce(
			outs
				.filter((o) => o.status === "accepted" && o.id)
				.map((o) => o.id as string),
			except,
		);
		return outs;
	}
	async function handleTrust(
		rec: LinkRec,
		body: Uint8Array,
		sender: string,
		key: TrustKey,
	) {
		if (!sec) return;
		let m: { t?: unknown; ids?: unknown; docs?: unknown };
		try {
			m = JSON.parse(fromUtf8(body));
		} catch {
			return reject("malformed trust message", sender);
		}
		if (!m || typeof m !== "object") return;
		if (
			m.t === "inv" &&
			Array.isArray(m.ids) &&
			m.ids.length <= TRUST_INV_MAX
		) {
			const want = sec.missing(m.ids).slice(0, TRUST_WANT_MAX);
			if (want.length) await sendTrust(rec, { t: "want", ids: want }, key);
		} else if (
			m.t === "want" &&
			Array.isArray(m.ids) &&
			m.ids.length <= TRUST_WANT_MAX
		) {
			const ids = m.ids.filter((x): x is string => typeof x === "string");
			if (!budget(budgets.serve, sender, ids.length, TRUST_SERVE_PER_MIN))
				return reject("security documents asked too often", sender);
			await sendDocs(rec, await sec.get(ids), key);
		} else if (
			m.t === "docs" &&
			Array.isArray(m.docs) &&
			m.docs.length <= TRUST_DOCS_MAX
		) {
			// a sender whose documents keep failing (bad signatures, junk) is cut off for a while: each costs a check
			for (let i = 0; i < m.docs.length; i += 16) {
				if (!budget(budgets.fail, sender, 0, TRUST_FAIL_PER_MIN))
					return reject("too many bad security documents", sender);
				const outs = await addLocal(m.docs.slice(i, i + 16), rec, sender);
				for (const o of outs)
					if (o.status === "rejected")
						reject(o.reason ?? "invalid security document", sender);
				const bad = outs.filter((o) => o.status === "rejected").length;
				if (bad && !budget(budgets.fail, sender, bad, TRUST_FAIL_PER_MIN))
					return reject("too many bad security documents", sender);
			}
		}
	}
	/** Rotation documents `peer` (still on a key of `fromEpoch`) can adopt, best last (at most MAX_EPOCH_SKIP ahead). */
	function rotationsFor(
		peer: string,
		fromEpoch: number,
	): Array<Omit<Rot, "id">> {
		if (!sec) return [];
		return sec
			.rotations()
			.filter(
				(r) =>
					r.to.includes(peer) &&
					r.epoch > fromEpoch &&
					r.epoch <= fromEpoch + MAX_EPOCH_SKIP &&
					r.epoch <= epoch,
			)
			.map(({ id: _id, ...d }) => d);
	}
	const offered = new Set<string>();
	/** (d) a peer still talks under one of our retired keys: hand it what it missed, under that key. */
	function offerRotations(rec: LinkRec, peer: string, via: TrustKey) {
		const k = `${curRot?.id ?? epoch}|${peer}|${via.epoch}`;
		if (offered.has(k) || !sec) return;
		if (offered.size >= 4096) offered.clear();
		offered.add(k);
		void (async () => {
			await sendDocs(rec, rotationsFor(peer, via.epoch), via);
			if (sec) await sendTrust(rec, { t: "inv", ids: sec.inventory() }, via);
		})().catch(err);
	}

	// ---- rotations (owner only issues them; every device adopts the best one it can open) ----
	/**
	 * Adopt the best rotation we are a recipient of (highest epoch, then lowest id), one window of MAX_EPOCH_SKIP at a
	 * time. Only owner-identity devices issue rotations, so concurrency only exists between devices of the owner;
	 * every device applies the same rule to the same set. Rotations are documents: whatever order they arrive in, and
	 * whoever relays them, every device ends on the same one.
	 */
	async function considerRotations() {
		if (!sec || !root || !running) return;
		const me = vault.deviceId;
		for (let guard = 0; guard < 64; guard++) {
			const ownerKex = kexOf(root.deviceId);
			for (const r of sec.rotations()) {
				if (!curRot && curRotId === r.id && r.epoch === epoch) curRot = r; // the rotation our pairing key came from
				if (
					r.epoch < epoch ||
					r.id === curRot?.id ||
					cands.has(r.id) ||
					unwrapFailed.has(r.id)
				)
					continue;
				if (
					r.epoch > epoch + MAX_EPOCH_SKIP ||
					!r.to.includes(me) ||
					!r.wraps[me]
				)
					continue;
				if (opts.canRotate) {
					let ok = true;
					for (const t of r.revoked)
						if (!(await opts.canRotate(r.from, t))) ok = false;
					if (!ok) {
						unwrapFailed.add(r.id);
						emit("rejected", {
							reason: "rotation not authorized",
							from: r.from,
							epoch: r.epoch,
						});
						continue;
					}
				}
				if (!ownerKex) continue; // the owner's key record has not arrived yet: tried again on the next change
				try {
					const key = await unwrapMeshKey(
						(await ecdhIdentity()).privateKey,
						(await kemIdentity()).secretKey,
						ownerKex.pub,
						await rotationPreId(r),
						r.from,
						me,
						r.wraps[me] as string,
					);
					cands.set(r.id, { rec: r, key });
				} catch {
					unwrapFailed.add(r.id);
					emit("rejected", {
						reason: "rotation wrap does not authenticate",
						from: r.from,
						epoch: r.epoch,
					});
				}
			}
			const cur = { epoch, id: curRot ? curRot.id : (curRotId ?? "\uffff") }; // genesis/unknown loses to any rotation of its epoch
			let best: { rec: Rot; key: Uint8Array } | null = null;
			for (const [id, c] of cands) {
				if (c.rec.epoch < epoch) {
					cands.delete(id);
					continue;
				}
				if (betterRot(c.rec, best ? best.rec : cur)) best = c;
			}
			if (!best) break;
			await adopt(best);
		}
		while (cands.size > MAX_CANDIDATES)
			cands.delete(cands.keys().next().value as string);
		await ownerRekey();
	}

	async function adopt(c: { rec: Rot; key: Uint8Array }) {
		// (c) the rotation we leave stays a candidate (same epoch): nothing is lost if the choice has to be revisited
		if (
			curRot &&
			meshKey &&
			curRot.epoch === c.rec.epoch &&
			curRot.id !== c.rec.id
		)
			cands.set(curRot.id, { rec: curRot, key: meshKey });
		const { oldEpoch, oldKey, oldRid } = await switchEpoch(c.key, c.rec.epoch);
		curRot = c.rec;
		curRotId = c.rec.id;
		await store.set("rotId", curRotId);
		cands.delete(c.rec.id);
		for (const [id, x] of cands) if (x.rec.epoch < epoch) cands.delete(id);
		for (const l of [...links])
			if (l.deviceId && isRevoked(l.deviceId)) closeRec(l);
		await rememberRetired(oldEpoch, oldKey, oldRid);
		void refreshTrust();
		for (const t of c.rec.revoked) emit("revoked", { deviceId: t, epoch });
	}

	/**
	 * A known revocation has not been executed by an owner rotation yet: the devices it cut off may hold the current
	 * key, whenever they were paired (R5-B2). The UI shows it as "pendiente de que el dueño se conecte".
	 */
	const rekeyPending = () =>
		sec ? sec.unexecuted().devices.length > 0 : false;
	/**
	 * Members a rotation left out although they were admitted before it (e.g. their key record was not known yet), or
	 * members whose grant handed over no key (re-anchored): the owner re-keys to include them.
	 */
	function missed(): string[] {
		if (!sec || !curRot) return [];
		const cr = curRot;
		const out: string[] = [];
		for (const d of trusted.values()) {
			if (d.deviceId === root?.deviceId || cr.to.includes(d.deviceId)) continue;
			const g = sec.memberGrant(d.deviceId);
			if (!g || (g.epoch !== undefined && g.epoch >= cr.epoch)) continue;
			if (kexOf(d.deviceId)) out.push(d.deviceId);
		}
		return out;
	}
	/**
	 * Owner devices only: re-key at epoch + 1 without every device a revocation cut off that no owner rotation has
	 * executed yet (an admin's revocation is executed here), and to include members a previous rotation missed. Runs
	 * after every change of the security state (R5-S3: a re-key refused once is retried as soon as it can work).
	 */
	async function ownerRekey() {
		if (
			!running ||
			!sec ||
			!root ||
			root.deviceId !== vault.deviceId ||
			destroyed
		)
			return;
		const u = sec.unexecuted();
		if (u.devices.length === 0 && missed().length === 0) return;
		// R4-S3: no rotation lists more than a receiver accepts: cut in several rotations if needed
		const chunks: string[][] = [];
		let cur: string[] = [];
		let refs = 0;
		for (const dev of u.devices) {
			const n = sec.trust.grantsOf(dev).length;
			if (
				cur.length &&
				(cur.length >= MAX_ROT_MEMBERS || refs + n > MAX_ROT_REFS)
			) {
				chunks.push(cur);
				cur = [];
				refs = 0;
			}
			cur.push(dev);
			refs += n;
		}
		chunks.push(cur);
		for (const chunk of chunks) {
			if (!running || destroyed || !sec) return;
			try {
				await rotate(sec.unexecuted(new Set(chunk)));
			} catch (e) {
				err(e);
				return;
			}
		}
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
		if (hostSession && pairRids.has(rec.rid))
			await hostSession.s.handle(m, send);
		else if (guestSession && pairRids.has(rec.rid))
			await guestSession.s.handle(m, send);
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
		sendFrameWith(
			rec,
			K_HELLO,
			rec.nonce,
			lg ? lg.material : docMat,
			lg ? lg.rid : dataRid,
			true,
		).catch(err);
	}
	/** SF4: same challenge again, at most HANDSHAKE_MAX times per link. */
	function resendHello(rec: LinkRec) {
		// R5-S2: never in a retired room (a straggler challenges us again by itself)
		if (
			!rec.nonce ||
			rec.authed ||
			rec.closing ||
			rec.legacy ||
			(rec.hellosOut ?? 0) >= HANDSHAKE_MAX
		)
			return;
		rec.hellosOut = (rec.hellosOut ?? 0) + 1;
		// a fresh copy: a new signature and sequence number, so the peer sees a new frame, not a replay (R4-S1)
		const nonce = rec.nonce.slice();
		// under the current AND the recent retired keys: the peer may still be on (or have switched from) any of them
		void (async () => {
			const lg = rec.legacy;
			await sendFrameWith(
				rec,
				K_HELLO,
				nonce,
				lg ? lg.material : docMat,
				lg ? lg.rid : dataRid,
				true,
			);
			if (!lg)
				for (const r of retiredKeys())
					await sendFrameWith(rec, K_HELLO, nonce, r.material, r.rid, true);
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
		await sendFrameWith(
			rec,
			K_AUTH,
			concat(peerNonce, u32(via.epoch), utf8(peer)),
			via.material,
			via.rid,
			true,
		);
		maybeStart(rec);
	}
	function maybeStart(rec: LinkRec) {
		if (!rec.authed || !rec.authSent || rec.started || rec.closing) return;
		rec.started = true;
		const peer = rec.deviceId as string;
		if (rec.legacy) {
			// retired room (BL1): the peer may be a straggler, or a partition that rotated on its own. Hand it the
			// rotations it can adopt and our inventory; it converges (and re-keys if needed) and does the same for us.
			const lg = rec.legacy;
			void (async () => {
				await sendDocs(rec, rotationsFor(peer, lg.epoch), lg);
				if (sec) await sendTrust(rec, { t: "inv", ids: sec.inventory() }, lg);
			})().catch(err);
			return;
		}
		sendFrame(rec, K_SV, Y.encodeStateVector(doc)).catch(err);
		if (awareness.getLocalState())
			sendFrame(
				rec,
				K_AWARENESS,
				encodeAwarenessUpdate(awareness, [doc.clientID]),
			).catch(err);
		if (sec)
			void sendTrust(
				rec,
				{ t: "inv", ids: sec.inventory() },
				linkKey(rec),
			).catch(err);
		// the peer may be on another key of this epoch (its handshake crossed a key switch): push the rotation we are on
		// if it is a recipient, under every key it may hold
		const cur = curRot;
		if (cur && cur.to.includes(peer)) {
			const { id: _id, ...d } = cur;
			void sendTrustEverywhere(
				rec,
				utf8(JSON.stringify({ t: "docs", docs: [d] })),
			).catch(err);
		}
	}

	function wireLink(link: PeerLink, rid: string) {
		const isData = running && rid === dataRid;
		const lg = running && !isData ? legacy.get(rid) : undefined;
		const isPair = pairRids.has(rid);
		if (rid !== "" && !isData && !isPair && !lg) return link.close();
		const rec: LinkRec = {
			link,
			rid: isPair && !isData ? "pair" : rid,
			chain: Promise.resolve(),
		};
		if (lg) rec.legacy = lg;
		if (rid === "") rec.rid = ""; // room-less (qr-sdp): frames are self-describing
		// R5-S2: a bounded number of links still to authenticate per room, and per announced peer
		if (rec.rid !== "pair") {
			const pending = [...links].filter(
				(l) => !l.authed && !l.closing && l.rid === rec.rid,
			);
			if (
				pending.length >= MAX_UNAUTH_PER_ROOM ||
				pending.filter((l) => l.link.id === link.id).length >=
					MAX_UNAUTH_PER_PEER
			) {
				reject("too many links waiting to authenticate", link.id);
				return link.close();
			}
		}
		links.add(rec);
		// S5: until the link is authenticated it may reassemble at most 1 MiB, charged to a budget shared by all
		// unauthenticated links; afterwards the configured limit applies
		const reasm = new Reassembler({
			maxMessageBytes: PRE_AUTH_MAX,
			maxPendingBytes: PRE_AUTH_MAX,
			shared: preAuthBudget,
		});
		rec.lift = () =>
			reasm.setLimits({
				maxMessageBytes: opts.maxMessageBytes ?? DEFAULT_MAX_MESSAGE,
				maxPendingBytes: opts.maxMessageBytes ?? DEFAULT_MAX_MESSAGE,
				shared: null,
			});
		const dispatch = (d: Uint8Array) =>
			d[0] === F_PAIR
				? onPairFrame(
						{ ...rec, rid: rid === "" ? ([...pairRids][0] ?? "") : rid },
						d,
					)
				: d[0] === F_DATA || d[0] === F_SDATA
					? onData(rec, d)
					: undefined;
		link.onMessage((d) => {
			if (rec.closing) return;
			rec.chain = rec.chain
				.then(async () => {
					if (d[0] !== F_FRAG) return dispatch(d);
					const whole = await reasm.push(d);
					if (whole && whole[0] !== F_FRAG && !rec.closing)
						return dispatch(whole);
				})
				.catch(err);
		});
		link.onClose(() => {
			reasm.clear();
			dropHeld(rec);
			dropEarly(rec);
			links.delete(rec);
			setStatus();
		});
		if (isPair && guestSession) guestSession.s.attach(sendPair(link));
		if (signFrames && (isData || lg || (rid === "" && running)))
			startHandshake(rec);
		else if (isData || (rid === "" && running)) {
			sendFrame(rec, K_SV, Y.encodeStateVector(doc)).catch(err);
			const st = awareness.getLocalState();
			if (st)
				sendFrame(
					rec,
					K_AWARENESS,
					encodeAwarenessUpdate(awareness, [doc.clientID]),
				).catch(err);
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
			for (const t of transports)
				if (t.kind === "link")
					linkSubs.push(t.onLink((l, r) => !destroyed && wireLink(l, r)));
		}
		const stops: Array<() => void> = [];
		rooms.set(rid, () => {
			for (const s of stops) s();
		});
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
		// adopt what is pending (rotations already held) and, on an owner device, execute what is pending at once (a
		// revocation recorded before a restart, or a re-key interrupted by the app tearing the mesh down)
		void serialRot(considerRotations).catch(err);
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
	const onAwareness = (
		c: { added: number[]; updated: number[]; removed: number[] },
		origin: unknown,
	) => {
		if (origin === ORIGIN || !running) return;
		broadcast(
			K_AWARENESS,
			encodeAwarenessUpdate(awareness, [
				...c.added,
				...c.updated,
				...c.removed,
			]),
		);
	};
	awareness.on("update", onAwareness);

	// ---- rotation ----
	// The new mesh key never travels under the shared (old) key: it is wrapped per remaining device with a hybrid
	// key, HKDF(ML-KEM-768 secret || ECDH(owner static key, peer static key), swal-rotate/v4|preId|from|to) -> AES-GCM,
	// where preId hashes the rotation document (epoch, recipients, cuts, nonce); the owner signs its id. Every device
	// keeps the recent rotation documents in its local store and hands them to devices that were offline (through a
	// retired room, see `legacy`); a revoked device has no wrap and cannot unwrap anyone else's.
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
			const oldest = [...legacy.values()].sort(
				(x, y) => x.epoch - y.epoch,
			)[0] as Legacy;
			legacy.delete(oldest.rid);
			leaveRoom(oldest.rid);
		}
		await joinRoom(dataRid, sigKey!);
		return { oldEpoch: old.epoch, oldKey, oldRid };
	}

	/** SF5: persist a key this device retired, so a restart keeps serving stragglers from that room. */
	async function rememberRetired(e: number, key: Uint8Array, rid: string) {
		const list =
			((await store.get(RETIRED_KEY)) as
				| Array<{ e: number; k: string; rid: string }>
				| undefined) ?? [];
		const next = [
			...list.filter((x) => x.rid !== rid),
			{ e, k: b64uEncode(key), rid },
		].slice(-MAX_RETIRED);
		await store.set(RETIRED_KEY, next);
	}

	/** SF5: rejoin the rooms of keys this device retired (from its local store; the shared doc is never trusted). */
	async function syncLegacy() {
		if (!running) return;
		const list =
			((await store.get(RETIRED_KEY)) as
				| Array<{ e?: unknown; k?: unknown }>
				| undefined) ?? [];
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
			const rid = await deriveRoomId(
				raw,
				appId,
				topicName,
				e,
				instanceId || undefined,
			);
			if (rid === dataRid || (legacy.has(rid) && rooms.has(rid))) continue;
			legacy.set(rid, {
				epoch: e,
				rid,
				material: await deriveDocMaterial(raw, topicName),
			});
			await joinRoom(
				rid,
				await importAesKey(await hkdf(raw, `swal-signal/v1|${topicName}`)),
			);
		}
	}

	/**
	 * Owner only: re-key at epoch + 1 for every member (not revoked, key record known), cutting `part.devices` and
	 * executing `part.cut` (their grants). The rotation is a signed document: recorded here first, then handed to every
	 * connected device under every key it may hold, then adopted.
	 */
	async function rotate(part: {
		devices: string[];
		cut: string[];
		revs: string[];
	}) {
		const me = vault.deviceId;
		if (!sec || root?.deviceId !== me)
			throw new Error("only the owner re-keys the mesh");
		const newEpoch = epoch + 1;
		if (newEpoch > MAX_EPOCH)
			throw new Error("epoch limit reached: re-create the mesh");
		const cutDevs = new Set(part.devices);
		for (const l of [...links])
			if (l.deviceId && (cutDevs.has(l.deviceId) || isRevoked(l.deviceId)))
				closeRec(l);
		const pubs = new Map<string, { pub: Uint8Array; kem: Uint8Array }>();
		for (const d of trusted.values()) {
			if (d.deviceId === me || cutDevs.has(d.deviceId) || isRevoked(d.deviceId))
				continue;
			const k = kexOf(d.deviceId);
			if (k) pubs.set(d.deviceId, k);
			else
				err(
					new Error(
						`no key record of ${d.deviceId} yet: it gets the key with a later rotation`,
					),
				);
		}
		// R4-S3/R5-S3: a rotation receivers would refuse must never be adopted here (the owner would end alone)
		if (
			pubs.size > MAX_ROT_MEMBERS ||
			cutDevs.size > MAX_ROT_MEMBERS ||
			part.cut.length > MAX_ROT_REFS
		)
			throw new Error(
				`re-key refused: ${pubs.size} recipients and ${cutDevs.size} cut devices; a rotation carries at most ${MAX_ROT_MEMBERS} of each`,
			);
		const newKey = randomBytes(32);
		const base = {
			t: "rot" as const,
			v: 2 as const,
			inst: (root as TrustRoot).mid,
			epoch: newEpoch,
			from: me,
			to: [...pubs.keys()].sort(),
			revoked: [...cutDevs].sort(),
			cut: [...part.cut].sort(),
			revs: [...part.revs].sort().slice(0, MAX_ROT_REFS),
			n: b64uEncode(randomBytes(16)),
		};
		// wraps are bound to the pre-id; the id also commits to the whole wrap set, and the owner signs the id
		const pid = await rotationPreId(base);
		const priv = (await ecdhIdentity()).privateKey;
		const wraps: Record<string, string> = {};
		for (const [to, k] of pubs)
			wraps[to] = await wrapMeshKey(priv, k.pub, k.kem, pid, me, to, newKey);
		const wh = await wrapsHash(wraps);
		const id = await rotationId({ ...base, wh });
		const sig = b64uEncode(await vault.sign(rotationSigBytes(id)));
		if (destroyed) return; // torn down while signing: publish nothing, keep the vault as it was
		const docR: RotDoc = { ...base, wh, wraps, sig };
		const out = await sec.add(docR); // verified like any received rotation; records its cuts for good
		if (out.status !== "accepted" && out.status !== "duplicate")
			throw new Error(`re-key refused: ${out.reason}`);
		// 1) every connected device gets the rotation under every key it may hold, 2) switch
		const body = utf8(JSON.stringify({ t: "docs", docs: [docR] }));
		await Promise.all(
			[...links]
				.filter(
					(l) =>
						!l.closing &&
						l.deviceId &&
						l.rid !== "pair" &&
						(!signFrames || l.authed),
				)
				.map((l) => sendTrustEverywhere(l, body).catch(err)),
		);
		await adopt({ rec: { ...docR, id }, key: newKey });
		announce([`R:${id}`]);
	}

	/**
	 * Revoke a device: signed web/trust revocations of its grants, cut here at once and handed to every device. On the
	 * owner the mesh is re-keyed right away; on an admin it is a REQUEST that the next owner device online executes
	 * (until then `rekeyPending` is true: the revoked device still holds the current key).
	 */
	async function revoke(
		deviceId: string,
		o: {
			heads?: Readonly<Record<string, number | { seq: number; id: string }>>;
			reason?: string;
		} = {},
	) {
		await ready;
		if (deviceId === vault.deviceId)
			throw new Error("cannot revoke the current device");
		if (!sec || !root) throw new Error("unknown device");
		await refreshTrust();
		if (deviceId === root.deviceId)
			throw new Error(`not authorized to revoke ${deviceId}`);
		if (sec.trust.grantsOf(deviceId).length === 0)
			throw new Error("unknown device");
		if (opts.canRotate && !(await opts.canRotate(vault.deviceId, deviceId)))
			throw new Error(`not authorized to revoke ${deviceId}`);
		const docs = await sec.revocationsFor(signer, deviceId, {
			heads: o.heads,
			reason: o.reason,
			now: now(),
		});
		if (docs.length === 0 && !isRevoked(deviceId))
			throw new Error(`not authorized to revoke ${deviceId}`);
		if (!running) await start();
		await addLocal(docs);
		// cut the revoked device off SYNCHRONOUSLY: its link must not be reachable by anything below
		for (const l of [...links])
			if (l.deviceId === deviceId || (l.deviceId && isRevoked(l.deviceId)))
				closeRec(l);
		await refreshTrust();
		emit("revoked", {
			deviceId,
			epoch,
			pending: root.deviceId !== vault.deviceId,
		});
		await serialRot(ownerRekey).catch(err);
	}

	/** Owner only: own grants for devices that lost membership through a revoked admin (cascade). */
	async function reanchor(deviceIds: string[]) {
		await ready;
		if (!sec || root?.deviceId !== vault.deviceId)
			throw new Error("only the owner re-anchors devices");
		const grants = [];
		for (const id of deviceIds) {
			if (sec.memberGrant(id)) continue;
			const old = sec.trust.grantsOf(id)[0];
			if (!old) throw new Error(`unknown device ${id}`);
			grants.push(
				await sec.issueGrant(signer, old.subject.pub, {
					role: old.delegate >= 1 ? "admin" : "member",
					name: old.name,
					now: now(),
				}),
			);
		}
		await addLocal(grants);
		await refreshTrust();
		await serialRot(ownerRekey).catch(err);
	}

	// ---- pairing ----
	/** First pairing of a fresh mesh: this device becomes its owner (the pinned trust root). */
	async function ensureRoot(): Promise<TrustRoot> {
		if (root && sec) return root;
		// a NEW mesh id, never one read from anywhere else (anybody could copy another mesh's id)
		const mid = b64uEncode(randomBytes(16));
		root = { mid, deviceId: vault.deviceId, pub: selfPub };
		await store.set("root", root);
		await openSecurity(root);
		await publishKex();
		return root;
	}

	/** Grant chain of this device (its member grant, then its issuers' up to the root): what a guest needs to verify. */
	function ownChain(): unknown[] {
		const out: unknown[] = [];
		let g = sec?.memberGrant(vault.deviceId) ?? null;
		for (let i = 0; g && i < 8; i++) {
			out.push(g);
			g = g.parent ? (sec?.trust.getGrant(g.parent) ?? null) : null;
		}
		return out;
	}

	async function pairHost(o: PairHostOptions = {}): Promise<PairOffer> {
		await ready;
		const guestRole: Role = o.role ?? "member";
		const r = await ensureRoot();
		await refreshTrust();
		const mine = selfRole();
		if (!mine || !canIssue(mine, guestRole))
			throw new Error(
				`this device (${mine ?? "not admitted"}) cannot admit a ${guestRole}`,
			);
		// R5-S3: refuse an admission the next re-key could not carry (receivers accept at most MAX_ROT_MEMBERS recipients)
		if (trusted.size + 1 >= MAX_ROT_MEMBERS)
			throw new Error(`the mesh is full (${MAX_ROT_MEMBERS} devices)`);
		if (
			mine === "admin" &&
			(sec?.trust
				.docs()
				.filter((d) => d.t === "grant" && d.issuer === vault.deviceId).length ??
				0) >= MAX_MEMBERS_PER_ADMIN
		)
			throw new Error(
				`this admin already admitted ${MAX_MEMBERS_PER_ADMIN} devices`,
			);
		await vault.getOrCreateMeshKey();
		const offer = await createPairOffer(vault, {
			mid: r.mid,
			root: r.deviceId,
			appId,
			topic: topicName,
			now: now(),
		});
		const rid = await derivePairRoomId(offer.pairSecret);
		const pairKey = await derivePairKey(offer.pairSecret);
		const host = new HostPairing(offer, {
			now,
			verify: identityVerify,
			prove: async (transcript) => ({
				pub: selfPub,
				sig: b64uEncode(
					await vault.sign(hostProofBytes(transcript, vault.deviceId, selfPub)),
				),
			}),
			onSas: (p: SasPrompt) => emit("sas", { role: "host", ...p }),
			buildGrant: async (guest): Promise<GrantBody> => {
				// B1: the ack already proved possession of guest.pub and deviceId = fingerprint(pub)
				if (guest.deviceId === vault.deviceId || guest.deviceId === r.deviceId)
					throw new Error("guest claims the host/root identity");
				if (!sec) throw new Error("no security state");
				if (
					opts.authorizeDevice &&
					!(await opts.authorizeDevice(guest.deviceId, b64uDecode(guest.pub)))
				) {
					throw new Error("device not authorized by the mesh policy");
				}
				// the key, its epoch and its rotation are read together, at the very moment the grant is made (a re-key may
				// have happened since the offer was shown)
				const keyNow = meshKey ?? (await vault.getOrCreateMeshKey());
				const epochNow = epoch;
				const rotNow = curRot;
				// a grant of its own (re-admission included: a new grant id, untouched by earlier revocations), handed the
				// key of this epoch
				const grant = await sec.issueGrant(signer, guest.pub, {
					role: guestRole === "admin" ? "admin" : "member",
					name: guest.name,
					epoch: epochNow,
					now: now(),
				});
				const dev: Device = {
					...guest,
					addedAt: grant.issuedAt,
					role: guestRole,
					admittedBy: vault.deviceId,
				};
				const extra = o.extra ? await o.extra(dev) : undefined;
				await addLocal([grant]);
				await refreshTrust();
				const docs: unknown[] = [grant, ...ownChain()];
				for (const k of [sec.kexDoc(r.deviceId), sec.kexDoc(vault.deviceId)])
					if (k && !docs.includes(k)) docs.push(k);
				if (rotNow && JSON.stringify(rotNow).length < 128 * 1024) {
					const { id: _id, ...d } = rotNow;
					docs.push(d);
				}
				return {
					meshKey: b64uEncode(keyNow),
					epoch: epochNow,
					mid: r.mid,
					hostDevice: selfDevice(),
					root: r,
					docs,
					...(rotNow ? { rotId: rotNow.id } : {}),
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
		const timer = setTimeout(
			() => endPairing(rid),
			offer.payload.exp - now() + 1000,
		);
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
			const drained = Promise.race([
				outQ.get(l.link) ?? Promise.resolve(),
				new Promise((r) => setTimeout(r, 10_000)),
			]);
			void drained.then(() => setTimeout(() => l.link.close(), 500));
		}
		if (hostSession?.rid === rid) hostSession = null;
		if (guestSession?.rid === rid) guestSession = null;
		setStatus();
	}

	const ROOT_MISMATCH_ERR =
		"pairing refused: this mesh id is pinned to another owner key";
	const MOVE_MESH_ERR =
		"this device belongs to another mesh: to join a different one, create a new Mesh with a fresh Y.Doc";
	/** No shared content at all (the mesh itself never writes to the doc). */
	function docIsFresh(): boolean {
		for (const [, t] of doc.share) {
			const ty = t as unknown as {
				_start: unknown;
				_map: Map<string, unknown>;
			};
			if (ty._start !== null || ty._map.size > 0) return false;
		}
		return true;
	}

	async function pairJoin(
		encoded: string,
		o: { confirmSas?: (code: string) => Promise<boolean> | boolean } = {},
	) {
		await ready;
		const p: PairPayload = decodePairPayload(encoded);
		if (p.appId !== appId || p.topic !== topicName)
			throw new Error("pairing payload is for a different app/topic");
		// B3: a device moving to ANOTHER mesh would merge this mesh's doc into it (and keep serving it). Only a fresh
		// doc may change meshes: create a new Mesh with a new Y.Doc for that.
		// S6: trust on first use. The QR names the root; a device never re-pins another key for a mesh id it already knows
		if (root && root.mid === p.mid && root.deviceId !== p.root)
			throw new Error(ROOT_MISMATCH_ERR);
		const moving = root !== null && root.mid !== p.mid;
		if (moving && !docIsFresh()) throw new Error(MOVE_MESH_ERR);
		// ...and while moving, the old mesh must not fill the fresh doc: go offline from it (resumed on failure)
		const resumeOld = moving && running;
		if (resumeOld) stopNetwork();
		const confirm =
			o.confirmSas ??
			((code: string) =>
				new Promise<boolean>((resolve) =>
					emit("sas", {
						role: "guest",
						code,
						confirm: () => resolve(true),
						reject: () => resolve(false),
					}),
				));
		const guest = await GuestPairing.create(p, vault, {
			name: opts.deviceName ?? "device",
			onSas: async (code) => Boolean(await confirm(code)),
			now: now(),
		});
		const rid = await derivePairRoomId(b64uDecode(p.pairSecret));
		guestSession = { s: guest, rid };
		pairRids.add(rid);
		await joinRoom(rid, await derivePairKey(b64uDecode(p.pairSecret)));
		const timeout = setTimeout(
			() => guest.fail(new Error("pairing timed out")),
			Math.max(1000, p.exp - now()),
		);
		try {
			const g = await guest.result;
			clearTimeout(timeout);
			// the trust root and our grant arrive over the SAS-authenticated session; the grant chain must be valid and
			// issued by the very host that proved the identity named by the QR
			if (!g.root || !Array.isArray(g.docs))
				throw new Error("pairing grant carries no grant (host too old?)");
			if (!isEpoch(g.epoch)) throw new Error("pairing grant: bad epoch");
			if (g.root.mid !== p.mid || g.mid !== p.mid)
				throw new Error(
					"pairing grant: mesh id does not match the pairing code",
				);
			if (g.root.deviceId !== p.root)
				throw new Error(
					"pairing grant: trust root does not match the pairing code",
				);
			if (!(await idMatchesPub(g.root.deviceId, g.root.pub)))
				throw new Error("pairing grant: invalid trust root");
			if (
				root &&
				root.mid === g.root.mid &&
				(root.deviceId !== g.root.deviceId || root.pub !== g.root.pub)
			)
				throw new Error(ROOT_MISMATCH_ERR);
			// verify in a scratch state first: nothing is pinned or stored before the grant checks out
			const probe = await SecurityState.open({
				root: g.root,
				store: memoryStore(),
				schema: opts.trustSchema,
				now,
			});
			await probe.addMany(g.docs);
			const mine = probe.memberGrant(vault.deviceId);
			if (!mine || mine.subject.pub !== selfPub)
				throw new Error("pairing grant: invalid grant for this device");
			// the host proved (inside the session) that it holds hostId's ML-DSA key; the grant must come from it
			if (mine.issuer !== p.hostId)
				throw new Error("pairing grant: grant not issued by the paired host");
			if (probe.identityOf(p.hostId) !== g.hostProof?.pub)
				throw new Error("pairing grant: grant not issued by the paired host");
			const switching = root?.mid !== g.root.mid;
			if (switching && root && !docIsFresh()) throw new Error(MOVE_MESH_ERR);
			// same mesh: never step back to an older epoch (and its older key) because the host lags behind us
			if (!switching && root && g.epoch < epoch)
				throw new Error(
					`pairing refused: the host is at epoch ${g.epoch}, this device at ${epoch}`,
				);
			// leave the current network BEFORE touching keys or the doc: nothing of one mesh may reach the other
			if (running) stopNetwork();
			if (switching) {
				// nothing of the old mesh's security state survives a move
				secUnsub?.();
				sec = null;
				trusted = new Map();
				legacy.clear();
				replay.clear();
				cands.clear();
				unwrapFailed.clear();
				curRot = null;
				curRotId = null;
				for (const k of [
					"sec/trust",
					"sec/kex",
					"sec/rots",
					"sec/cuts",
					"sec/gone",
				])
					await store.set(k, []);
				await store.set(RETIRED_KEY, []);
				await store.set("rotId", null);
			}
			root = g.root;
			await store.set("root", root);
			if (
				g.hostDevice &&
				g.hostDevice.deviceId === g.root.deviceId &&
				typeof g.hostDevice.name === "string"
			) {
				ownerName = g.hostDevice.name;
				await store.set("ownerName", ownerName);
			}
			if (!sec) await openSecurity(root);
			await (sec as SecurityState).addMany(g.docs);
			const key = b64uDecode(g.meshKey);
			await vault.setMeshKey(key);
			await persistEpoch(g.epoch);
			epoch = g.epoch;
			// the rotation that produced this key (if any): lets this device take part in tie-breaks of its epoch
			curRotId = typeof g.rotId === "string" ? g.rotId : null;
			const cr = curRotId ? sec?.rotation(curRotId) : undefined;
			curRot = cr && cr.epoch === g.epoch ? cr : null;
			cands.clear();
			await store.set("rotId", curRotId);
			await publishKex();
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
		reanchor,
		get security(): MeshSecurity | null {
			const st = sec;
			if (!st) return null;
			return {
				trust: st.trust,
				docs: async () => st.get(st.inventory()),
				rotations: () => st.rotations(),
				keyAgreement: (id: string) => st.keyAgreement(id),
				executedCuts: () => st.executedCuts(),
				add: async (d: unknown) =>
					(await addLocal([d]))[0] ?? { status: "rejected" },
				addMany: (ds: readonly unknown[]) => addLocal(ds),
				issueGrant: (
					subjectPub: string,
					o2: { role: "admin" | "member"; name?: string },
				) => st.issueGrant(signer, subjectPub, { ...o2, now: now() }),
			};
		},
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
			if (!set) {
				set = new Set();
				listeners.set(event, set);
			}
			set.add(cb);
			return () => void set!.delete(cb);
		},
	};
}
