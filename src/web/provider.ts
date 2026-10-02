import * as Y from "yjs";
import { Awareness, applyAwarenessUpdate, encodeAwarenessUpdate, removeAwarenessStates } from "y-protocols/awareness";
import { deriveDocMaterial, deriveSenderKey, hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
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
import { derivePairRoomId, deriveRoomId } from "./rooms.js";
import type { Device, PeerLink, RtcOptions, SigTransport, VaultClient } from "./types.js";
import { b64uDecode, b64uEncode, concat, fromUtf8, randomBytes, utf8 } from "./util.js";
import { connectViaSignaling } from "./webrtc.js";

export type MeshStatus = "off" | "connecting" | "online";
export type MeshEvent = "status" | "peers" | "devices" | "sas" | "paired" | "revoked" | "error";

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
	pairHost(): Promise<PairOffer>;
	pairJoin(payload: string, opts?: { confirmSas?: (code: string) => Promise<boolean> | boolean }): Promise<void>;
	devices(): Device[];
	revoke(deviceId: string): Promise<void>;
	leave(): void;
	destroy(): void;
	on(event: MeshEvent, cb: (data: any) => void): () => void;
}

const F_DATA = 1;
const F_PAIR = 2;
const K_SV = 0;
const K_UPDATE = 1;
const K_AWARENESS = 2;
const K_ROTATE = 3;
const ORIGIN = Symbol("swal-mesh");
const DEV = "dev/";
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
}

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
	let epoch = 0;
	let status: MeshStatus = "off";
	const links = new Set<LinkRec>();
	const senderKeys = new Map<string, CryptoKey>(); // `${epoch}|${deviceId}` -> per-sender AES-GCM key
	const revokedIds = new Set<string>();
	const legacy = new Map<string, Legacy>(); // retired data rid -> its epoch material
	let ecdhId: EcdhIdentity | null = null;
	const rooms = new Map<string, () => void>(); // rid -> leave
	const linkSubs: Array<() => void> = [];
	let hostSession: { s: HostPairing; rid: string } | null = null;
	let guestSession: { s: GuestPairing; rid: string } | null = null;
	let pairRids = new Set<string>();

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

	// ---- devices (inside the encrypted-on-the-wire Y.Doc 'meta' map) ----
	const devices = (): Device[] =>
		[...meta.keys()].filter((k) => k.startsWith(DEV)).map((k) => meta.get(k) as Device).sort((a, b) => a.addedAt - b.addedAt);
	meta.observe(() => emit("devices", devices()));

	// ---- persistence ----
	let persistence: { destroy(): Promise<void> | void } | null = null;
	const ready = (async () => {
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
		if (devices().length > 1 && !destroyed) await start(); // already paired: resume
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
	/** Verified ECDH public key of a registered device, or null. */
	async function peerEcdhPub(deviceId: string): Promise<Uint8Array | null> {
		const dev = meta.get(DEV + deviceId) as Device | undefined;
		const e = meta.get(ECDH_PREFIX + deviceId) as { pub: string; sig: string } | undefined;
		if (!dev || !e || typeof e.pub !== "string" || typeof e.sig !== "string") return null;
		try {
			const ok = await vault.verify(b64uDecode(dev.pub), ecdhSignedBytes(deviceId, e.pub), b64uDecode(e.sig));
			return ok ? b64uDecode(e.pub) : null;
		} catch {
			return null;
		}
	}

	// ---- keys ----
	async function senderKey(material: Uint8Array, ep: number, deviceId: string): Promise<CryptoKey> {
		const k = `${ep}|${deviceId}`;
		let key = senderKeys.get(k);
		if (!key) senderKeys.set(k, (key = await deriveSenderKey(material, topicName, deviceId)));
		return key;
	}
	async function loadKeys(raw?: Uint8Array) {
		meshKey = raw ?? (await vault.getOrCreateMeshKey());
		epoch = Math.max(Number(await vault.getEpoch?.() ?? 0), Number(meta.get("epoch") ?? 0), epoch);
		docMat = await deriveDocMaterial(meshKey, topicName);
		sigKey = await importAesKey(await hkdf(meshKey, `swal-signal/v1|${topicName}`));
		dataRid = await deriveRoomId(meshKey, appId, topicName, epoch);
	}

	// ---- framing ----
	// Every sender seals under its OWN subkey (HKDF over the sender's deviceId); receivers derive it
	// from the deviceId in the frame header (also bound in the AAD). Wire: F_DATA | idLen | id | nonce | ct+tag.
	async function sendFrame(rec: LinkRec, kind: number, body: Uint8Array) {
		const lg = rec.legacy;
		const mat = lg ? lg.material : docMat;
		if (!mat || rec.closing) return;
		const key = await senderKey(mat, lg ? lg.epoch : epoch, vault.deviceId);
		const id = utf8(vault.deviceId);
		const sealed = await sealUpdate(key, concat(new Uint8Array([kind]), body), `${lg ? lg.rid : dataRid}|${vault.deviceId}`);
		if (rec.closing) return;
		rec.link.send(concat(new Uint8Array([F_DATA, id.length]), id, sealed));
	}
	const established = () =>
		[...links].filter(
			(l) => !l.closing && !l.legacy && (l.rid === dataRid || l.rid === "") && !(l.deviceId && revokedIds.has(l.deviceId)),
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
			f = (m: unknown) => link.send(concat(new Uint8Array([F_PAIR]), utf8(JSON.stringify(m))));
			pairSenders.set(link, f);
		}
		return f;
	}

	async function onData(rec: LinkRec, data: Uint8Array) {
		const lg = rec.legacy;
		const mat = lg ? lg.material : docMat;
		if (!mat || !running || rec.closing) return;
		const idLen = data[1];
		const sender = fromUtf8(data.subarray(2, 2 + idLen));
		if (revokedIds.has(sender)) return;
		let plain: Uint8Array;
		try {
			const key = await senderKey(mat, lg ? lg.epoch : epoch, sender);
			plain = await openUpdate(key, data.subarray(2 + idLen), `${lg ? lg.rid : dataRid}|${sender}`);
		} catch {
			return; // wrong key / tampered / other epoch: drop silently
		}
		if (rec.closing) return;
		if (!rec.deviceId) {
			rec.deviceId = sender;
			setStatus();
		}
		const kind = plain[0];
		const body = plain.subarray(1);
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
			Y.applyUpdate(doc, body, ORIGIN);
		} else if (kind === K_AWARENESS) {
			applyAwarenessUpdate(awareness, body, ORIGIN);
		} else if (kind === K_ROTATE) {
			await handleRotate(body);
		}
	}

	async function handleRotate(body: Uint8Array) {
		let r: RotateMsg;
		try {
			r = JSON.parse(fromUtf8(body)) as RotateMsg;
		} catch {
			return;
		}
		if (r.to !== vault.deviceId || r.epoch !== epoch + 1 || revokedIds.has(r.from) || r.from === r.revoked) return;
		const fromPub = await peerEcdhPub(r.from);
		if (!fromPub) return;
		let newKey: Uint8Array;
		try {
			newKey = await unwrapMeshKey((await ecdhIdentity()).privateKey, fromPub, r.epoch, r.from, r.to, b64uDecode(r.wrap));
		} catch {
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
		link.onMessage((d) => {
			if (rec.closing) return;
			rec.chain = rec.chain
				.then(() => (d[0] === F_PAIR ? onPairFrame({ ...rec, rid: rid === "" ? [...pairRids][0] ?? "" : rid }, d) : d[0] === F_DATA ? onData(rec, d) : undefined))
				.catch(err);
		});
		link.onClose(() => {
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
		await vault.setEpoch?.(newEpoch);
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
			const rid = await deriveRoomId(raw, appId, topicName, e);
			if (legacy.has(rid) && rooms.has(rid)) continue;
			legacy.set(rid, { epoch: e, rid, material: await deriveDocMaterial(raw, topicName) });
			await joinRoom(rid, await importAesKey(await hkdf(raw, `swal-signal/v1|${topicName}`)));
		}
	}
	meta.observe((ev) => {
		if ([...ev.keysChanged].some((k) => k.startsWith(OLD_PREFIX))) void syncLegacy().catch(err);
	});

	async function adoptRotation(newKey: Uint8Array, newEpoch: number, revoked: string) {
		revokedIds.add(revoked);
		for (const l of [...links]) if (l.deviceId === revoked) closeRec(l);
		const { oldEpoch, oldKey } = await switchEpoch(newKey, newEpoch);
		doc.transact(() => {
			meta.set(OLD_PREFIX + oldEpoch, b64uEncode(oldKey));
			meta.set("epoch", newEpoch);
		});
		emit("revoked", { deviceId: revoked, epoch });
	}

	async function revoke(deviceId: string) {
		await ready;
		if (deviceId === vault.deviceId) throw new Error("cannot revoke the current device");
		if (!meta.has(DEV + deviceId)) throw new Error("unknown device");
		if (!running) await start();
		// cut the revoked device off SYNCHRONOUSLY: its link must not be reachable by anything below
		revokedIds.add(deviceId);
		for (const l of [...links]) if (l.deviceId === deviceId) closeRec(l);
		const newKey = randomBytes(32);
		const newEpoch = epoch + 1;
		const priv = (await ecdhIdentity()).privateKey;
		const wraps = new Map<string, RotateMsg>();
		for (const d of devices()) {
			if (d.deviceId === vault.deviceId || d.deviceId === deviceId) continue;
			const pub = await peerEcdhPub(d.deviceId);
			if (!pub) {
				err(new Error(`no verified ECDH key for ${d.deviceId}: it must be re-paired after the rotation`));
				continue;
			}
			const wrap = await wrapMeshKey(priv, pub, newEpoch, vault.deviceId, d.deviceId, newKey);
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
			meta.delete(ECDH_PREFIX + deviceId);
			meta.set("epoch", newEpoch);
			meta.set(OLD_PREFIX + oldEpoch, b64uEncode(oldKey));
			for (const [to, m] of wraps) meta.set(`${ROT_PREFIX}${newEpoch}:${to}`, { from: m.from, wrap: m.wrap, revoked: deviceId });
		});
		emit("revoked", { deviceId, epoch });
	}

	// ---- pairing ----
	async function pairHost(): Promise<PairOffer> {
		await ready;
		const key = await vault.getOrCreateMeshKey();
		if (!meta.has("mid")) meta.set("mid", b64uEncode(randomBytes(16)));
		const offer = await createPairOffer(vault, { mid: meta.get("mid"), appId, topic: topicName, now: now() });
		const rid = await derivePairRoomId(offer.pairSecret);
		const pairKey = await derivePairKey(offer.pairSecret);
		const host = new HostPairing(offer, {
			now,
			onSas: (p: SasPrompt) => emit("sas", { role: "host", ...p }),
			buildGrant: async (): Promise<GrantBody> => ({
				meshKey: b64uEncode(key),
				epoch,
				mid: meta.get("mid"),
				snapshot: b64uEncode(Y.encodeStateAsUpdate(doc)),
				hostDevice: meta.get(DEV + vault.deviceId),
			}),
			onPaired: (d) => {
				doc.transact(() => meta.set(DEV + d.deviceId, d));
				emit("paired", d);
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
		// let the last frame (grant) flush before dropping the pairing links
		const pairLinks = [...links].filter((l) => l.rid === "pair");
		setTimeout(() => pairLinks.forEach((l) => l.link.close()), 500);
		if (hostSession?.rid === rid) hostSession = null;
		if (guestSession?.rid === rid) guestSession = null;
		setStatus();
	}

	async function pairJoin(encoded: string, o: { confirmSas?: (code: string) => Promise<boolean> | boolean } = {}) {
		await ready;
		const p: PairPayload = decodePairPayload(encoded);
		if (p.appId !== appId || p.topic !== topicName) throw new Error("pairing payload is for a different app/topic");
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
			const key = b64uDecode(g.meshKey);
			await vault.setMeshKey(key);
			await vault.setEpoch?.(g.epoch);
			epoch = g.epoch;
			Y.applyUpdate(doc, b64uDecode(g.snapshot), ORIGIN);
			meta.set("epoch", g.epoch);
			meta.set(DEV + vault.deviceId, {
				deviceId: vault.deviceId,
				pub: b64uEncode(vault.devicePublicKey),
				name: opts.deviceName ?? "device",
				addedAt: now(),
			} satisfies Device);
			await publishEcdh();
			endPairing(rid);
			emit("paired", g.hostDevice);
			await start();
		} catch (e) {
			clearTimeout(timeout);
			endPairing(rid);
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
