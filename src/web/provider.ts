import * as Y from "yjs";
import { Awareness, applyAwarenessUpdate, encodeAwarenessUpdate, removeAwarenessStates } from "y-protocols/awareness";
import { deriveDocKey, hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
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

interface LinkRec {
	link: PeerLink;
	rid: string;
	deviceId?: string;
	chain: Promise<void>;
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
	let docKey: CryptoKey | null = null;
	let sigKey: CryptoKey | null = null;
	let dataRid = "";
	let epoch = 0;
	let status: MeshStatus = "off";
	const links = new Set<LinkRec>();
	const rooms = new Map<string, () => void>(); // rid -> leave
	const linkSubs: Array<() => void> = [];
	let hostSession: { s: HostPairing; rid: string } | null = null;
	let guestSession: { s: GuestPairing; rid: string } | null = null;
	let pairRids = new Set<string>();

	const peerIds = () => [...new Set([...links].filter((l) => l.deviceId && l.rid !== "pair").map((l) => l.deviceId!))];
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
		if (devices().length > 1 && !destroyed) await start(); // already paired: resume
	})();
	ready.catch(err);

	// ---- keys ----
	async function loadKeys(raw?: Uint8Array) {
		meshKey = raw ?? (await vault.getOrCreateMeshKey());
		epoch = Math.max(Number(await vault.getEpoch?.() ?? 0), Number(meta.get("epoch") ?? 0), epoch);
		docKey = await deriveDocKey(meshKey, topicName);
		sigKey = await importAesKey(await hkdf(meshKey, `swal-signal/v1|${topicName}`));
		dataRid = await deriveRoomId(meshKey, appId, topicName, epoch);
	}

	// ---- framing ----
	async function sendFrame(rec: LinkRec, kind: number, body: Uint8Array) {
		if (!docKey) return;
		const id = utf8(vault.deviceId);
		const sealed = await sealUpdate(docKey, concat(new Uint8Array([kind]), body), `${dataRid}|${vault.deviceId}`);
		rec.link.send(concat(new Uint8Array([F_DATA, id.length]), id, sealed));
	}
	const established = () => [...links].filter((l) => l.rid === dataRid || l.rid === "");
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
		if (!docKey || !running) return;
		const idLen = data[1];
		const sender = fromUtf8(data.subarray(2, 2 + idLen));
		let plain: Uint8Array;
		try {
			plain = await openUpdate(docKey, data.subarray(2 + idLen), `${dataRid}|${sender}`);
		} catch {
			return; // wrong key / tampered / other epoch: drop silently
		}
		if (!rec.deviceId) {
			rec.deviceId = sender;
			setStatus();
		}
		const kind = plain[0];
		const body = plain.subarray(1);
		if (kind === K_SV) {
			await sendFrame(rec, K_UPDATE, Y.encodeStateAsUpdate(doc, body));
		} else if (kind === K_UPDATE) {
			Y.applyUpdate(doc, body, ORIGIN);
		} else if (kind === K_AWARENESS) {
			applyAwarenessUpdate(awareness, body, ORIGIN);
		} else if (kind === K_ROTATE) {
			const r = JSON.parse(fromUtf8(body)) as { meshKey: string; epoch: number; revoked: string };
			if (r.epoch > epoch) await adoptRotation(b64uDecode(r.meshKey), r.epoch, r.revoked);
		}
	}

	async function onPairFrame(rec: LinkRec, data: Uint8Array) {
		const msg = JSON.parse(fromUtf8(data.subarray(1)));
		const send = sendPair(rec.link);
		if (hostSession && pairRids.has(rec.rid)) await hostSession.s.handle(msg, send);
		else if (guestSession && pairRids.has(rec.rid)) await guestSession.s.handle(msg, send);
	}

	function wireLink(link: PeerLink, rid: string) {
		const isData = running && rid === dataRid;
		const isPair = pairRids.has(rid);
		if (rid !== "" && !isData && !isPair) return link.close();
		const rec: LinkRec = { link, rid: isPair && !isData ? "pair" : rid, chain: Promise.resolve() };
		if (rid === "") rec.rid = ""; // room-less (qr-sdp): frames are self-describing
		links.add(rec);
		link.onMessage((d) => {
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
	}

	function stopNetwork() {
		running = false;
		for (const rid of [...rooms.keys()]) leaveRoom(rid);
		for (const l of [...links]) l.link.close();
		links.clear();
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
	async function adoptRotation(newKey: Uint8Array, newEpoch: number, revoked: string) {
		await vault.setMeshKey(newKey);
		await vault.setEpoch?.(newEpoch);
		const oldRid = dataRid;
		epoch = newEpoch;
		await loadKeys(newKey);
		for (const l of [...links]) if (l.deviceId === revoked) l.link.close();
		leaveRoom(oldRid);
		for (const l of links) if (l.rid === oldRid) l.rid = dataRid;
		await joinRoom(dataRid, sigKey!);
		emit("revoked", { deviceId: revoked, epoch });
	}

	async function revoke(deviceId: string) {
		await ready;
		if (deviceId === vault.deviceId) throw new Error("cannot revoke the current device");
		if (!meta.has(DEV + deviceId)) throw new Error("unknown device");
		if (!running) await start();
		const newKey = randomBytes(32);
		const newEpoch = epoch + 1;
		const payload = utf8(JSON.stringify({ meshKey: b64uEncode(newKey), epoch: newEpoch, revoked: deviceId }));
		for (const l of [...links]) if (l.deviceId === deviceId) l.link.close();
		// 1) tell the remaining peers under the OLD key, 2) switch, 3) publish the removal under the NEW key
		await Promise.all(established().filter((l) => l.deviceId).map((l) => sendFrame(l, K_ROTATE, payload)));
		await vault.setMeshKey(newKey);
		await vault.setEpoch?.(newEpoch);
		const oldRid = dataRid;
		epoch = newEpoch;
		await loadKeys(newKey);
		leaveRoom(oldRid);
		for (const l of links) if (l.rid === oldRid) l.rid = dataRid;
		await joinRoom(dataRid, sigKey!);
		doc.transact(() => {
			meta.delete(DEV + deviceId);
			meta.set("epoch", newEpoch);
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
