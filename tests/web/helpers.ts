import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import * as Y from "yjs";
import type { LoopbackHub } from "../../src/web/index.js";
import {
	createLoopbackHub,
	createMesh,
	deviceIdOf,
	type Mesh,
	type MeshOptions,
	type VaultClient,
} from "../../src/web/index.js";
import {
	createPairOffer,
	type GrantBody,
	GuestPairing,
	HostPairing,
	hostProofBytes,
	type PairPayload,
} from "../../src/web/pairing.js";
import { identityVerify, kemKeygen } from "../../src/web/pq.js";
import { generateEcdhIdentity } from "../../src/web/rotation.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";

// A deviceId is the fingerprint of the identity key (B1). Tests name devices with labels ("devA"...) and map
// between both: `idOf(label)` = id of the LAST vault created with that label (tests in a file run sequentially),
// `label(id)` / `labels(ids)` for readable assertions.
const ID_OF = new Map<string, string>();
const LABEL_OF = new Map<string, string>();
export const idOf = (l: string): string => {
	const id = ID_OF.get(l);
	if (!id) throw new Error(`no vault labelled ${l}`);
	return id;
};
export const label = (id: string): string => LABEL_OF.get(id) ?? id;
export const labels = (ids: Iterable<string>): string[] =>
	[...ids].map(label).sort();
export const devLabels = (m: Mesh): string[] =>
	labels(m.devices().map((d) => d.deviceId));
export const peerLabels = (m: Mesh): string[] => labels(m.peers);

export async function makeVault(
	lbl: string,
): Promise<VaultClient & { meshKey: Uint8Array | null; epoch: number }> {
	const kp = ml_dsa65.keygen(); // ML-DSA-65 identity (AGENTS.md §2)
	const pub = kp.publicKey;
	const id = await deviceIdOf(pub);
	ID_OF.set(lbl, id);
	LABEL_OF.set(id, lbl);
	const ecdh = await generateEcdhIdentity(); // persistent for the life of this vault (like a real one)
	const kem = kemKeygen(); // ML-KEM-768 half of the hybrid rotation wraps, persistent as well
	const kv = new Map<string, unknown>(); // local, non-replicated state (trust pins, revocations): survives "reloads"
	const v = {
		deviceId: id,
		devicePublicKey: pub,
		meshKey: null as Uint8Array | null,
		epoch: 0,
		async getOrCreateMeshKey() {
			return (v.meshKey ??= randomBytes(32));
		},
		async setMeshKey(raw: Uint8Array) {
			v.meshKey = raw;
		},
		async sign(data: Uint8Array) {
			return ml_dsa65.sign(data, kp.secretKey);
		},
		getEcdhIdentity: async () => ecdh,
		getKemIdentity: async () => kem,
		getEpoch: () => v.epoch,
		setEpoch: (n: number) => void (v.epoch = n),
		kv,
		store: {
			get: (k: string) => structuredClone(kv.get(k)),
			set: (k: string, val: unknown) => void kv.set(k, structuredClone(val)),
		},
	};
	return v;
}

export interface Dev {
	doc: Y.Doc;
	mesh: Mesh;
	vault: Awaited<ReturnType<typeof makeVault>>;
	/** deviceId (= fingerprint of the vault's identity key) */
	id: string;
}

export async function makeDev(
	id: string,
	hub: LoopbackHub,
	now?: () => number,
	extra: Partial<MeshOptions> & {
		vault?: Awaited<ReturnType<typeof makeVault>>;
	} = {},
): Promise<Dev> {
	const doc = extra.doc ?? new Y.Doc();
	const vault = extra.vault ?? (await makeVault(id));
	const mesh = createMesh({
		appId: "fize",
		topic: "fize/data/r1",
		doc,
		vault,
		signaling: [hub.transport()],
		deviceName: id,
		now,
		...extra,
	});
	await mesh.ready;
	return { doc, mesh, vault, id: vault.deviceId };
}

/**
 * R4-N7: true once `cond` holds without interruption for `hold` ms, within `deadline` ms. Convergence checks use it
 * instead of "first agreement, then a fixed pause": with ML-DSA a slow device can trigger one more legitimate re-key
 * right after a first agreement.
 */
export const stable = async (cond: () => boolean, deadline = 30_000, hold = 1000): Promise<boolean> => {
	const end = Date.now() + deadline;
	let since: number | null = null;
	while (Date.now() < end) {
		if (cond()) {
			since ??= Date.now();
			if (Date.now() - since >= hold) return true;
		} else since = null;
		await new Promise((r) => setTimeout(r, 20));
	}
	return false;
};

export const until = async (cond: () => boolean, ms = 3000) => {
	const t = Date.now();
	while (!cond()) {
		if (Date.now() - t > ms) throw new Error("timeout waiting for condition");
		await new Promise((r) => setTimeout(r, 5));
	}
};

/** Full pairing host->guest with both SAS confirmed; returns the SAS codes seen. */
export async function pair(
	host: Dev,
	guest: Dev,
	opts: { guestOk?: boolean } = {},
) {
	const codes: { host?: string; guest?: string } = {};
	host.mesh.on("sas", (p) => {
		codes.host = p.code;
		p.confirm();
	});
	const offer = await host.mesh.pairHost();
	const join = guest.mesh.pairJoin(offer.payload, {
		confirmSas: (c) => {
			codes.guest = c;
			return opts.guestOk ?? true;
		},
	});
	await join;
	return { codes, offer };
}

export const metaOf = (d: Dev) => d.doc.getMap<any>("meta");

/** Security view of a mesh (round 5 model: signed documents outside the Y.Doc), or null before it existed. */
// biome-ignore lint/suspicious/noExplicitAny: test helper over an API that changed shape
const secOf = (d: Pick<Dev, "mesh">): any => (d.mesh as any).security ?? null;

/** Does `d` know (and trust) the key-agreement keys of device `id`? */
export const kexKnown = (d: Dev, id: string): boolean => {
	const sec = secOf(d);
	return sec ? sec.keyAgreement(id) !== null : metaOf(d).has(`ecdh/${id}`);
};

/** Every device lists every other one and knows its key-agreement keys. */
export const meshReady = (devs: Dev[], ms = 20_000) =>
	until(
		() =>
			devs.every((d) => d.mesh.devices().length >= devs.length) &&
			devs.every((d) => devs.every((y) => kexKnown(d, y.id))),
		ms,
	);

/** Rotation wraps stored in a device's meta (rotrec:<id> + rot:<id>:<to>), optionally only those of one epoch. */
export function storedWraps(d: Pick<Dev, "doc"> & Partial<Pick<Dev, "mesh">>, epoch?: number) {
	const sec = d.mesh ? secOf(d as Pick<Dev, "mesh">) : null;
	if (sec) {
		// round 5: verified owner rotations kept in the device's security state (not in the shared doc)
		const out: Array<{ id: string; rec: any; to: string; key: string; wrap: string }> = [];
		for (const r of sec.rotations()) {
			if (epoch !== undefined && r.epoch !== epoch) continue;
			for (const [to, wrap] of Object.entries(r.wraps as Record<string, string>))
				out.push({ id: r.id, rec: r, to, key: `${r.id}:${to}`, wrap });
		}
		return out;
	}
	const m = d.doc.getMap<any>("meta");
	const out: Array<{
		id: string;
		rec: any;
		to: string;
		key: string;
		wrap: string;
	}> = [];
	for (const k of m.keys()) {
		if (!k.startsWith("rotrec:")) continue;
		const id = k.slice("rotrec:".length);
		const rec = m.get(k);
		if (epoch !== undefined && rec?.epoch !== epoch) continue;
		for (const k2 of m.keys())
			if (k2.startsWith(`rot:${id}:`))
				out.push({
					id,
					rec,
					to: k2.slice(`rot:${id}:`.length),
					key: k2,
					wrap: m.get(k2),
				});
	}
	return out;
}

/** A (owner) pairs B and C; waits until everyone is connected and every ECDH key is everywhere. */
export async function trio(
	hub: LoopbackHub,
	extra: {
		a?: Partial<MeshOptions>;
		b?: Partial<MeshOptions>;
		c?: Partial<MeshOptions>;
	} = {},
) {
	const a = await makeDev("devA", hub, undefined, extra.a);
	const b = await makeDev("devB", hub, undefined, extra.b);
	const c = await makeDev("devC", hub, undefined, extra.c);
	await pair(a, b);
	await pair(a, c);
	await until(
		() =>
			a.mesh.peers.length === 2 &&
			b.mesh.peers.length >= 1 &&
			c.mesh.peers.length >= 1,
	);
	await until(() =>
		[a, b, c].every((d) => [a, b, c].every((x) => kexKnown(d, x.id))),
	);
	return { a, b, c };
}

export { createLoopbackHub };

type TestVault = Awaited<ReturnType<typeof makeVault>>;

/** Run the pairing state machines back to back (no mesh): what does the host admit for this guest vault? */
export async function pairDirect(
	hostVault: TestVault,
	guestVault: TestVault,
	hooks: {
		prove?: (t: Uint8Array) => Promise<{ pub: string; sig: string }>;
		payload?: (p: PairPayload) => PairPayload;
		/** runs after each message handed to the guest (e.g. to inject traffic from another link) */
		afterGuest?: (m: Parameters<HostPairing["handle"]>[0], guest: GuestPairing) => void;
	} = {},
) {
	const offer = await createPairOffer(hostVault, {
		mid: "m",
		root: hostVault.deviceId,
		appId: "app",
		topic: "app/data/x",
		now: Date.now(),
	});
	const out: { admitted: string | null; failed: string | null } = {
		admitted: null,
		failed: null,
	};
	const host = new HostPairing(offer, {
		now: Date.now,
		verify: identityVerify,
		prove:
			hooks.prove ??
			(async (t) => {
				const pub = b64uEncode(hostVault.devicePublicKey);
				return { pub, sig: b64uEncode(await hostVault.sign(hostProofBytes(t, hostVault.deviceId, pub))) };
			}),
		onSas: (p) => p.confirm(),
		buildGrant: async (g): Promise<GrantBody> => {
			out.admitted = g.deviceId;
			return { meshKey: "", epoch: 0, mid: "m" };
		},
		onPaired() {},
		onFail: (r) => {
			out.failed = r;
		},
	});
	const guest = await GuestPairing.create(hooks.payload ? hooks.payload(offer.payload) : offer.payload, guestVault, {
		name: "g",
		onSas: async () => true,
		now: Date.now(),
	});
	type Msg = Parameters<HostPairing["handle"]>[0];
	const toGuest = (m: Msg) =>
		queueMicrotask(() => {
			void guest.handle(m, toHost);
			hooks.afterGuest?.(m, guest);
		});
	const toHost = (m: Msg) => queueMicrotask(() => void host.handle(m, toGuest));
	guest.attach(toHost);
	const res = await guest.result.then(
		() => "granted",
		(e: Error) => e.message,
	);
	return { ...out, guest: res };
}

