// ROUND-3 AUDIT helpers (untracked, delete after)
import { deriveDocMaterial, deriveSenderKey, openUpdate, sealUpdate } from "../../src/web/crypto.js";
import type { PeerLink } from "../../src/web/index.js";
import { deriveRoomId } from "../../src/web/index.js";
import { concat, fromUtf8, randomBytes, utf8 } from "../../src/web/util.js";
import type { makeVault } from "./helpers.js";

export const TOPIC = "fize/data/r1";
type Vault = Awaited<ReturnType<typeof makeVault>>;
export const u32 = (n: number) => {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, false);
	return b;
};

/** A signed data frame exactly like provider.sendFrameWith builds it. `signer` signs, `claim` is the header sender. */
export async function craft(
	v: Vault,
	mat: Uint8Array,
	rid: string,
	kind: number,
	body: Uint8Array,
	sess: Uint8Array,
	seq: number,
	claim = v.deviceId,
) {
	const sig = await v.sign(concat(utf8(`swal-frame/v2|${rid}|${claim}|`), new Uint8Array([kind]), sess, u32(seq), body));
	const inner = concat(new Uint8Array([kind]), sess, u32(seq), new Uint8Array([sig.length >> 8, sig.length & 0xff]), sig, body);
	const key = await deriveSenderKey(mat, TOPIC, claim);
	const id = utf8(claim);
	return concat(new Uint8Array([3, id.length]), id, await sealUpdate(key, inner, `${rid}|${claim}`));
}

/** Decrypt a signed frame from `from` (no signature check): kind + body. */
export async function openFrame(mat: Uint8Array, rid: string, d: Uint8Array) {
	if (d[0] !== 3) return null;
	const idLen = d[1] as number;
	const from = fromUtf8(d.subarray(2, 2 + idLen));
	try {
		const plain = await openUpdate(await deriveSenderKey(mat, TOPIC, from), d.subarray(2 + idLen), `${rid}|${from}`);
		const sigLen = ((plain[13] as number) << 8) | (plain[14] as number);
		return { from, kind: plain[0] as number, sess: plain.slice(1, 9), seq: new DataView(plain.buffer, plain.byteOffset + 9, 4).getUint32(0, false), body: plain.subarray(15 + sigLen) };
	} catch {
		return null;
	}
}

/** A raw peer speaking as `v` on `link` in room `rid` (key `k`, epoch `ep`): answers the handshake, then lets the test send. */
export async function rawPeer(v: Vault, k: Uint8Array, ep: number, link: PeerLink, instance: string) {
	const early: Uint8Array[] = [];
	let handler: ((d: Uint8Array) => void) | null = null;
	link.onMessage((d) => (handler ? handler(d) : early.push(d)));
	const rid = await deriveRoomId(k, "fize", TOPIC, ep, instance);
	const mat = await deriveDocMaterial(k, TOPIC);
	const sess = randomBytes(8);
	let seq = 0;
	let authed = false;
	const seen: Array<{ from: string; kind: number; body: Uint8Array }> = [];
	const send = async (kind: number, body: Uint8Array, claim?: string) => link.send(await craft(v, mat, rid, kind, body, sess, ++seq, claim));
	handler = (d: Uint8Array) => {
		void (async () => {
			const f = await openFrame(mat, rid, d);
			if (!f) return;
			seen.push(f);
			if (f.kind === 5) {
				await send(6, concat(f.body, u32(ep), utf8(f.from)));
				authed = true;
			}
		})();
	};
	for (const d of early.splice(0)) handler(d);
	// challenge back (the victim only sends data after we answered; we do not need its K_AUTH)
	await send(5, randomBytes(16));
	return { rid, mat, send, seen, isAuthed: () => authed };
}
