// ROUND-3 AUDIT PoC (untracked, delete after): relayed rotations carry unauthenticated `wraps`; a relayer passes
// on whatever it received first, once per (rotation, peer).
import { describe, expect, it } from "vitest";
import type { LinkTransport, PeerLink } from "../../../../../src/web/index.js";
import { createLoopbackHub, deriveRoomId } from "../../../../../src/web/index.js";
import { deriveDocMaterial } from "../../../../../src/web/crypto.js";
import { b64uEncode, fromUtf8, utf8 } from "../../../../../src/web/util.js";
import { type Dev, makeDev, makeVault, kexKnown, metaOf, pair, until } from "../../../../../tests/web/helpers.js";
import { TOPIC, craft, openFrame } from "../ronda-3/zz-r3-lib.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
type Hub = ReturnType<typeof createLoopbackHub>;

/** Transport of a device that has no link to `blocked` (data rooms only; pairing rooms stay open). */
function partial(hub: Hub, blocked: () => string[], tamper?: (l: PeerLink) => PeerLink): LinkTransport {
	const inner = hub.transport();
	return {
		...inner,
		join: (r, id) => inner.join(r, id),
		leave: (r) => inner.leave(r),
		close: () => inner.close(),
		onLink: (cb) =>
			inner.onLink((l, rid) => {
				if (!rid.startsWith("p_") && blocked().includes(l.id)) {
					l.close();
					return;
				}
				cb(tamper && !rid.startsWith("p_") ? tamper(l) : l, rid);
			}),
	};
}

describe("R3 relay", () => {
	for (const tampering of [true, false])
		it(`RL1: a malicious relayer corrupts the other recipients' wraps; the honest relayer forwards them once${tampering ? "" : " (control)"}`, async () => {
			const hub = createLoopbackHub();
			const va = await makeVault("devA");
			const vh = await makeVault("devH");
			const vv = await makeVault("devV");
			const vm = await makeVault("devM");
			const vx = await makeVault("devX");
			let enforce = false;
			let instance = "";
			let k0: Uint8Array | null = null;
			const m = { dev: null as Dev | null };
			// M's outgoing K_ROTATE frames: V's wrap replaced by garbage, re-signed by M (M is the attacker)
			const tamper = (l: PeerLink): PeerLink => {
				let q: Promise<void> = Promise.resolve();
				return {
					...l,
					id: l.id,
					onMessage: (cb) => l.onMessage(cb),
					onClose: (cb) => l.onClose(cb),
					close: () => l.close(),
					send: (d) => {
						const copy = d.slice();
						q = q.then(async () => {
							if (!tampering || !enforce || !k0 || copy[0] !== 3) return l.send(copy);
							const keys: Array<[Uint8Array, number]> = [[k0, 0]];
							if (m.dev?.vault.meshKey) keys.push([m.dev.vault.meshKey, m.dev.mesh.epoch]);
							for (const [k, ep] of keys) {
								const rid = await deriveRoomId(k, "fize", TOPIC, ep, instance);
								const mat = await deriveDocMaterial(k, TOPIC);
								const f = await openFrame(mat, rid, copy);
								if (!f) continue;
								if (f.kind !== 3) return l.send(copy);
								const msg = JSON.parse(fromUtf8(f.body));
								const bad = (w: string) => (w[5] === "A" ? `${w.slice(0, 5)}B${w.slice(6)}` : `${w.slice(0, 5)}A${w.slice(6)}`);
								if (msg.wraps?.[vv.deviceId]) msg.wraps[vv.deviceId] = bad(msg.wraps[vv.deviceId]);
								if (msg.to === vv.deviceId) msg.wrap = bad(msg.wrap);
								return l.send(await craft(vm, mat, rid, 3, utf8(JSON.stringify(msg)), f.sess, f.seq));
							}
							l.send(copy);
						});
					},
				};
			};
			// topology once enforced: A-M, M-H, M-V, H-V (A has no link to H or V)
			const blk = (pairs: string[]) => () => (enforce ? pairs : []);
			const a = await makeDev("devA", hub, undefined, { vault: va, signaling: [partial(hub, blk([vh.deviceId, vv.deviceId]))] });
			const h = await makeDev("devH", hub, undefined, { vault: vh, signaling: [partial(hub, blk([va.deviceId]))] });
			const v = await makeDev("devV", hub, undefined, { vault: vv, signaling: [partial(hub, blk([va.deviceId]))] });
			const md = await makeDev("devM", hub, undefined, { vault: vm, signaling: [partial(hub, () => [], tamper)] });
			m.dev = md;
			const x = await makeDev("devX", hub, undefined, { vault: vx });
			for (const d of [h, v, md, x]) await pair(a, d);
			const all = [a, h, v, md, x];
			await until(
				() => all.every((p) => all.every((q) => kexKnown(p, q.id))) && all.every((p) => p.mesh.devices().length === 5),
				8000,
			);
			instance = a.mesh.namespace.split("/")[1] as string;
			k0 = (a.vault.meshKey as Uint8Array).slice();
			x.mesh.destroy();
			// rebuild the network with the partial topology (restart everybody on the same doc/vault)
			for (const d of [a, h, v, md]) d.mesh.destroy();
			enforce = true;
			const a2 = await makeDev("devA", hub, undefined, { doc: a.doc, vault: va, signaling: [partial(hub, blk([vh.deviceId, vv.deviceId]))] });
			const h2 = await makeDev("devH", hub, undefined, { doc: h.doc, vault: vh, signaling: [partial(hub, blk([va.deviceId]))] });
			const v2 = await makeDev("devV", hub, undefined, { doc: v.doc, vault: vv, signaling: [partial(hub, blk([va.deviceId]))] });
			const m2 = await makeDev("devM", hub, undefined, { doc: md.doc, vault: vm, signaling: [partial(hub, () => [], tamper)] });
			m.dev = m2;
			await until(
				() =>
					a2.mesh.peers.includes(vm.deviceId) &&
					h2.mesh.peers.includes(vm.deviceId) &&
					v2.mesh.peers.includes(vh.deviceId) &&
					v2.mesh.peers.includes(vm.deviceId),
				5000,
			);
			expect(a2.mesh.peers).toEqual([vm.deviceId]);
			const rejected: string[] = [];
			v2.mesh.on("rejected", (e) => rejected.push(e.reason));
			await a2.mesh.revoke(vx.deviceId);
			const ok = await until(() => [h2, v2, m2].every((d) => d.mesh.epoch === 1 && keyOf(d) === keyOf(a2)), 6000).then(
				() => true,
				() => false,
			);
			console.log(
				`RL1 tampering=${tampering}: epochs A ${a2.mesh.epoch} M ${m2.mesh.epoch} H ${h2.mesh.epoch} V ${v2.mesh.epoch}; V rejected ${JSON.stringify(rejected)}`,
			);
			if (tampering) expect(v2.mesh.epoch).toBe(0); // ATTACK: V never gets a valid wrap
			else expect(ok).toBe(true);
			for (const d of [a2, h2, v2, m2]) d.mesh.destroy();
		}, 40_000);
});
