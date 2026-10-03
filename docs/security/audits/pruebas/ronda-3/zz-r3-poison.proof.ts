// ROUND-3 AUDIT PoC (untracked, delete after): SF2 negative cache (badRevs) keyed by signature only.
import { describe, expect, it } from "vitest";
import type { PeerLink } from "../../src/web/index.js";
import { createLoopbackHub, deriveRoomId } from "../../src/web/index.js";
import { b64uEncode, utf8 } from "../../src/web/util.js";
import { type Dev, makeDev, metaOf, pair, until } from "./helpers.js";
import { TOPIC, rawPeer } from "./zz-r3-lib.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);

describe("R3 negative-cache poisoning", () => {
	for (const poison of [true, false])
		it(`N1: a member poisons badRevs with the genuine revocation's sig: the straggler never adopts the rotation${poison ? "" : " (control)"}`, async () => {
			const hub = createLoopbackHub();
			const a = await makeDev("devA", hub);
			const b = await makeDev("devB", hub);
			const m = await makeDev("devM", hub);
			const x = await makeDev("devX", hub);
			for (const d of [b, m, x]) await pair(a, d);
			const all = [a, b, m, x];
			await until(
				() => all.every((p) => all.every((q) => metaOf(p).has(`ecdh/${q.id}`))) && all.every((p) => p.mesh.devices().length === 4),
				8000,
			);
			const k0 = (m.vault.meshKey as Uint8Array).slice();
			const instance = a.mesh.namespace.split("/")[1] as string;
			b.mesh.destroy(); // B offline (straggler)
			await a.mesh.revoke(x.id);
			await until(() => m.mesh.epoch === 1 && keyOf(m) === keyOf(a));
			const genuine = metaOf(m).get(`rev/${x.id}:1`); // M (a member) reads the revocation record from the doc
			expect(genuine?.sig).toBeTruthy();
			a.mesh.destroy(); // the owner is offline for a moment
			m.mesh.destroy(); // M speaks raw from here on
			x.mesh.destroy();
			// M waits in the retired room (B's live room) for B
			const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
			const t = hub.transport("evil");
			const lks: PeerLink[] = [];
			t.onLink((l) => void lks.push(l));
			await t.join(rid0, m.id);
			const rejected: string[] = [];
			const b2 = await makeDev("devB", hub, undefined, { doc: b.doc, vault: b.vault });
			b2.mesh.on("rejected", (e) => rejected.push(e.reason));
			await until(() => lks.length >= 1);
			const peer = await rawPeer(m.vault, k0, 0, lks[0] as PeerLink, instance);
			await until(() => peer.isAuthed() && b2.mesh.peers.includes(m.id), 3000);
			if (poison) {
				const bogus = { ...genuine, mid: "not-this-mesh" }; // same sig, fails verification -> badRevs.add(sig)
				const body = utf8(
					JSON.stringify({
						rot: { v: 1, epoch: 1, from: m.id, revoked: [x.id], to: [b.id], n: "p", revs: [bogus] },
						to: b.id,
						wrap: "",
					}),
				);
				await peer.send(3, body);
				await settle(500);
			}
			// the owner comes back and serves B the genuine rotation through its retired room
			const a2 = await makeDev("devA", hub, undefined, { doc: a.doc, vault: a.vault });
			const ok = await until(() => b2.mesh.epoch === 1 && keyOf(b2) === keyOf(a2), 6000).then(
				() => true,
				() => false,
			);
			console.log(
				`N1 poison=${poison}: B epoch ${b2.mesh.epoch} (owner ${a2.mesh.epoch}); B still lists revoked X: ${b2.mesh.devices().some((d) => d.deviceId === x.id)}; B rejected: ${JSON.stringify([...new Set(rejected)])}`,
			);
			if (poison) {
				expect(ok).toBe(false); // ATTACK: the straggler is stuck on the old key
				expect(b2.mesh.devices().some((d) => d.deviceId === x.id)).toBe(true); // and still trusts the revoked device
				// the revoked device comes back on its old key and reads what B writes from now on
				const x2 = await makeDev("devX", hub, undefined, { doc: x.doc, vault: x.vault });
				b2.doc.getMap("secret").set("after-revocation", "written by B after X was revoked");
				const leaked = await until(() => x2.doc.getMap("secret").get("after-revocation") !== undefined, 4000).then(
					() => true,
					() => false,
				);
				console.log(`N1 revoked X received B's post-revocation write: ${leaked}`);
				expect(leaked).toBe(true);
				x2.mesh.destroy();
			} else expect(ok).toBe(true);
			for (const d of [a2, b2]) d.mesh.destroy();
			t.close();
		}, 30_000);
});
