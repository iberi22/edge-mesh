// R6 adaptation of R5-S3 (zz-r5-freeze) and R4-2 (zz-r4-cap): a malicious admin issues FAKES grants (default 1030) to
// made-up devices, KEX of them with valid key-agreement records (so they would be rotation recipients), and revokes
// REVOKED of them (so the owner has >1024 unexecuted cuts to carry). Then the owner revokes the honest tablet b, then the
// admin. Convention: PASSES while the attack works (the owner cannot cut b, or cannot cut the admin, or ends alone).
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import { kemKeygen } from "../../../../../src/web/pq.js";
import { generateEcdhIdentity } from "../../../../../src/web/rotation.js";
import { vaultSigner } from "../../../../../src/web/secstate.js";
import { issueRevocation } from "../../../../../src/web/trust/docs.js";
import { createSigner, signCanonical } from "../../../../../src/web/trust/keys.js";
import { b64uEncode } from "../../../../../src/web/util.js";
import { makeDev, meshReady, stable } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, keyOf, sec, settle } from "./zz-r6-lib.js";

const N = Number(process.env.FAKES ?? 1030);
const K = Number(process.env.KEX ?? 300);
const REV = Number(process.env.REVOKED ?? 1030);

describe("R6 adaptation of R5-S3 / R4-2 (an admin floods grants, key records and revocations)", () => {
	it("ATTACK: the owner can no longer cut b, or the admin, or ends alone", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const errs: string[] = [];
		a.mesh.on("error", (e) => errs.push(String((e as Error)?.message ?? e)));
		const x = await admit(a, g, "adm", "admin");
		const b = await admit(a, g, "b");
		await meshReady([a, x, b], 30_000);
		const sx = sec(x);
		const inst = (a.mesh.root as { mid: string }).mid;
		const ec = b64uEncode((await generateEcdhIdentity()).publicKey);
		const kem = b64uEncode(kemKeygen().publicKey);
		const t0 = Date.now();
		const grants = [];
		const kexes = [];
		for (let i = 0; i < N; i++) {
			const kp = ml_dsa65.keygen();
			const gr = await sx.issueGrant(b64uEncode(kp.publicKey), { role: "member", name: `f${i}` });
			grants.push(gr);
			if (i < K) {
				const sg = await createSigner(kp);
				const body = { t: "kex" as const, v: 1 as const, inst, dev: sg.fp, ecdh: ec, kem, n: 0 };
				kexes.push({ ...body, sig: await signCanonical(sg, body) });
			}
		}
		const st1: Record<string, number> = {};
		for (let i = 0; i < grants.length; i += 200) for (const o of await sx.addMany(grants.slice(i, i + 200))) st1[o.status] = (st1[o.status] ?? 0) + 1;
		for (const o of await sx.addMany(kexes)) st1[`kex-${o.status}`] = (st1[`kex-${o.status}`] ?? 0) + 1;
		const signer = vaultSigner(x.vault, b64uEncode(x.vault.devicePublicKey));
		const xGrant = sx.trust.grantsOf(x.id)[0];
		const revs = [];
		const stored = sx.trust.docs().filter((d: { t: string; issuer: string }) => d.t === "grant" && d.issuer === x.id);
		for (const gr of stored.slice(0, REV)) revs.push(await issueRevocation(signer, { target: gr.id, lastSeq: 0, upTo: {} }, { inst, parent: xGrant }));
		for (let i = 0; i < revs.length; i += 200) for (const o of await sx.addMany(revs.slice(i, i + 200))) st1[`rev-${o.status}`] = (st1[`rev-${o.status}`] ?? 0) + 1;
		console.log(`crafted ${N} grants / ${K} kex / ${revs.length} revocations in ${Date.now() - t0} ms`, JSON.stringify(st1));
		const ownerDevs = () => a.mesh.devices().length;
		await settle(15_000);
		console.log("owner sees", ownerDevs(), "devices, epoch", a.mesh.epoch, "pending", a.mesh.rekeyPending, "x epoch", x.mesh.epoch, "b epoch", b.mesh.epoch);
		await a.mesh.revoke(b.id).catch((e) => console.log("revoke(b) threw:", (e as Error).message));
		const bCut = await stable(() => keyOf(b) !== keyOf(a) && keyOf(x) === keyOf(a), 60_000, 1000);
		console.log("after revoke(b): bCut", bCut, "epoch", a.mesh.epoch, "x epoch", x.mesh.epoch, "owner peers", a.mesh.peers.length, "re-key errors", errs.filter((e) => e.includes("re-key")).slice(0, 2));
		await a.mesh.revoke(x.id).catch((e) => console.log("revoke(x) threw:", (e as Error).message));
		const xCut = await stable(() => keyOf(x) !== keyOf(a) && !a.mesh.rekeyPending && a.mesh.devices().length <= 2, 90_000, 1000);
		console.log("after revoke(x): xCut", xCut, "epoch", a.mesh.epoch, "devices", a.mesh.devices().length, "pending", a.mesh.rekeyPending, "errors", errs.filter((e) => e.includes("re-key")).slice(0, 2));
		expect(bCut && xCut).toBe(false); // ATTACK WORKS if either cut fails
		for (const d of [a, x, b]) d.mesh.destroy();
	}, 900_000);
});
