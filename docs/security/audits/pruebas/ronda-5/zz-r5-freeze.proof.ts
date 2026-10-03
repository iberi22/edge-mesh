// R5 proof: a malicious admin admits >1024 (fake) members with valid key-agreement keys. The owner's rotate() then
// refuses every re-key (R4-S3: >1024 recipients), so NO revocation is executed any more: the revoked keep the key.
// Then the owner revokes the admin itself (which voids the fakes' chains): does the mesh recover?
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import { signAdmission } from "../../src/web/admission.js";
import { deviceIdOf, kemKeygen } from "../../src/web/pq.js";
import { ecdhSignedBytes, generateEcdhIdentity } from "../../src/web/rotation.js";
import { b64uEncode } from "../../src/web/util.js";
import { createLoopbackHub, type Dev, makeDev, metaOf, pair, until } from "./helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const N = Number(process.env.FAKES ?? 1030);

describe("R5 admin freezes re-keying", () => {
	it("an admin admits >1024 members: the owner can no longer cut anybody", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		a.mesh.on("sas", (p) => p.confirm());
		const errs: string[] = [];
		a.mesh.on("error", (e) => errs.push(String(e?.message ?? e)));
		const x = await makeDev("adm", g);
		const ox = await a.mesh.pairHost({ role: "admin" });
		await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
		const b = await makeDev("b", g);
		await pair(a, b);
		const all = [a, x, b];
		await until(() => all.every((d) => d.mesh.devices().length === 3) && all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))), 20_000);
		const mid = (a.mesh.root as { mid: string }).mid;
		const ec = b64uEncode((await generateEcdhIdentity()).publicKey);
		const kem = b64uEncode(kemKeygen().publicKey);
		const entries: Array<[string, unknown, unknown]> = [];
		const t0 = Date.now();
		for (let i = 0; i < N; i++) {
			const kp = ml_dsa65.keygen();
			const id = await deviceIdOf(kp.publicKey);
			const adm = await signAdmission(x.vault, { mid, deviceId: id, pub: b64uEncode(kp.publicKey), name: `f${i}`, role: "member", by: x.id, epoch: 0, at: 0 });
			const sig = b64uEncode(ml_dsa65.sign(ecdhSignedBytes(id, ec, kem), kp.secretKey));
			entries.push([id, adm, { pub: ec, kem, sig }]);
		}
		console.log(`crafted ${N} fakes in ${Date.now() - t0} ms`);
		x.doc.transact(() => {
			for (const [id, adm, e] of entries) {
				metaOf(x).set(`adm/${id}`, adm);
				metaOf(x).set(`ecdh/${id}`, e);
			}
		});
		await until(() => a.mesh.devices().length >= N + 3, 180_000);
		await settle(3000);
		console.log("owner sees", a.mesh.devices().length, "devices");
		// 1) the owner revokes the honest-but-lost tablet b
		await a.mesh.revoke(b.id).catch((e) => console.log("revoke(b) threw:", e.message));
		await settle(8000);
		console.log("after owner revokes b: epoch", a.mesh.epoch, "b holds key:", keyOf(b) === keyOf(a), "rekeyPending", a.mesh.rekeyPending, "errors:", errs.filter((e) => e.includes("re-key")).length);
		const frozen = keyOf(b) === keyOf(a);
		// 2) the owner revokes the admin (its admissions die with it)
		await a.mesh.revoke(x.id).catch((e) => console.log("revoke(x) threw:", e.message));
		await settle(15_000);
		console.log("after owner revokes admin: epoch", a.mesh.epoch, "devices", a.mesh.devices().length, "b holds key:", keyOf(b) === keyOf(a), "x holds key:", keyOf(x) === keyOf(a), "rekeyPending", a.mesh.rekeyPending);
		expect(frozen).toBe(true); // ATTACK WORKS: the owner's revocation of b was not executed
		for (const d of all) d.mesh.destroy();
	}, 600_000);
});
