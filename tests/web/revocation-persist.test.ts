import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../src/web/index.js";
import { vaultSigner } from "../../src/web/secstate.js";
import { issueRevocation } from "../../src/web/trust/docs.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import { devLabels, makeDev, metaOf, pair, trio, until } from "./helpers.js";

const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

describe("H4: revocations survive reloads and reach devices that join later", () => {
	it("a reloaded device keeps rejecting a revoked one, even when an insider replays its signed grant", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const oldGrantC = structuredClone(a.mesh.security!.trust.grantsOf(c.id)[0]);
		expect(oldGrantC?.sig).toBeTruthy();
		await a.mesh.revoke(c.id);
		await until(() => b.mesh.epoch === 1);

		a.mesh.destroy(); // reload A: same persisted doc + vault (incl. its local store)
		const a2 = await makeDev("devA", hub, undefined, {
			doc: a.doc,
			vault: a.vault,
		});
		expect(a2.mesh.epoch).toBe(1);
		await until(() => a2.mesh.peers.includes(b.id));

		// insider B hands C's old, validly signed grant around again (and writes it into the shared doc)
		expect((await b.mesh.security!.add(oldGrantC)).status).toBe("duplicate");
		b.doc.transact(() => metaOf(b).set(`adm/${c.id}`, oldGrantC));
		await until(() => metaOf(a2).has(`adm/${c.id}`));
		await settle();
		expect(devLabels(a2.mesh)).not.toContain("devC");

		// a device paired AFTER the revocation never saw it locally: it learns it from the signed record
		const e = await makeDev("devE", hub);
		await pair(a2, e);
		await until(() => e.mesh.devices().some((d) => d.deviceId === b.id));
		await settle();
		expect(devLabels(e.mesh)).not.toContain("devC");
		for (const x of [a2, b, c, e]) x.mesh.destroy();
	});

	it("a revocation forged by a member is ignored", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const sec = b.mesh.security!;
		const mid = a.mesh.root!.mid;
		const bGrant = sec.trust.grantsOf(b.id)[0]!;
		const cGrant = sec.trust.grantsOf(c.id)[0]!;
		// a well-formed revocation signed by a member (it may revoke nobody: it is no ancestor of C's grant)...
		const forged = await issueRevocation(
			vaultSigner(b.vault, b64uEncode(b.vault.devicePublicKey)),
			{ target: cGrant.id, lastSeq: 0 },
			{ inst: mid, parent: bGrant },
		);
		expect((await sec.add(forged)).status).toBe("rejected");
		// ...one "by the owner" with a bogus signature...
		const bogus = {
			...forged,
			issuer: a.id,
			parent: undefined,
			sig: b64uEncode(randomBytes(3309)),
		};
		expect((await sec.add(bogus)).status).toBe("rejected");
		// ...and the pre-round-5 records in the shared doc
		metaOf(b).set(`rev/${c.id}:1`, {
			v: 2,
			mid,
			target: c.id,
			by: b.id,
			epoch: 1,
			sig: "AAAA",
		});
		await until(() => metaOf(a).has(`rev/${c.id}:1`));
		await settle();
		expect(devLabels(a.mesh)).toEqual(["devA", "devB", "devC"]);
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("an explicitly re-paired device is admitted again everywhere", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		await a.mesh.revoke(c.id);
		await until(() => b.mesh.epoch === 1);
		await settle(20);
		await pair(a, c);
		expect(c.mesh.epoch).toBe(1);
		await until(
			() =>
				b.mesh.devices().some((d) => d.deviceId === c.id) &&
				b.mesh.peers.includes(c.id),
		);
		c.doc.getMap("data").set("back", 1);
		await until(() => b.doc.getMap("data").get("back") === 1);
		for (const x of [a, b, c]) x.mesh.destroy();
	});
});
