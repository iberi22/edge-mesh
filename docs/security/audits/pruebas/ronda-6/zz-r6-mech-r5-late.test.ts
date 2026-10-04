// R5 proof: a device paired AFTER the last rotation (so not in curRot.to) and then revoked: does the owner re-key?
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../../../../../src/web/util.js";
import { createLoopbackHub, type Dev, makeDev, kexKnown, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);

describe("R5 late-paired revoke", () => {
	it("owner revokes a device paired after the current rotation", async () => {
		const g = createLoopbackHub();
		const o = await makeDev("o", g);
		const b = await makeDev("b", g);
		const c = await makeDev("c", g);
		await pair(o, b);
		await pair(o, c);
		await until(() => [o, b, c].every((d) => [o, b, c].every((x) => kexKnown(d, x.id))), 20_000);
		await o.mesh.revoke(c.id);
		await until(() => o.mesh.epoch === 1 && b.mesh.epoch === 1, 20_000);
		const d = await makeDev("d", g);
		await pair(o, d);
		await until(() => d.mesh.epoch === 1 && o.mesh.devices().length === 3, 20_000);
		await until(() => [o, b, d].every((x) => [o, b, d].every((y) => kexKnown(x, y.id))), 20_000);
		console.log("before revoke d: epochs", o.mesh.epoch, b.mesh.epoch, d.mesh.epoch, "same key d/o", keyOf(d) === keyOf(o));
		await o.mesh.revoke(d.id);
		await settle(4000);
		console.log("after revoke d: epochs o", o.mesh.epoch, "b", b.mesh.epoch, "d", d.mesh.epoch, "d still has owner key:", keyOf(d) === keyOf(o), "rekeyPending", o.mesh.rekeyPending);
		// ATTACK WORKS if d still holds the owner's current key
		expect(keyOf(d) === keyOf(o)).toBe(true);
		for (const x of [o, b, c, d]) x.mesh.destroy();
	}, 90_000);
});
