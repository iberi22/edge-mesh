// La caché de members()/unexecuted() no puede ignorar el reloj: un permiso que vence debe dejar de
// contar aunque no llegue ningún documento nuevo (si no, la rotación seguiría incluyendo al vencido).
import { describe, expect, it } from "vitest";
import { SecurityState, vaultSigner } from "../../src/web/secstate.js";
import { issueGrant } from "../../src/web/trust/docs.js";
import { memoryStore } from "../../src/web/store.js";
import { b64uEncode } from "../../src/web/util.js";
import { makeVault } from "./helpers.js";

describe("SecurityState: caché sensible al vencimiento de permisos", () => {
	it("un miembro con permiso vencido deja de listarse sin nuevos documentos", async () => {
		let t = 1_000_000_000_000;
		const owner = await makeVault("owner");
		const mem = await makeVault("mem");
		const pub = (v: Awaited<ReturnType<typeof makeVault>>) => b64uEncode(v.devicePublicKey);
		const root = { mid: "m", deviceId: owner.deviceId, pub: pub(owner) };
		const st = await SecurityState.open({ root, store: memoryStore(), now: () => t });
		const so = vaultSigner(owner, pub(owner));
		const g = await issueGrant(
			so,
			{ subject: { pub: pub(mem) }, role: "member", permissions: { mesh: "editar" }, notBefore: 0, expiresAt: t + 5_000 },
			{ inst: "m" },
		);
		expect((await st.add(g)).status).toBe("accepted");
		expect(st.members().map((m) => m.deviceId)).toContain(mem.deviceId);
		t += 10_000; // vence el permiso; no llega ningún documento
		expect(st.members().map((m) => m.deviceId)).not.toContain(mem.deviceId);
	});
});
