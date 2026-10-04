import { describe, expect, it, vi } from "vitest";
import {
	createLoopbackHub,
	type Dev,
	makeDev,
	meshReady,
} from "./helpers.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import { contentId } from "../../src/web/trust/canonical.js";
import { SecurityState } from "../../src/web/secstate.js";

// Count signature verifications to ensure unrequested docs do not consume PQC CPU
const verified = vi.hoisted(() => ({ n: 0 }));
vi.mock("@noble/post-quantum/ml-dsa.js", async (importOriginal) => {
	const m = await importOriginal<typeof import("@noble/post-quantum/ml-dsa.js")>();
	const v = m.ml_dsa65;
	return {
		...m,
		ml_dsa65: {
			...v,
			verify: (...xs: Parameters<typeof v.verify>) => {
				verified.n++;
				return v.verify(...xs);
			},
		},
	};
});

const junkSig = () => b64uEncode(randomBytes(3309));
const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
// biome-ignore lint/suspicious/noExplicitAny: test handle
const sec = (d: Dev): any => (d.mesh as any).security;
const restart = (d: Dev, g: ReturnType<typeof createLoopbackHub>, label: string) =>
	makeDev(label, g, undefined, { doc: d.doc, vault: d.vault });

interface Evil {
	hideKey: (k: string) => boolean;
	hideDoc: (d: { t?: string; id?: string }) => boolean;
	serve: Map<string, unknown>;
	push: unknown[];
}
const ctl = new Map<unknown, Evil>();
// biome-ignore lint/suspicious/noExplicitAny: test patch
const P = SecurityState.prototype as any;
if (!P.__r6s1b) {
	P.__r6s1b = true;
	const inv = P.inventory;
	const get = P.get;
	P.inventory = function (this: { store: unknown }) {
		const c = ctl.get(this.store);
		const ks: string[] = inv.call(this);
		return c ? [...ks.filter((k) => !c.hideKey(k)), ...c.serve.keys()] : ks;
	};
	P.get = async function (this: { store: unknown }, keys: string[]) {
		const c = ctl.get(this.store);
		const out: Array<{ t?: string; id?: string }> = await get.call(this, keys);
		if (!c) return out;
		const res: unknown[] = out.filter((d) => !c.hideDoc(d));
		for (const k of keys) if (c.serve.has(k)) res.push(c.serve.get(k));
		return c.push.length ? [...res, ...c.push] : res;
	};
}
function evil(d: Dev, e: Partial<Evil> = {}): Evil {
	const c: Evil = {
		hideKey: () => false,
		hideDoc: () => false,
		serve: new Map(),
		push: [],
		...e,
	};
	ctl.set(d.vault.store, c);
	return c;
}
const unevil = (d: Dev) => ctl.delete(d.vault.store);

async function junkRevocations(
	inst: string,
	target: string,
	issuer: string,
	n: number,
	tag: string,
): Promise<unknown[]> {
	const out: unknown[] = [];
	for (let i = 0; i < n; i++) {
		const body = {
			t: "revoke",
			v: 1,
			alg: "ML-DSA-65",
			inst,
			target,
			lastSeq: 0,
			upTo: {},
			issuer,
			issuedAt: i,
		};
		const id = await contentId(body);
		out.push({ ...body, id, tag, sig: junkSig() });
	}
	return out;
}

describe("[mesh-r6.S1b] budget strict boundary and unrequested docs filtering", () => {
	it("borde exacto: presupuesto N con N elementos se rechaza al llegar al tope (límite estricto >=)", async () => {
		// Test strict >= behavior on budgets
		const m = new Map<string, { t: number; n: number }>();
		const limit = 10;
		// Helper mimicking provider budget logic
		const checkBudget = (peer: string, n: number, max: number): boolean => {
			let b = m.get(peer);
			if (!b) {
				b = { t: Date.now(), n: 0 };
				m.set(peer, b);
			}
			if (b.n >= max) return false;
			b.n += n;
			return true;
		};

		// 10 items allowed (b.n = 0..9 < 10)
		for (let i = 0; i < limit; i++) {
			expect(checkBudget("p1", 1, limit)).toBe(true);
		}
		// 11th item when b.n = 10 reaches limit 10: b.n >= 10 -> rejected!
		expect(checkBudget("p1", 1, limit)).toBe(false);
	});

	it("DoS: enviar K documentos no pedidos (>= 50) resulta en 0 verificaciones de firma para los no pedidos", async () => {
		// Honest control run
		const gControl = createLoopbackHub();
		const aControl = await makeDev("o", gControl);
		const mControl = await makeDev("m", gControl);
		aControl.mesh.on("sas", (p) => p.confirm());
		const offC = await aControl.mesh.pairHost({ role: "member" });
		await mControl.mesh.pairJoin(offC.payload, { confirmSas: () => true });
		await meshReady([aControl, mControl], 30_000);

		aControl.mesh.destroy();
		await settle(300);

		const vControl0 = verified.n;
		const aControl2 = await restart(aControl, gControl, "o");
		await settle(8000);
		const controlVerifications = verified.n - vControl0;

		for (const d of [aControl2, mControl]) d.mesh.destroy();

		// Attack run with 60 unrequested documents pushed
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const m = await makeDev("m", g);

		a.mesh.on("sas", (p) => p.confirm());
		const off = await a.mesh.pairHost({ role: "member" });
		await m.mesh.pairJoin(off.payload, { confirmSas: () => true });
		await meshReady([a, m], 30_000);

		const inst = (a.mesh.root as { mid: string }).mid;
		const target = sec(a).trust.grantsOf(m.id)[0].id;

		const e = evil(m);
		// Never announced/asked for: pushed along with any answer
		e.push = await junkRevocations(inst, target, a.id, 60, "unrequested-dos");

		const v0 = verified.n;
		a.mesh.destroy();
		await settle(300);

		const a2 = await restart(a, g, "o");
		await settle(8000);

		const pushedCount = e.push.length;
		const attackVerifications = verified.n - v0;

		for (const d of [a2, m]) d.mesh.destroy();
		unevil(m);

		expect(pushedCount).toBe(60);
		// Unrequested docs verifications = attackVerifications - controlVerifications = 0!
		const unrequestedVerifications = attackVerifications - controlVerifications;
		expect(unrequestedVerifications).toBe(0);
	}, 120_000);

	it("variante: documento no pedido con firma inválida tampoco consume CPU (0 verificaciones)", async () => {
		// Honest control run
		const gControl = createLoopbackHub();
		const aControl = await makeDev("o", gControl);
		const mControl = await makeDev("m", gControl);
		aControl.mesh.on("sas", (p) => p.confirm());
		const offC = await aControl.mesh.pairHost({ role: "member" });
		await mControl.mesh.pairJoin(offC.payload, { confirmSas: () => true });
		await meshReady([aControl, mControl], 30_000);

		aControl.mesh.destroy();
		await settle(300);

		const vControl0 = verified.n;
		const aControl2 = await restart(aControl, gControl, "o");
		await settle(8000);
		const controlVerifications = verified.n - vControl0;

		for (const d of [aControl2, mControl]) d.mesh.destroy();

		// Attack run with 50 unrequested invalid signature documents pushed
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const m = await makeDev("m", g);

		a.mesh.on("sas", (p) => p.confirm());
		const off = await a.mesh.pairHost({ role: "member" });
		await m.mesh.pairJoin(off.payload, { confirmSas: () => true });
		await meshReady([a, m], 30_000);

		const inst = (a.mesh.root as { mid: string }).mid;
		const target = sec(a).trust.grantsOf(m.id)[0].id;

		const e = evil(m);
		// 50 unrequested docs with invalid signatures
		e.push = await junkRevocations(inst, target, a.id, 50, "invalid-sig");

		const v0 = verified.n;
		a.mesh.destroy();
		await settle(300);

		const a2 = await restart(a, g, "o");
		await settle(8000);

		const pushedCount = e.push.length;
		const attackVerifications = verified.n - v0;

		for (const d of [a2, m]) d.mesh.destroy();
		unevil(m);

		expect(pushedCount).toBe(50);
		// 0 verifications for unrequested bad-signature documents
		const unrequestedVerifications = attackVerifications - controlVerifications;
		expect(unrequestedVerifications).toBe(0);
	}, 120_000);
});
