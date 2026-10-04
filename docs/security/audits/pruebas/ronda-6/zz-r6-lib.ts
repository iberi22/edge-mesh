// ROUND-6 AUDIT helpers (untracked, delete after): a malicious peer on the trust channel.
// All devices run in one process, so SecurityState.prototype is patched once and dispatches on the instance's
// local store (the vault.s `store`, stable across restarts): only the devices registered here misbehave.
import { SecurityState } from "../../../../../src/web/secstate.js";
import { b64uEncode } from "../../../../../src/web/util.js";
import { createLoopbackHub, type Dev, makeDev } from "../../../../../tests/web/helpers.js";

export type Hub = ReturnType<typeof createLoopbackHub>;
export interface Evil {
	/** keys hidden from inventory() and docs hidden from get() / rotations() */
	hideKey: (k: string) => boolean;
	hideDoc: (d: { t?: string; id?: string }) => boolean;
	/** extra keys announced and the documents served for them */
	serve: Map<string, unknown>;
}
const ctl = new Map<unknown, Evil>();
// biome-ignore lint/suspicious/noExplicitAny: test patch
const P = SecurityState.prototype as any;
if (!P.__r6) {
	P.__r6 = true;
	const inv = P.inventory;
	const get = P.get;
	const rots = P.rotations;
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
		return res;
	};
	P.rotations = function (this: { store: unknown }) {
		const c = ctl.get(this.store);
		const rs: Array<{ t?: string; id?: string }> = rots.call(this);
		return c ? rs.filter((r) => !c.hideDoc(r)) : rs;
	};
}
// biome-ignore lint/suspicious/noExplicitAny: test helper
export const sec = (d: Dev): any => (d.mesh as any).security;
export function evil(d: Dev, e: Partial<Evil> = {}): Evil {
	const c: Evil = { hideKey: () => false, hideDoc: () => false, serve: new Map(), ...e };
	ctl.set(d.vault.store, c);
	return c;
}
export const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
export const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
export const has = (d: Dev, t: Dev) => d.mesh.devices().some((y) => y.deviceId === t.id);
export async function admit(host: Dev, g: Hub, label: string, role?: "admin") {
	const d = await makeDev(label, g);
	host.mesh.on("sas", (p) => p.confirm());
	const off = await host.mesh.pairHost(role ? { role } : {});
	await d.mesh.pairJoin(off.payload, { confirmSas: () => true });
	return d;
}
/** Restart a device (same doc + vault + local store) on hub `g`. */
export const restart = (d: Dev, g: Hub, label: string) => makeDev(label, g, undefined, { doc: d.doc, vault: d.vault });
export { createLoopbackHub };
export const unevil = (d: Dev) => ctl.delete(d.vault.store);
/** n distinct encodings of the same base64url signature ('-' -> '+', '_' -> '/') */
export function variants(sig: string, n: number): string[] {
	const pos: number[] = [];
	for (let i = 0; i < sig.length; i++) if (sig[i] === "-" || sig[i] === "_") pos.push(i);
	return pos.slice(0, n).map((i) => sig.slice(0, i) + (sig[i] === "-" ? "+" : "/") + sig.slice(i + 1));
}
