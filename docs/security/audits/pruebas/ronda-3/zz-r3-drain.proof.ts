// ROUND-3 AUDIT PoC (untracked, delete after): BL3 drain() backpressure as a DoS vector.
import { describe, expect, it } from "vitest";
import type { LinkTransport, PeerLink } from "../../src/web/index.js";
import { createLoopbackHub } from "../../src/web/index.js";
import { randomBytes, b64uEncode } from "../../src/web/util.js";
import { makeDev, makeVault, metaOf, pair, until } from "./helpers.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

/** A peer that keeps reading, just slowly (like a throttled SCTP receive window): never "stalled". */
function slowLink(l: PeerLink, bytesPerTick: number, tickMs: number, stats: { accepted: number; delivered: number }): PeerLink {
	const q: Uint8Array[] = [];
	let queued = 0;
	const waiters: Array<() => void> = [];
	const LOW = 1024 * 1024;
	const timer = setInterval(() => {
		let budget = bytesPerTick;
		while (q.length && budget > 0) {
			const f = q.shift() as Uint8Array;
			queued -= f.length;
			budget -= f.length;
			stats.delivered += f.length;
			l.send(f);
		}
		if (queued <= LOW) for (const w of waiters.splice(0)) w();
	}, tickMs);
	l.onClose(() => {
		clearInterval(timer);
		for (const w of waiters.splice(0)) w();
	});
	return {
		id: l.id,
		send(d) {
			q.push(d.slice());
			queued += d.length;
			stats.accepted += d.length;
		},
		drain: () => (queued <= LOW ? Promise.resolve() : new Promise<void>((r) => waiters.push(r))),
		onMessage: (cb) => l.onMessage(cb),
		onClose: (cb) => l.onClose(cb),
		close: () => {
			clearInterval(timer);
			l.close();
		},
	};
}

describe("R3 drain", () => {
	it("D1: a slow-draining member stalls the owner's revoke(): owner stays on the old epoch, rotrec unpublished", async () => {
		const hub = createLoopbackHub();
		const mv = await makeVault("devM");
		const stats = { accepted: 0, delivered: 0 };
		let mClosed = false;
		const inner = hub.transport();
		const wrapped: LinkTransport = {
			...inner,
			join: (r, id) => inner.join(r, id),
			leave: (r) => inner.leave(r),
			close: () => inner.close(),
			onLink: (cb) =>
				inner.onLink((l, rid) => {
					if (l.id !== mv.deviceId) return cb(l, rid);
					if (rid.startsWith("p_")) return cb(l, rid);
					l.onClose(() => {
						mClosed = true;
					});
					cb(slowLink(l, 32 * 1024, 100, stats), rid);
				}),
		};
		const a = await makeDev("devA", hub, undefined, { signaling: [wrapped] });
		const b = await makeDev("devB", hub);
		const c = await makeDev("devC", hub);
		// owner's doc: ~6 MiB of app data
		a.doc.transact(() => {
			for (let i = 0; i < 96; i++) a.doc.getMap("data").set(`k${i}`, b64uEncode(randomBytes(48 * 1024)));
		});
		await pair(a, b);
		await pair(a, c);
		const m = await makeDev("devM", hub, undefined, { vault: mv });
		await pair(a, m);
		const all = [a, b, c, m];
		await until(
			() => all.every((x) => all.every((y) => metaOf(x).has(`ecdh/${y.id}`))) && all.every((x) => x.mesh.devices().length === 4),
			20_000,
		);
		await until(() => a.mesh.peers.includes(m.id), 5000);
		await until(() => stats.accepted === stats.delivered && stats.accepted > 6e6, 60_000); // initial sync done
		mClosed = false;
		// the owner's app writes ~6 MiB (broadcast to everybody; towards M it drains at ~320 KiB/s)
		a.doc.transact(() => {
			for (let i = 0; i < 6; i++) a.doc.getMap("more").set(`k${i}`, `${i}`.padEnd(1024 * 1024, "z"));
		});
		await settle(100);
		const t0 = Date.now();
		let revoked = false;
		const p = a.mesh.revoke(c.id).then(() => {
			revoked = true;
		});
		await until(() => b.mesh.epoch === 1, 5000);
		await settle(5000);
		const ownerEpoch = a.mesh.epoch;
		const rotrecs = [...metaOf(a).keys()].filter((k) => k.startsWith("rotrec:")).length;
		console.log(
			`D1 after ${Date.now() - t0} ms: B epoch ${b.mesh.epoch}, owner epoch ${ownerEpoch}, revoke resolved ${revoked}, owner rotrec entries ${rotrecs}, M link closed ${mClosed}, bytes accepted by M link ${stats.accepted}, delivered ${stats.delivered}`,
		);
		expect(b.mesh.epoch).toBe(1);
		expect(ownerEpoch).toBe(0); // ATTACK: the revoking owner is stuck on the old key
		expect(revoked).toBe(false);
		expect(rotrecs).toBe(0); // stragglers cannot be served (nothing published)
		await until(() => revoked, 60_000);
		console.log(`D1 revoke() resolved after ${Date.now() - t0} ms`);
		for (const x of all) x.mesh.destroy();
	}, 120_000);

	it("D2: backlog towards a slow-draining member grows past the old 16 MiB cap without the link ever closing", async () => {
		const hub = createLoopbackHub();
		const mv = await makeVault("devM");
		const stats = { accepted: 0, delivered: 0 };
		let mClosed = false;
		const inner = hub.transport();
		const wrapped: LinkTransport = {
			...inner,
			join: (r, id) => inner.join(r, id),
			leave: (r) => inner.leave(r),
			close: () => inner.close(),
			onLink: (cb) =>
				inner.onLink((l, rid) => {
					if (l.id !== mv.deviceId) return cb(l, rid);
					if (rid.startsWith("p_")) return cb(l, rid);
					l.onClose(() => {
						mClosed = true;
					});
					cb(slowLink(l, 16 * 1024, 200, stats), rid);
				}),
		};
		const a = await makeDev("devA", hub, undefined, { signaling: [wrapped] });
		const m = await makeDev("devM", hub, undefined, { vault: mv });
		await pair(a, m);
		await until(() => a.mesh.peers.includes(m.id), 5000);
		await settle(300);
		const heap0 = process.memoryUsage().heapUsed;
		let produced = 0;
		for (let i = 0; i < 48; i++) {
			const v = `${i}`.padEnd(1024 * 1024, "y"); // ~1 MiB per update
			produced += v.length;
			a.doc.getMap("data").set(`k${i}`, v);
			await settle(20);
		}
		await settle(3000);
		const heap1 = process.memoryUsage().heapUsed;
		const backlog = produced - stats.accepted;
		console.log(
			`D2 produced ${(produced / 2 ** 20).toFixed(1)} MiB for M; accepted by link ${(stats.accepted / 2 ** 20).toFixed(1)} MiB; delivered ${(stats.delivered / 2 ** 20).toFixed(1)} MiB; held in the mesh outQ ~${(backlog / 2 ** 20).toFixed(1)} MiB; heap +${((heap1 - heap0) / 2 ** 20).toFixed(0)} MiB; link closed ${mClosed}`,
		);
		expect(mClosed).toBe(false);
		expect(backlog).toBeGreaterThan(16 * 2 ** 20); // ATTACK: unbounded buffering, the old S5 bound is gone
		a.mesh.destroy();
		m.mesh.destroy();
	}, 60_000);
});
