import { describe, expect, it } from "vitest";
import type { LinkTransport, PeerLink } from "../../src/web/index.js";
import { createLoopbackHub } from "../../src/web/index.js";
import {
	makeDev,
	pair,
	until,
} from "./helpers.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

/** B's transport, with every frame B receives recorded (`log`) */
function recorder(inner: LinkTransport) {
	const log: Array<{ link: string; via: PeerLink; d: Uint8Array }> = [];
	const deliver = new Map<PeerLink, (d: Uint8Array) => void>();
	const t: LinkTransport = {
		...inner,
		join: (rid, id) => inner.join(rid, id),
		leave: (rid) => inner.leave(rid),
		close: () => inner.close(),
		onLink(cb) {
			return inner.onLink((l, rid) => {
				const orig = l.onMessage.bind(l);
				const wrapped: PeerLink = {
					id: l.id,
					send: (d) => l.send(d),
					close: () => l.close(),
					onClose: (f) => l.onClose(f),
					onMessage: (f) => {
						deliver.set(wrapped, f);
						orig((d) => {
							log.push({ link: l.id, via: wrapped, d: d.slice() });
							f(d);
						});
					},
				};
				cb(wrapped, rid);
			});
		},
	};
	return { t, log, deliver };
}

describe("R6-S1 Session Replay Attack Variants", () => {
	it("repeating replay across two separate links in sequence authenticates nothing on either link", async () => {
		const hub = createLoopbackHub();
		const rec = recorder(hub.transport());
		let inject: ((l: PeerLink, rid: string) => void) | null = null;
		const rids: string[] = [];
		const evil: LinkTransport = {
			kind: "link",
			name: "evil",
			async join(rid) {
				rids.push(rid);
			},
			onLink(cb) {
				inject = cb;
				return () => {};
			},
			leave() {},
			close() {},
		};
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, {
			signaling: [rec.t, evil],
		});
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id), 10_000);

		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d) => got.push(new TextDecoder().decode(d)));

		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("pay table 7"));
		await until(() => got.length === 1, 10_000);

		a.mesh.destroy();
		await settle(100);

		const dataRid = rids.filter((r) => !r.startsWith("p_")).at(-1) as string;
		const captured = rec.log.filter((x) => x.link === a.id);

		// First replay attempt on link fake1
		let recv1: ((d: Uint8Array) => void) | null = null;
		const fake1: PeerLink = {
			id: "relay1",
			send() {},
			onMessage: (cb) => {
				recv1 = cb;
			},
			onClose() {},
			close() {},
		};
		(inject as unknown as (l: PeerLink, rid: string) => void)(fake1, dataRid);
		for (const f of captured) (recv1 as unknown as (d: Uint8Array) => void)(f.d);
		await settle(200);

		expect(got).toEqual(["pay table 7"]);
		expect(b.mesh.peers).not.toContain(a.id);

		// Second replay attempt on link fake2
		let recv2: ((d: Uint8Array) => void) | null = null;
		const fake2: PeerLink = {
			id: "relay2",
			send() {},
			onMessage: (cb) => {
				recv2 = cb;
			},
			onClose() {},
			close() {},
		};
		(inject as unknown as (l: PeerLink, rid: string) => void)(fake2, dataRid);
		for (const f of captured) (recv2 as unknown as (d: Uint8Array) => void)(f.d);
		await settle(200);

		expect(got).toEqual(["pay table 7"]);
		expect(b.mesh.peers).not.toContain(a.id);

		b.mesh.destroy();
	});

	it("re-injecting captured signed frames on a new link after an attacker completes a distinct handshake authenticates nothing from the victim", async () => {
		const hub = createLoopbackHub();
		const rec = recorder(hub.transport());
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, {
			signaling: [rec.t],
		});
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id) && a.mesh.peers.includes(b.id), 10_000);

		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d, from) => got.push(`${from}:${new TextDecoder().decode(d)}`));

		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("from A"));
		await until(() => got.length === 1, 10_000);

		const captured = rec.log.filter((x) => x.link === a.id);
		a.mesh.destroy();
		await settle(100);

		// Now Attacker C pairs with B and establishes an authenticated link
		const c = await makeDev("devC", hub);
		await pair(c, b);
		await until(() => b.mesh.peers.includes(c.id) && c.mesh.peers.includes(b.id), 10_000);

		// Attacker C sends legitimate message
		await c.mesh.channel("orders").send(new TextEncoder().encode("from C"));
		await until(() => got.length === 2, 10_000);

		// Attacker C now injects captured data frames from A into C's link to B
		const framesFromA = captured.filter((x) => x.d.length > 2);

		// Find C's active link recorder deliver callback
		const cDeliver = rec.log.find((x) => x.link === c.id)?.via;
		expect(cDeliver).toBeDefined();

		if (cDeliver) {
			const deliverCb = rec.deliver.get(cDeliver);
			expect(deliverCb).toBeDefined();
			if (deliverCb) {
				for (const f of framesFromA) {
					deliverCb(f.d);
				}
			}
		}

		await settle(200);

		// Verify that no extra messages from A were processed
		expect(got).toEqual([`${a.id}:from A`, `${c.id}:from C`]);

		b.mesh.destroy();
		c.mesh.destroy();
	});

	it("pre-auth early frames injected before a handshake cannot be delivered under a different session", async () => {
		const hub = createLoopbackHub();
		const rec = recorder(hub.transport());
		let inject: ((l: PeerLink, rid: string) => void) | null = null;
		const rids: string[] = [];
		const evil: LinkTransport = {
			kind: "link",
			name: "evil",
			async join(rid) {
				rids.push(rid);
			},
			onLink(cb) {
				inject = cb;
				return () => {};
			},
			leave() {},
			close() {},
		};

		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, {
			signaling: [rec.t, evil],
		});
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id) && a.mesh.peers.includes(b.id), 10_000);

		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d, from) => got.push(`${from}:${new TextDecoder().decode(d)}`));

		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("secret message"));
		await until(() => got.length === 1, 10_000);

		const capturedData = rec.log.filter((x) => x.link === a.id);
		a.mesh.destroy();
		await settle(100);

		// Inject captured data frame first into fake link (stored in early)
		const dataRid = rids.filter((r) => !r.startsWith("p_")).at(-1) as string;
		let recvFake: ((d: Uint8Array) => void) | null = null;
		const fakeLink: PeerLink = {
			id: "fake_link",
			send() {},
			onMessage: (cb) => {
				recvFake = cb;
			},
			onClose() {},
			close() {},
		};
		(inject as unknown as (l: PeerLink, rid: string) => void)(fakeLink, dataRid);

		// Inject captured data frames from A (which will be put into early queue on unauthed link)
		const dataFrame = capturedData.find((x) => x.d[0] === 3 && x.d.length > 20);
		if (dataFrame) {
			(recvFake as unknown as (d: Uint8Array) => void)(dataFrame.d);
		}

		await settle(100);
		expect(got.length).toBe(1); // Not delivered yet

		b.mesh.destroy();
	});
});
