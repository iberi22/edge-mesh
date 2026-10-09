import { describe, expect, it } from "vitest";
import type { LinkTransport, PeerLink } from "../../src/web/index.js";
import { createLoopbackHub } from "../../src/web/index.js";
import { makeDev, pair, until } from "./helpers.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

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

describe("S1 replay attack variants", () => {
	it("replaying a captured session twice sequentially across two different new links authenticates nothing both times", async () => {
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
		await until(() => b.mesh.peers.includes(a.id));
		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d) => got.push(new TextDecoder().decode(d)));
		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("pay table 7"));
		await until(() => got.length === 1);
		const rejected: string[] = [];
		b.mesh.on("rejected", (e) => rejected.push(e.reason));
		a.mesh.destroy();
		await settle(100);

		const dataRid = rids.filter((r) => !r.startsWith("p_")).at(-1) as string;
		const capturedFrames = rec.log.filter((x) => x.link === a.id);

		// Replay 1 on fake link 1
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
		for (const f of capturedFrames)
			(recv1 as unknown as (d: Uint8Array) => void)(f.d);
		await settle(200);

		// Replay 2 on fake link 2
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
		for (const f of capturedFrames)
			(recv2 as unknown as (d: Uint8Array) => void)(f.d);
		await settle(200);

		expect(got).toEqual(["pay table 7"]);
		expect(b.mesh.peers).not.toContain(a.id);
		expect(rejected.every((r) => r === "bad link authentication")).toBe(true);
		b.mesh.destroy();
	});

	it("reinjecting captured session messages after an attacker initiates a fresh handshake on a new link authenticates nothing", async () => {
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
		await until(() => b.mesh.peers.includes(a.id));
		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d) => got.push(new TextDecoder().decode(d)));
		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("pay table 7"));
		await until(() => got.length === 1);
		const rejected: string[] = [];
		b.mesh.on("rejected", (e) => rejected.push(e.reason));
		a.mesh.destroy();
		await settle(100);

		const dataRid = rids.filter((r) => !r.startsWith("p_")).at(-1) as string;
		const capturedFrames = rec.log.filter((x) => x.link === a.id);

		// Attacker connects on a new fake link
		let recv: ((d: Uint8Array) => void) | null = null;
		const fake: PeerLink = {
			id: "attackerLink",
			send() {},
			onMessage: (cb) => {
				recv = cb;
			},
			onClose() {},
			close() {},
		};
		(inject as unknown as (l: PeerLink, rid: string) => void)(fake, dataRid);
		// b will send K_HELLO to fake upon wireLink.
		await settle(50);

		// Attacker now reinjects captured session frames (which contain old K_HELLO/K_AUTH/data)
		for (const f of capturedFrames)
			(recv as unknown as (d: Uint8Array) => void)(f.d);

		await settle(200);
		expect(got).toEqual(["pay table 7"]);
		expect(b.mesh.peers).not.toContain(a.id);
		expect(rejected.every((r) => r === "bad link authentication")).toBe(true);
		b.mesh.destroy();
	});
});
