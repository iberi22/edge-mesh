import * as Y from "yjs";
import { describe, expect, it } from "vitest";
import { F_FRAG, FRAG_HEADER, Reassembler, fragment } from "../../src/web/fragment.js";
import { createLoopbackHub, type LinkTransport } from "../../src/web/index.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import { dataChannelLink } from "../../src/web/webrtc.js";
import { makeDev, pair, until } from "./helpers.js";

const LIMIT = 256 * 1024; // e.g. RTCSctpTransport.maxMessageSize in Chrome

/** Links that throw on messages above `limit`, like RTCDataChannel.send does above maxMessageSize. */
function capped(t: LinkTransport, limit = LIMIT, seen?: { max: number }): LinkTransport {
	const orig = t.onLink.bind(t);
	t.onLink = (cb) =>
		orig((link, rid) => {
			const send = link.send.bind(link);
			link.send = (d) => {
				if (seen) seen.max = Math.max(seen.max, d.length);
				if (d.length > limit) throw new TypeError(`message too large: ${d.length} > ${limit}`);
				send(d);
			};
			cb(link, rid);
		});
	return t;
}

/** Incompressible text of ~`bytes` length (getRandomValues is capped at 64 KiB per call). */
const bigText = (bytes: number) => {
	const parts: string[] = [];
	for (let n = 0; n < bytes; n += 64_000) parts.push(b64uEncode(randomBytes(48_000)));
	return parts.join("");
};

describe("H5: fragmentation of large mesh messages", () => {
	it("pairs and syncs a multi-MB document over links capped at 256 KiB per message", async () => {
		const hub = createLoopbackHub();
		const seen = { max: 0 };
		const a = await makeDev("devA", hub, undefined, { signaling: [capped(hub.transport(), LIMIT, seen)] });
		const b = await makeDev("devB", hub, undefined, { signaling: [capped(hub.transport(), LIMIT, seen)] });
		const big = bigText(3 * 1024 * 1024);
		a.doc.getMap("data").set("big", big);
		await pair(a, b);
		expect(b.doc.getMap("data").get("big")).toBe(big);
		await until(() => a.mesh.status === "online" && b.mesh.status === "online", 15_000); // MBs of crypto: slow CI
		const big2 = bigText(2 * 1024 * 1024);
		a.doc.getMap("data").set("big2", big2);
		await until(() => b.doc.getMap("data").get("big2") === big2, 15_000);
		expect(seen.max).toBeLessThanOrEqual(64 * 1024);
		expect(Y.encodeStateAsUpdate(a.doc).length).toBe(Y.encodeStateAsUpdate(b.doc).length);
		a.mesh.destroy();
		b.mesh.destroy();
	}, 45_000);
});

describe("fragment / Reassembler", () => {
	it("small messages pass through untouched; large ones split into bounded frames that reassemble in any order", async () => {
		const small = randomBytes(100);
		expect(await fragment(small, 1024)).toEqual([small]);
		const msg = randomBytes(10_000);
		const frags = await fragment(msg, 1024);
		expect(frags.length).toBe(Math.ceil(10_000 / (1024 - FRAG_HEADER)));
		for (const f of frags) {
			expect(f.length).toBeLessThanOrEqual(1024);
			expect(f[0]).toBe(F_FRAG);
		}
		const r = new Reassembler();
		const shuffled = [...frags].reverse();
		shuffled.splice(3, 0, frags[2]); // a duplicate
		let out: Uint8Array | null = null;
		for (const f of shuffled) out = (await r.push(f)) ?? out;
		expect(out).toEqual(msg);
		expect(r.pending).toBe(0);
	});

	it("drops a message whose reassembled bytes do not match its hash", async () => {
		const frags = await fragment(randomBytes(5000), 1024);
		frags[1] = frags[1].slice();
		frags[1][frags[1].length - 1] ^= 1;
		const drops: string[] = [];
		const r = new Reassembler({ onDrop: (why) => drops.push(why) });
		const outs = await Promise.all(frags.map((f) => r.push(f)));
		expect(outs.every((o) => o === null)).toBe(true);
		expect(drops).toContain("hash mismatch");
		expect(r.pending).toBe(0);
	});

	it("rejects messages declared larger than the limit and bounds concurrent partial messages", async () => {
		const drops: string[] = [];
		const r = new Reassembler({ maxMessageBytes: 8000, maxPendingBytes: 12_000, onDrop: (why) => drops.push(why) });
		const tooBig = await fragment(randomBytes(9000), 1024);
		expect(await r.push(tooBig[0])).toBeNull();
		expect(drops).toContain("message too large");
		expect(r.pending).toBe(0);
		const m1 = await fragment(randomBytes(7000), 1024);
		const m2 = await fragment(randomBytes(7000), 1024);
		await r.push(m1[0]);
		await r.push(m2[0]); // 14000 declared > 12000: the oldest partial is evicted
		expect(r.pending).toBe(1);
		expect(r.pendingBytes).toBeLessThanOrEqual(12_000);
		let out: Uint8Array | null = null;
		for (const f of m2.slice(1)) out = (await r.push(f)) ?? out;
		expect(out?.length).toBe(7000);
		for (const f of m1.slice(1)) expect(await r.push(f)).toBeNull(); // evicted: never completes
	});

	it("rejects inconsistent headers and frames that overflow the declared length", async () => {
		const r = new Reassembler();
		const frags = await fragment(randomBytes(3000), 1024);
		const forged = frags[1].slice();
		new DataView(forged.buffer).setUint32(13, 99); // total changed mid-message
		await r.push(frags[0]);
		expect(await r.push(forged)).toBeNull();
		expect(r.pending).toBe(0);
		expect(await r.push(new Uint8Array([F_FRAG, 1, 2]))).toBeNull(); // truncated header
	});

	it("drops partial messages after the timeout", async () => {
		let t = 0;
		const r = new Reassembler({ timeoutMs: 1000, now: () => t });
		const frags = await fragment(randomBytes(3000), 1024);
		await r.push(frags[0]);
		expect(r.pending).toBe(1);
		t = 1500;
		r.sweep();
		expect(r.pending).toBe(0);
		for (const f of frags.slice(1)) expect(await r.push(f)).toBeNull();
		r.clear();
	});
});

class FakeDC {
	readyState = "open";
	binaryType = "blob";
	bufferedAmount = 0;
	bufferedAmountLowThreshold = 0;
	sent: Uint8Array[] = [];
	maxBuffered = 0;
	ls: Record<string, Array<(e: any) => void>> = {};
	addEventListener(t: string, f: (e: any) => void) {
		(this.ls[t] ??= []).push(f);
	}
	emit(t: string, e: any = {}) {
		for (const f of this.ls[t] ?? []) f(e);
	}
	send(d: Uint8Array) {
		this.sent.push(d);
		this.bufferedAmount += d.length;
		this.maxBuffered = Math.max(this.maxBuffered, this.bufferedAmount);
	}
	/** the network drains everything queued so far */
	drain() {
		this.bufferedAmount = 0;
		this.emit("bufferedamountlow");
	}
	close() {
		this.readyState = "closed";
		this.emit("close");
	}
}

describe("dataChannelLink", () => {
	it("applies backpressure: never queues megabytes into the SCTP buffer at once", async () => {
		const dc = new FakeDC();
		const link = dataChannelLink("x", dc as unknown as RTCDataChannel);
		for (let i = 0; i < 64; i++) link.send(new Uint8Array(60 * 1024).fill(i)); // ~3.8 MB burst
		expect(dc.maxBuffered).toBeLessThanOrEqual(2 * 1024 * 1024);
		while (dc.bufferedAmount > 0) dc.drain();
		const total = dc.sent.reduce((n, c) => n + c.length - 1, 0);
		expect(total).toBe(64 * 60 * 1024);
	});

	it("bounds reassembly of chunked messages and closes on overflow", () => {
		const dc = new FakeDC();
		const link = dataChannelLink("x", dc as unknown as RTCDataChannel);
		let closed = false;
		link.onClose(() => (closed = true));
		const chunk = new Uint8Array(16001);
		chunk[0] = 1; // "more follows", forever
		for (let i = 0; i < 400 && !closed; i++) dc.emit("message", { data: chunk.buffer });
		expect(closed).toBe(true);
	});
});
