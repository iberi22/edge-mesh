import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { wsTransport } from "../../src/web/index.js";
import { decodeBlob, encodeBlob } from "../../src/web/transports/qr-sdp.js";

describe("qr-sdp blob", () => {
	it("round-trips and keeps host candidates only", async () => {
		const sdp = [
			"v=0", "o=- 1 1 IN IP4 0.0.0.0", "s=-", "t=0 0", "a=ice-options:trickle",
			"a=candidate:1 1 udp 2113937151 192.168.1.5 5000 typ host",
			"a=candidate:2 1 udp 1677729535 1.2.3.4 5000 typ srflx raddr 0.0.0.0 rport 0",
			"a=fingerprint:sha-256 AA:BB",
		].join("\r\n");
		const blob = await encodeBlob("offer", sdp);
		expect(blob).toMatch(/^[A-Za-z0-9_-]+$/);
		const out = await decodeBlob(blob);
		expect(out.kind).toBe("offer");
		expect(out.sdp).toContain("typ host");
		expect(out.sdp).not.toContain("srflx");
		await expect(decodeBlob("AAAA")).rejects.toThrow();
	});
});

class FakeWS {
	static last: FakeWS;
	readyState = 0;
	sent: any[] = [];
	ls: Record<string, Array<(e: any) => void>> = {};
	constructor(public url: string) {
		FakeWS.last = this;
		setTimeout(() => {
			this.readyState = 1;
			this.emit("open", {});
		}, 0);
	}
	addEventListener(t: string, f: (e: any) => void) {
		(this.ls[t] ??= []).push(f);
	}
	emit(t: string, e: any) {
		for (const f of this.ls[t] ?? []) f(e);
	}
	send(d: string) {
		this.sent.push(JSON.parse(d));
	}
	close() {
		this.readyState = 3;
	}
}

describe("wsTransport (docs/SIGNALING-PROTOCOL.md)", () => {
	it("joins with token in the message, maps server frames, sends only signals", async () => {
		const ws = wsTransport("wss://mesh.example/", { token: "JWT", WebSocketImpl: FakeWS as any, reconnect: false });
		const got: any[] = [];
		ws.onMessage((m) => got.push(m));
		await ws.join("A".repeat(22), "me");
		expect(FakeWS.last.url).toBe(`wss://mesh.example/r/${"A".repeat(22)}`);
		expect(FakeWS.last.sent[0]).toEqual({ type: "join", rid: "A".repeat(22), from: "me", token: "JWT" });
		FakeWS.last.emit("message", { data: JSON.stringify({ type: "peers", peers: ["x", "y"] }) });
		FakeWS.last.emit("message", { data: JSON.stringify({ type: "signal", from: "x", payload: "pp" }) });
		expect(got.map((m) => [m.type, m.from])).toEqual([["join", "x"], ["join", "y"], ["signal", "x"]]);
		ws.send({ type: "join", rid: "A".repeat(22), from: "me" }); // never sent: server fans out
		ws.send({ type: "signal", rid: "A".repeat(22), from: "me", to: "x", payload: "q" });
		expect(FakeWS.last.sent).toHaveLength(2);
		expect(FakeWS.last.sent[1]).toEqual({ type: "signal", rid: "A".repeat(22), from: "me", to: "x", payload: "q" });
		ws.close();
	});
	it("omits token for pairing rooms and has no default url", async () => {
		const ws = wsTransport("wss://m", { token: "JWT", WebSocketImpl: FakeWS as any, reconnect: false });
		await ws.join("p_" + "B".repeat(20), "me");
		expect(FakeWS.last.sent[0].token).toBeUndefined();
		expect(() => wsTransport("")).toThrow();
		ws.close();
	});
});

describe("src/web is browser-pure", () => {
	const files: string[] = [];
	const walk = (d: string) => {
		for (const f of readdirSync(d)) {
			const p = join(d, f);
			statSync(p).isDirectory() ? walk(p) : files.push(p);
		}
	};
	walk(join(import.meta.dirname, "../../src/web"));
	it("has no node: imports, process.env, Buffer or node-only modules", () => {
		expect(files.length).toBeGreaterThan(8);
		for (const f of files) {
			const src = readFileSync(f, "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
			expect(src, f).not.toMatch(/from\s+["']node:/);
			expect(src, f).not.toMatch(/require\(/);
			expect(src, f).not.toMatch(/process\.env|\bprocess\./);
			expect(src, f).not.toMatch(/\bBuffer\b/);
			expect(src, f).not.toMatch(/from\s+["'](crypto|fs|ws|peerjs|ethers)["']/);
		}
	});
});
