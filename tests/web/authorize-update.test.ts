import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../src/web/index.js";
import { makeDev, pair, until } from "./helpers.js";

describe("authorizeUpdate hook (data authorization plugs in here)", () => {
	it("is called with the AUTHENTICATED sender; a refused update is not applied and is reported", async () => {
		const hub = createLoopbackHub();
		const calls: string[] = [];
		const a = await makeDev("devA", hub, undefined, {
			authorizeUpdate: (sender: string, update: Uint8Array) => {
				calls.push(sender);
				return sender !== "devC" && update.length > 0;
			},
		});
		const b = await makeDev("devB", hub);
		const c = await makeDev("devC", hub);
		await pair(a, b);
		await pair(a, c);
		await until(() => a.mesh.peers.length === 2);
		const rejected: any[] = [];
		a.mesh.on("rejected", (e) => rejected.push(e));
		b.doc.getMap("data").set("fromB", 1);
		c.doc.getMap("data").set("fromC", 1);
		await until(() => a.doc.getMap("data").get("fromB") === 1 && rejected.some((r) => r.from === "devC"));
		expect(a.doc.getMap("data").get("fromC")).toBeUndefined();
		expect(rejected.find((r) => r.from === "devC").reason).toBe("update not authorized");
		expect(new Set(calls)).toEqual(new Set(["devB", "devC"]));
		for (const x of [a, b, c]) x.mesh.destroy();
	});
});
