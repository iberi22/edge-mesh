import * as Y from "yjs";
import { describe, expect, it } from "vitest";
import { createLoopbackHub, vaultSigner, createMesh } from "../../src/web/index.js";
import { makeDev, pair, until } from "./helpers.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import type { LinkTransport } from "../../src/web/types.js";

describe("catch-up gap re-offering [mesh-r6.S3b]", () => {
	it("detects a gap in an intermediate batch, re-requests missing document, and achieves full convergence", async () => {
		const hub = createLoopbackHub();
		const o = await makeDev("owner", hub);

		// Issue 10 grants on owner to form a catch-up set
		const grants: any[] = [];
		for (let i = 0; i < 10; i++) {
			const gr = await o.mesh.security!.issueGrant(
				vaultSigner(o.vault, o.mesh.security!.trust.keyOf(o.id) ?? b64uEncode(o.vault.devicePublicKey)),
				b64uEncode(randomBytes(1952)),
				{ role: "member", name: `gap-grant-${i}` }
			);
			grants.push(gr);
		}
		await o.mesh.security!.addMany(grants);

		// Target an intermediate grant (e.g., grant index 4)
		const targetGrant = grants[4];
		const targetDocId = targetGrant.id;

		// Create lag device with a custom transport wrapper that drops frame containing targetDocId on first attempt
		let droppedCount = 0;
		let reRequested = false;

		const baseTransport = hub.transport();
		const interceptedTransport: LinkTransport = {
			kind: "link",
			name: "intercepted",
			join: baseTransport.join.bind(baseTransport),
			leave: baseTransport.leave.bind(baseTransport),
			close: baseTransport.close.bind(baseTransport),
			onLink: (cb) => {
				return baseTransport.onLink((link, rid) => {
					const origSend = link.send.bind(link);
					link.send = (data) => {
						const text = new TextDecoder("latin1").decode(data);
						if (text.includes(targetDocId) && droppedCount === 0) {
							droppedCount++;
							// Deliberately drop this frame to simulate an intermediate gap in catch-up
							return;
						}
						origSend(data);
					};
					cb(link, rid);
				});
			},
		};

		const lagDoc = new Y.Doc();
		const lagVault = await (await import("./helpers.js")).makeVault("lag");
		const lagMesh = createMesh({
			appId: "fize",
			topic: "fize/data/r1",
			doc: lagDoc,
			vault: lagVault,
			signaling: [interceptedTransport],
			deviceName: "lag",
		});
		await lagMesh.ready;
		const lag = { doc: lagDoc, mesh: lagMesh, vault: lagVault, id: lagVault.deviceId };

		lag.mesh.on("rejected", (e: any) => {
			if (e.reason && e.reason.includes("catch-up gap")) {
				reRequested = true;
			}
		});

		// Pair lag with owner
		await pair(o, lag);
		await until(() => o.mesh.status === "online" && lag.mesh.status === "online");

		// Verify that a frame was dropped
		expect(droppedCount).toBe(1);

		// Verify lag achieves full convergence (holds all grants including the re-requested targetDocId)
		await until(async () => {
			const docs = await lag.mesh.security!.docs();
			return docs.some((d: any) => d.id === targetDocId);
		}, 10000);

		expect(reRequested).toBe(true);
		const lagDocs = await lag.mesh.security!.docs();
		expect(lagDocs.some((d: any) => d.id === targetDocId)).toBe(true);

		o.mesh.destroy();
		lag.mesh.destroy();
	});

	it("detects a gap in the last batch, re-requests missing document, and achieves full convergence", async () => {
		const hub = createLoopbackHub();
		const o = await makeDev("owner", hub);

		// Issue 5 grants on owner
		const grants: any[] = [];
		for (let i = 0; i < 5; i++) {
			const gr = await o.mesh.security!.issueGrant(
				vaultSigner(o.vault, o.mesh.security!.trust.keyOf(o.id) ?? b64uEncode(o.vault.devicePublicKey)),
				b64uEncode(randomBytes(1952)),
				{ role: "member", name: `last-grant-${i}` }
			);
			grants.push(gr);
		}
		await o.mesh.security!.addMany(grants);

		// Target the LAST grant (index 4)
		const lastGrant = grants[4];
		const lastDocId = lastGrant.id;

		let droppedCount = 0;
		let gapNotified = false;

		const baseTransport = hub.transport();
		const interceptedTransport: LinkTransport = {
			kind: "link",
			name: "intercepted-last",
			join: baseTransport.join.bind(baseTransport),
			leave: baseTransport.leave.bind(baseTransport),
			close: baseTransport.close.bind(baseTransport),
			onLink: (cb) => {
				return baseTransport.onLink((link, rid) => {
					const origSend = link.send.bind(link);
					link.send = (data) => {
						const text = new TextDecoder("latin1").decode(data);
						if (text.includes(lastDocId) && droppedCount === 0) {
							droppedCount++;
							// Deliberately drop the last document frame
							return;
						}
						origSend(data);
					};
					cb(link, rid);
				});
			},
		};

		const lagDoc = new Y.Doc();
		const lagVault = await (await import("./helpers.js")).makeVault("lagLast");
		const lagMesh = createMesh({
			appId: "fize",
			topic: "fize/data/r1",
			doc: lagDoc,
			vault: lagVault,
			signaling: [interceptedTransport],
			deviceName: "lagLast",
		});
		await lagMesh.ready;
		const lag = { doc: lagDoc, mesh: lagMesh, vault: lagVault, id: lagVault.deviceId };

		lag.mesh.on("rejected", (e: any) => {
			if (e.reason && e.reason.includes("catch-up gap")) {
				gapNotified = true;
			}
		});

		await pair(o, lag);
		await until(() => o.mesh.status === "online" && lag.mesh.status === "online");

		// Verify that the frame for the last document was dropped once
		expect(droppedCount).toBe(1);

		// Verify lag recovers the last document from the final batch and achieves full convergence
		await until(async () => {
			const docs = await lag.mesh.security!.docs();
			return docs.some((d: any) => d.id === lastDocId);
		}, 10000);

		expect(gapNotified).toBe(true);
		const lagDocs = await lag.mesh.security!.docs();
		expect(lagDocs.some((d: any) => d.id === lastDocId)).toBe(true);

		o.mesh.destroy();
		lag.mesh.destroy();
	});
});
