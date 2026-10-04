// The published surface of the browser mesh: the names README.md and examples/web-basic.ts are allowed to use, and
// the quick start itself (imported and executed, never copied here). An accidental export removal fails this file.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import { quickStart } from "../../examples/web-basic.js";
import * as merge from "../../src/web/merge/index.js";
import * as oplog from "../../src/web/oplog/index.js";
import * as trust from "../../src/web/trust/index.js";
import * as web from "../../src/web/index.js";
import { until } from "./helpers.js";

const read = (rel: string): string => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

/**
 * Every name a module declares as exported, values AND types: the `export { … }` / `export type { … }` blocks plus
 * `export const|let|var|function|class|interface|type|enum NAME`. Types are erased at runtime, so this is the only
 * way a type-only export removal is caught.
 */
function declaredNames(rel: string): string[] {
	const src = read(rel);
	const names = new Set<string>();
	for (const block of src.matchAll(/export\s+(?:type\s+)?\{([^}]*)\}/g))
		for (const part of block[1].split(",")) {
			const name = part.trim().replace(/^type\s+/, "").split(/\s+as\s+/).pop()?.trim();
			if (name) names.add(name);
		}
	for (const decl of src.matchAll(
		/export\s+(?:declare\s+)?(?:abstract\s+)?(?:const|let|var|function|class|interface|type|enum)\s+([A-Za-z0-9_$]+)/g,
	))
		names.add(decl[1] as string);
	return [...names].sort();
}

/** The fenced TypeScript block right after a markdown heading. */
function fencedTsAfter(md: string, heading: string): string {
	const at = md.indexOf(heading);
	expect(at, `heading ${heading} in README.md`).toBeGreaterThan(-1);
	const open = md.indexOf("```ts", at);
	expect(open, `a ts block after ${heading}`).toBeGreaterThan(-1);
	const end = md.indexOf("```", open + 5);
	return md.slice(open + 5, end);
}

/** Code lines only (no comments, no blank lines): what both files must agree on. */
const codeLines = (src: string): string[] =>
	src
		.split("\n")
		.map((l) => l.replace(/\s+$/, ""))
		.filter((l) => l.trim() !== "" && !l.trim().startsWith("//"));

/** Each subpath of package.json "exports" under ./web, with the exact names it may export. */
const ENTRY_POINTS = [
	{
		entry: "./web",
		file: "../../src/web/index.ts",
		mod: web,
		declared: [
			"Device", "Exchange", "HEALTH_SCHEMA_PREFIX", "HealthRecord", "IDENTITY_ALG", "KEM_ALG", "KexDoc",
			"LinkTransport", "LoopbackHub", "MAX_MEMBERS_PER_ADMIN", "MAX_ROT_MEMBERS", "MESH_MODULE", "MESH_SCHEMA",
			"ML_DSA_PUBLIC_KEY_BYTES", "ML_DSA_SIGNATURE_BYTES", "ML_KEM_CIPHERTEXT_BYTES", "ML_KEM_PUBLIC_KEY_BYTES",
			"Mesh", "MeshChannel", "MeshEvent", "MeshOptions", "MeshSecurity", "MeshStatus", "MeshStore",
			"PairHostOptions", "PairJoinResult", "PairOffer", "PairPayload", "PeerLink", "QrSdpTransport", "Role",
			"RotDoc", "RtcOptions", "SecDoc", "SecurityState", "SigMessage", "SigTransport", "SignalingChannel",
			"TopicScope", "TrustRoot", "VaultClient", "canIssue", "createLoopbackHub", "createMesh", "decodePairPayload",
			"deriveDocKey", "derivePairRoomId", "deriveRoomId", "deviceIdOf", "exchange", "exchangeTopic", "fingerprint",
			"idMatchesPub", "idbStore", "identityKeygen", "identitySign", "identityVerify", "isDeviceId",
			"isHealthRecord", "isRotDoc", "kemKeygen", "legacyNamespace", "memoryStore", "meshNamespace", "openUpdate",
			"qrSdpTransport", "sealUpdate", "topic", "wsTransport",
		],
		values: [
			"HEALTH_SCHEMA_PREFIX", "IDENTITY_ALG", "KEM_ALG", "MAX_MEMBERS_PER_ADMIN", "MAX_ROT_MEMBERS", "MESH_MODULE",
			"MESH_SCHEMA", "ML_DSA_PUBLIC_KEY_BYTES", "ML_DSA_SIGNATURE_BYTES", "ML_KEM_CIPHERTEXT_BYTES",
			"ML_KEM_PUBLIC_KEY_BYTES", "SecurityState", "canIssue", "createLoopbackHub", "createMesh",
			"decodePairPayload", "deriveDocKey", "derivePairRoomId", "deriveRoomId", "deviceIdOf", "exchange",
			"exchangeTopic", "fingerprint", "idMatchesPub", "idbStore", "identityKeygen", "identitySign",
			"identityVerify", "isDeviceId", "isHealthRecord", "isRotDoc", "kemKeygen", "legacyNamespace", "memoryStore",
			"meshNamespace", "openUpdate", "qrSdpTransport", "sealUpdate", "topic", "wsTransport",
		],
	},
	{
		entry: "./web/trust",
		file: "../../src/web/trust/index.ts",
		mod: trust,
		declared: [
			"AddResult", "AddStatus", "Anchor", "At", "Decision", "DenyReason", "DeviceRef", "Grant", "GrantBody",
			"GrantInput", "IssueContext", "LEVELS", "Level", "PUBLIC_KEY_BYTES", "Permissions", "Revocation",
			"RevocationBody", "RevocationInput", "RolePreset", "SIGNATURE_BYTES", "SIG_ALG", "SigAlg", "Signer",
			"TrustDoc", "TrustSchema", "TrustStore", "TrustStoreOptions", "bodyOf", "canonicalBytes", "canonicalJson",
			"checkGrantShape", "checkIntegrity", "checkRevocationShape", "contentId", "createSigner", "createTrustStore",
			"generateSigner", "isLevel", "isPublicKey", "isSignature", "issueGrant", "issueRevocation",
			"keyFingerprint", "levelRank", "rolePreset", "sha256B64u", "signBytes", "signCanonical", "verifyBytes",
			"verifyCanonical", "verifyDocSignature",
		],
		values: [
			"LEVELS", "PUBLIC_KEY_BYTES", "SIGNATURE_BYTES", "SIG_ALG", "TrustStore", "bodyOf", "canonicalBytes",
			"canonicalJson", "checkGrantShape", "checkIntegrity", "checkRevocationShape", "contentId", "createSigner",
			"createTrustStore", "generateSigner", "isLevel", "isPublicKey", "isSignature", "issueGrant",
			"issueRevocation", "keyFingerprint", "levelRank", "rolePreset", "sha256B64u", "signBytes", "signCanonical",
			"verifyBytes", "verifyCanonical", "verifyDocSignature",
		],
	},
	{
		entry: "./web/oplog",
		file: "../../src/web/oplog/index.ts",
		mod: oplog,
		declared: [
			"Checkpoint", "CheckpointHook", "HaveMsg", "HlcClock", "HlcParts", "IngestResult", "IngestStatus",
			"MemoryOpStore", "MemoryQuarantineStore", "Op", "OpBody", "OpInput", "OpLog", "OpLogChannel", "OpLogError",
			"OpLogEvents", "OpLogMessage", "OpLogOptions", "OpLogSync", "OpRange", "OpStore", "OpVerdict", "OpsMsg",
			"PendingReason", "QuarantineEntry", "QuarantineReason", "QuarantineStore", "ServeOptions", "StoredOp",
			"SyncRateLimit", "WantMsg", "attachOpLogSync", "compareHlc", "compareOps", "createHlc", "decodeMessage",
			"encodeMessage", "formatHlc", "haveMessage", "hlcWall", "isHlc", "openOpLog", "parseHlc", "serve", "wantFor",
		],
		values: [
			"MemoryOpStore", "MemoryQuarantineStore", "OpLog", "OpLogError", "attachOpLogSync", "compareHlc",
			"compareOps", "createHlc", "decodeMessage", "encodeMessage", "formatHlc", "haveMessage", "hlcWall", "isHlc",
			"openOpLog", "parseHlc", "serve", "wantFor",
		],
	},
	{
		entry: "./web/merge",
		file: "../../src/web/merge/index.ts",
		mod: merge,
		declared: [
			"EventEntity", "EventReducer", "EventResult", "LedgerAccount", "LedgerOptions", "LwwEntity", "LwwOptions",
			"LwwPayload", "MergeOp", "MergeStrategy", "compareMergeOps", "createProjector", "eventLog", "ledger",
			"lwwField", "toMergeOp",
		],
		values: ["compareMergeOps", "createProjector", "eventLog", "ledger", "lwwField", "toMergeOp"],
	},
] as const;

describe("public API of @iberi22/edge-mesh/web", () => {
	for (const { entry, file, mod, declared, values } of ENTRY_POINTS)
		it(`${entry} exports exactly the snapshot names`, () => {
			// runtime names: a value that silently became type-only (or vice versa) breaks consumers here
			expect(Object.keys(mod).sort()).toEqual([...values]);
			// declared names (values + types): an accidental removal of either fails
			expect(declaredNames(file)).toEqual([...declared]);
		});

	it("the subpaths of package.json exports are the snapshot entry points", () => {
		const pkg = JSON.parse(read("../../package.json")) as { exports: Record<string, unknown> };
		expect(Object.keys(pkg.exports).filter((k) => k.startsWith("./web"))).toEqual(
			ENTRY_POINTS.map((e) => e.entry),
		);
	});

	it("every name imported by examples/web-basic.ts is exported by ./web", () => {
		const example = read("../../examples/web-basic.ts");
		const imported = new Set<string>();
		for (const block of example.matchAll(/import\s+(?:type\s+)?\{([^}]*)\}/g))
			for (const part of block[1].split(",")) {
				const name = part.trim().replace(/^type\s+/, "").split(/\s+as\s+/)[0]?.trim();
				if (name) imported.add(name);
			}
		expect(imported.size).toBeGreaterThan(0);
		// declared names, so a type-only import (Mesh, VaultClient) counts too
		const declared = declaredNames("../../src/web/index.ts");
		for (const name of imported) expect(declared).toContain(name);
	});

	it("the README quick start is the code of examples/web-basic.ts", () => {
		const readme = read("../../README.md");
		// same code, only the module specifier differs (the example imports the source, the README the package)
		const fromReadme = fencedTsAfter(readme, "## Quick start").replaceAll(
			"@iberi22/edge-mesh/web",
			"../src/web/index.js",
		);
		expect(codeLines(fromReadme)).toEqual(codeLines(read("../../examples/web-basic.ts")));
	});
});

describe("README quick start (examples/web-basic.ts)", () => {
	it("runs: two devices pair over in-memory links and replicate the doc encrypted", async () => {
		const { owner, guest, guestId, docs } = await quickStart();
		try {
			const [ownerDoc, guestDoc] = docs;
			await until(() => owner.status === "online" && guest.status === "online");
			// the owner is offline until it hosts a pairing; its grant then makes the guest a member of the mesh
			expect(owner.role()).toBe("owner");
			expect(owner.role(guestId)).toBe("member");
			expect(guest.role()).toBe("member");
			expect(guest.role(owner.root?.deviceId ?? "")).toBe("owner");
			expect(owner.devices().map((d) => d.deviceId)).toEqual(expect.arrayContaining([guestId]));
			expect(owner.root?.mid).toBe(guest.root?.mid);
			// the owner is the trust anchor itself (authority from being the root, not from a grant)
			expect(owner.devices().find((d) => d.role === "owner")?.deviceId).toBe(owner.root?.deviceId);
			// a member may edit the mesh module but not administer it (admins are tier 2: owner -> admin -> member)
			expect(owner.security?.trust.can(guestId, "mesh", "editar")).toBe(true);
			expect(owner.security?.trust.can(guestId, "mesh", "administrar")).toBe(false);

			// the write made before pairing arrives by sync, not inside the grant
			await until(() => guestDoc.getMap("state").get("hello") === "world");
			expect(Y.encodeStateAsUpdate(ownerDoc)).toEqual(Y.encodeStateAsUpdate(guestDoc));
			expect(guest.peers).toContain(owner.root?.deviceId ?? "");

			// and back the other way
			guestDoc.getMap("state").set("from", "guest");
			await until(() => ownerDoc.getMap("state").get("from") === "guest");
		} finally {
			owner.destroy();
			guest.destroy();
		}
	});

	it("the owner revokes the guest: cut at once, re-key, and no further replication to it", async () => {
		const { owner, guest, guestId, docs } = await quickStart();
		const [ownerDoc, guestDoc] = docs;
		try {
			await until(() => guest.status === "online" && owner.security?.keyAgreement(guestId) !== null);
			expect(owner.devices().map((d) => d.deviceId)).toContain(guestId);

			await owner.revoke(guestId);
			expect(owner.epoch).toBe(1);
			expect(owner.devices().map((d) => d.deviceId)).not.toContain(guestId);
			expect(owner.role(guestId)).toBeNull();
			expect(owner.security?.trust.can(guestId, "mesh", "editar")).toBe(false);

			// the revoked device keeps the old key, so the re-keyed mesh never reaches it again
			await until(() => guest.peers.length === 0, 10_000);
			ownerDoc.getMap("state").set("after", "rekey");
			await new Promise((r) => setTimeout(r, 300));
			expect(guestDoc.getMap("state").get("after")).toBeUndefined();
		} finally {
			owner.destroy();
			guest.destroy();
		}
	});
});