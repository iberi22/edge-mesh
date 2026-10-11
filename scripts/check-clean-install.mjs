// Regression check: the packed tarball must be importable with ONLY the
// hard dependencies installed (no optional peers).
//
// What it does:
//   1. `npm pack` the current checkout (expects `dist/` already built).
//   2. Creates an isolated temp dir, installs the tarball + `yjs` only.
//   3. Asserts none of the optional peers are resolvable there.
//   4. Dynamically imports all five export paths and fails non-zero if any
//      import throws (e.g. ERR_MODULE_NOT_FOUND for a statically imported
//      optional peer).
//
// Run: `npm run test:pack` (also wired into CI after build).

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const PKG_NAME = "@swal/edge-mesh";
const EXPORT_PATHS = [
	".",
	"./web",
	"./web/trust",
	"./web/oplog",
	"./web/merge",
];
const OPTIONAL_PEERS = [
	"idb",
	"ws",
	"cbor-x",
	"peerjs",
	"ethers",
	"@bokuweb/zstd-wasm",
];

function run(cmd, args, cwd) {
	return execFileSync(cmd, args, {
		cwd,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
}

function fail(message) {
	console.error(`[check-clean-install] FAIL: ${message}`);
	process.exit(1);
}

function main() {
	const distDir = path.join(REPO_ROOT, "dist");
	if (!fs.existsSync(path.join(distDir, "index.js"))) {
		fail("dist/index.js missing — run `npm run build` first.");
	}

	console.log("[check-clean-install] packing tarball…");
	const packOut = run("npm", ["pack", "--json"], REPO_ROOT);
	let tarballName;
	try {
		const parsed = JSON.parse(packOut);
		tarballName = (Array.isArray(parsed) ? parsed[0] : parsed).filename;
	} catch {
		fail(`could not parse \`npm pack --json\` output: ${packOut}`);
	}
	const tarball = path.join(REPO_ROOT, tarballName);
	console.log(`[check-clean-install] tarball: ${tarballName}`);

	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "em-clean-"));
	try {
		run("npm", ["init", "-y"], tmpDir);
		console.log("[check-clean-install] installing tarball + yjs only…");
		run("npm", ["install", "--no-audit", "--no-fund", tarball, "yjs"], tmpDir);

		// npm auto-installs peer dependencies: strip any optional peers so
		// the fixture really has only hard dependencies installed.
		for (const peer of OPTIONAL_PEERS) {
			fs.rmSync(path.join(tmpDir, "node_modules", peer), {
				recursive: true,
				force: true,
			});
		}

		// Prove the fixture is meaningful: optional peers must NOT resolve
		// from the fixture dir (scoped require: no fallback to our own tree).
		const fixtureRequire = createRequire(path.join(tmpDir, "package.json"));
		for (const peer of OPTIONAL_PEERS) {
			let resolved = null;
			try {
				resolved = fixtureRequire.resolve(peer);
			} catch {
				// Expected: not installed.
			}
			if (resolved !== null) {
				fail(
					`optional peer '${peer}' unexpectedly resolvable in fixture dir (${resolved}).`,
				);
			}
		}
		console.log("[check-clean-install] confirmed no optional peers installed.");

		// Import every export path from the fixture's node_modules.
		const failures = [];
		const probeFile = path.join(tmpDir, "probe.mjs");
		for (const subpath of EXPORT_PATHS) {
			const specifier =
				subpath === "."
					? PKG_NAME
					: `${PKG_NAME}${subpath.slice(1)}`;
			const probe = `await import(${JSON.stringify(specifier)});\nconsole.log("ok");\n`;
			fs.writeFileSync(probeFile, probe);
			try {
				run("node", [probeFile], tmpDir);
				console.log(`[check-clean-install] import('${specifier}') OK`);
			} catch (err) {
				const stderr = err.stderr?.toString() ?? String(err);
				console.error(
					`[check-clean-install] import('${specifier}') FAILED:\n${stderr}`,
				);
				failures.push(subpath);
			}
		}
		if (failures.length > 0) {
			fail(`imports failed for: ${failures.join(", ")}`);
		}
		console.log(
			`[check-clean-install] PASS: all ${EXPORT_PATHS.length} export paths importable without optional peers.`,
		);
	} finally {
		fs.rmSync(tmpDir, { recursive: true, force: true });
		try {
			fs.rmSync(tarball, { force: true });
		} catch {
			// best effort
		}
	}
}

main();
