import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
	test: {
		exclude: [
			"workers/**",
			"node_modules/**",
			"dist/**",
			"packages/**",
			// docs/security/audits holds the auditor's round instruments: they PASS while the attack works, so a red
			// one is not a finding (most are stale oracles for fixed attacks, or harness bitrot from older rounds). The
			// open witnesses that still pass are gated in tests/web/audit-regressions-r6-open.test.ts; the archive itself
			// stays a manual command (`npm run test:audit`).
			"docs/security/audits/**",
		],
		// ML-DSA-65 (pure JS, ~7 ms per signature, ~2 ms per verification) makes the multi-device mesh tests CPU-bound
		// when the whole suite runs in parallel: the default 5 s per test is too tight for them.
		testTimeout: 20_000,
		alias: {
			"@iberi22/edge-mesh": path.resolve(import.meta.dirname ?? ".", "./src/index.ts"),
		},
	},
});
