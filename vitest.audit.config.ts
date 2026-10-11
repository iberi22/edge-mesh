import { defineConfig } from "vitest/config";
import path from "node:path";

// docs/security/audits holds the auditor's round instruments: they PASS while the attack works, so a red
// one is not a finding (most are stale oracles for fixed attacks, or harness bitrot from older rounds). The
// open witnesses that still pass are gated in tests/web/audit-regressions-r6-open.test.ts; the archive itself
// stays a manual command (`npm run test:audit`). Run this archive on demand with:
//   npm run test:audit [-- <archivo|patrón>]
export default defineConfig({
	test: {
		include: ["docs/security/audits/**/*.test.ts"],
		exclude: ["node_modules/**", "dist/**"],
		// ML-DSA-65 makes the multi-device mesh tests CPU-bound: same budget as the regression config
		testTimeout: 20_000,
		alias: {
			"@iberi22/edge-mesh": path.resolve(import.meta.dirname ?? ".", "./src/index.ts"),
		},
	},
});
