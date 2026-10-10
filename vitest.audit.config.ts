import { defineConfig } from "vitest/config";
import path from "node:path";

// The auditor's round instruments under docs/security/audits keep their own convention ('PASSES while the attack
// works'), so they are not part of the CI gate (`npm test`): a failing instrument records that an attack still works,
// and most of the red ones are stale oracles or harness bitrot, not findings. The open witnesses that still pass are
// gated in tests/web/audit-regressions-r6-open.test.ts. Run this archive on demand with:
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
