import { defineConfig } from "vitest/config";
import path from "node:path";

// The auditor's round instruments live under docs/security/audits and keep their own convention
// ('PASSES while the attack works'), so they are not part of the CI gate (`npm test`). Run them on demand with:
//   npm run test:audit [-- <archivo|patrón>]
// A failing instrument here records a finding, not a regression in the product.
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
