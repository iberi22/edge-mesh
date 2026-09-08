import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
	test: {
		include: ["**/*.{test,spec}.?(c|m)[jt]s?(x)", "tests/**/*test.ts", "tests/**/*.test.ts"],
		alias: {
			"@iberi22/edge-mesh": path.resolve(import.meta.dirname ?? ".", "./src/index.ts"),
		},
	},
});
