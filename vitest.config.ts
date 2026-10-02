import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
	test: {
		exclude: ["workers/**", "node_modules/**", "dist/**", "packages/**"],
		alias: {
			"@iberi22/edge-mesh": path.resolve(import.meta.dirname ?? ".", "./src/index.ts"),
		},
	},
});
