import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
	test: {
		alias: {
			"@iberi22/edge-mesh": path.resolve(__dirname, "./src/index.ts"),
		},
	},
});
