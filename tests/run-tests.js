import { spawnSync } from "node:child_process";

// Process process.argv to remove "--include" and just pass "performance"
const args = process.argv.slice(2);
const finalArgs = [];

for (let i = 0; i < args.length; i++) {
	if (args[i] === "--include") {
		// If next arg exists, push it as positional, skip "--include"
		if (args[i + 1]) {
			finalArgs.push(args[i + 1]);
			i++;
		}
	} else {
		finalArgs.push(args[i]);
	}
}

// Run vitest run with the parsed args
const result = spawnSync("npx", ["vitest", "run", ...finalArgs], {
	stdio: "inherit",
	shell: true,
});

process.exit(result.status ?? 0);
