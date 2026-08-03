import * as fs from "node:fs";
import * as path from "node:path";

export interface BenchmarkResult {
	readonly name: string;
	readonly metric: string;
	readonly value: number;
	readonly unit: string;
	readonly threshold: number;
	readonly condition: string;
	readonly passed: boolean;
}

export function saveBenchmarkResult(result: BenchmarkResult): void {
	const dirPath = path.resolve(process.cwd(), "docs/performance");
	const filePath = path.join(dirPath, "baseline.json");

	// Create directory if it doesn't exist
	if (!fs.existsSync(dirPath)) {
		fs.mkdirSync(dirPath, { recursive: true });
	}

	let baseline: { timestamp: string; benchmarks: BenchmarkResult[] } = {
		timestamp: new Date().toISOString(),
		benchmarks: [],
	};

	if (fs.existsSync(filePath)) {
		try {
			const content = fs.readFileSync(filePath, "utf-8");
			baseline = JSON.parse(content);
		} catch {
			// If parsing fails, start fresh
		}
	}

	// Update timestamp
	baseline = {
		...baseline,
		timestamp: new Date().toISOString(),
	};

	// Find and update or add new benchmark
	const existingIdx = baseline.benchmarks.findIndex(
		(b) => b.name === result.name,
	);
	if (existingIdx !== -1) {
		const updatedBenchmarks = [...baseline.benchmarks];
		updatedBenchmarks[existingIdx] = result;
		baseline = {
			...baseline,
			benchmarks: updatedBenchmarks,
		};
	} else {
		baseline = {
			...baseline,
			benchmarks: [...baseline.benchmarks, result],
		};
	}

	fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2), "utf-8");
}
