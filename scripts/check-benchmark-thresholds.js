import fs from "node:fs";

const THRESHOLDS = {
  deduplicator_ops_per_second: 10000, // min 10k ops/sec
  signature_latency_ms: 100,          // max 100ms per signature (usually <5ms)
  verification_latency_ms: 100       // max 100ms per verification (usually <5ms)
};

function main() {
  console.log("Checking benchmark thresholds...");
  if (!fs.existsSync("benchmark-results.json")) {
    console.error("Error: benchmark-results.json not found. Run 'npm run bench' first.");
    process.exit(1);
  }

  const results = JSON.parse(fs.readFileSync("benchmark-results.json", "utf8"));
  let passed = true;

  if (results.deduplicator_ops_per_second < THRESHOLDS.deduplicator_ops_per_second) {
    console.error(`❌ Benchmark failure: Deduplicator throughput is too low. Expected >= ${THRESHOLDS.deduplicator_ops_per_second} ops/sec, got ${results.deduplicator_ops_per_second}`);
    passed = false;
  } else {
    console.log(`✅ Deduplicator throughput: ${results.deduplicator_ops_per_second} ops/sec (Threshold: >= ${THRESHOLDS.deduplicator_ops_per_second})`);
  }

  if (results.signature_latency_ms > THRESHOLDS.signature_latency_ms) {
    console.error(`❌ Benchmark failure: Signature latency is too high. Expected <= ${THRESHOLDS.signature_latency_ms} ms, got ${results.signature_latency_ms.toFixed(2)} ms`);
    passed = false;
  } else {
    console.log(`✅ Signature latency: ${results.signature_latency_ms.toFixed(2)} ms (Threshold: <= ${THRESHOLDS.signature_latency_ms} ms)`);
  }

  if (results.verification_latency_ms > THRESHOLDS.verification_latency_ms) {
    console.error(`❌ Benchmark failure: Verification latency is too high. Expected <= ${THRESHOLDS.verification_latency_ms} ms, got ${results.verification_latency_ms.toFixed(2)} ms`);
    passed = false;
  } else {
    console.log(`✅ Verification latency: ${results.verification_latency_ms.toFixed(2)} ms (Threshold: <= ${THRESHOLDS.verification_latency_ms} ms)`);
  }

  if (!passed) {
    console.error("❌ Some benchmark thresholds were not met!");
    process.exit(1);
  }

  console.log("🎉 All benchmark thresholds are met successfully!");
}

main();
