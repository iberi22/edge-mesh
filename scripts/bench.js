import { MessageDeduplicator } from "../dist/index.js";
import { createPostQuantumIdentity, generateKeypair } from "../dist/index.js";
import { createEnvelope, signEnvelope, verifyEnvelopeSignature } from "../dist/index.js";
import fs from "node:fs";

async function main() {
  console.log("Running benchmarks...");

  // 1. Message Deduplicator Benchmark
  console.log("Benchmarking MessageDeduplicator...");
  const deduplicator = new MessageDeduplicator({ ventanaMs: 5000 });
  const count = 50000;
  const startDeduplicator = performance.now();
  for (let i = 0; i < count; i++) {
    deduplicator.esDuplicado(`msg-${i}`);
  }
  const endDeduplicator = performance.now();
  const deduplicatorDurationMs = endDeduplicator - startDeduplicator;
  const deduplicatorOpsPerSec = Math.round((count / deduplicatorDurationMs) * 1000);
  console.log(`Deduplicator: ${deduplicatorOpsPerSec} ops/sec (${deduplicatorDurationMs.toFixed(2)} ms total)`);

  // 2. Post-Quantum Identity Signature Benchmark
  console.log("Benchmarking ML-DSA-65...");
  const identity = createPostQuantumIdentity("n1", generateKeypair("maestra"));
  const env = createEnvelope("SYNC", "n1", "*", { foo: "bar" });

  const signIterations = 10;
  const startSign = performance.now();
  for (let i = 0; i < signIterations; i++) {
    await signEnvelope(env, identity);
  }
  const endSign = performance.now();
  const signDurationMs = endSign - startSign;
  const signAvgLatencyMs = signDurationMs / signIterations;
  console.log(`ML-DSA-65 Sign: ${signAvgLatencyMs.toFixed(2)} ms avg (${signDurationMs.toFixed(2)} ms total)`);

  // 3. Post-Quantum Identity Verification Benchmark
  const signedEnv = await signEnvelope(env, identity);
  const verifyIterations = 10;
  const startVerify = performance.now();
  for (let i = 0; i < verifyIterations; i++) {
    await verifyEnvelopeSignature(signedEnv, identity.exportarPublico(), identity);
  }
  const endVerify = performance.now();
  const verifyDurationMs = endVerify - startVerify;
  const verifyAvgLatencyMs = verifyDurationMs / verifyIterations;
  console.log(`ML-DSA-65 Verify: ${verifyAvgLatencyMs.toFixed(2)} ms avg (${verifyDurationMs.toFixed(2)} ms total)`);

  const results = {
    deduplicator_ops_per_second: deduplicatorOpsPerSec,
    signature_latency_ms: signAvgLatencyMs,
    verification_latency_ms: verifyAvgLatencyMs
  };

  fs.writeFileSync("benchmark-results.json", JSON.stringify(results, null, 2));
  console.log("Benchmark results saved to benchmark-results.json");
}

main().catch(err => {
  console.error("Benchmark failed:", err);
  process.exit(1);
});
