# ADR-005: Architectural Separation of GpuAgent Compute Kernels vs AiCore Deep Learning Models

**Status:** Accepted
**Date:** 2026-07-29
**Deciders:** SWAL team

## Context

The mesh network ecosystem requires support for diverse AI and compute workloads. These are represented by two distinct requirements:
1. **Model-level runtimes (`ai-core`)**: Heavyweight deep learning models (such as LLMs, TTS, ASR running through transformers.js, sherpa-onnx, and WebLLM) requiring complex neural network execution layers, runtime environments, and pre-trained model weight binaries.
2. **Stateless compute kernels (`gpu-agent`)**: Lightweight general-purpose GPGPU parallel mathematical tasks (such as element-wise `vector-sum`, `dot` products, or matrix scaling `matrix-scale`) designed for fast edge mathematics, federated learning weight aggregation, or computational validation.

To avoid bloating the core library and overloading client devices that do not require AI capabilities, a clean architectural decision on the relationship between these subsystems is needed.

Furthermore, executing multiple heavy AI and compute libraries in browser contexts can easily lead to triplicating browser runtimes (e.g., loading WebGPU/WASM drivers for `ai-core`, `gpu-agent`, and `WebLLM` independently). This redundancy causes heavy memory footprints, resource contention, and GPU driver failures (such as WebGPU device-lost contexts).

## Decision

1. **Independent Ecosystem Plugin**: Implement `gpu-agent` as a separate, lightweight plugin (under `src/adapters/gpu-agent/`) instead of absorbing it directly into `ai-core` or abandoning it.
2. **WGSL Kernels & CPU Fallback**: Provide low-level WebGPU WGSL kernels (`vector-sum`, `dot`, `matrix-scale`) with highly-optimized, robust CPU fallback mathematical implementations to guarantee seamless operation in environments where WebGPU is missing or disabled (such as standard Node.js/V8 tests or legacy browsers).
3. **Task Queue with Integrated Verification**: Implement a FIFO/asynchronous task queue (`cola de tareas`) that handles execution flow transparently, accompanied by a `verifyTask` verification hook to enable mathematical correctness checks on computed results.
4. **Avoid Runtime Triplication**:
   - **No Embedded Model Weights**: Keep `gpu-agent` purely stateless. It must not embed or download heavyweight neural model runtimes or weight parameters.
   - **Fail-Soft Environment Detection**: Implement graceful WebGPU feature detection. If `navigator.gpu` is blocked, lost, or already occupied by `ai-core` or other libraries, `gpu-agent` will automatically fall back to CPU execution without throwing unhandled exceptions.
   - **Interoperability**: Expose clean plugin APIs so that `ai-core` or other third-party adapters can delegate simple parallelized mathematical operations directly to `gpu-agent`, thereby centralizing raw math compute tasks.

## Consequences

- **Positive**:
  - Zero weight/model bloat in the core network library.
  - Bulletproof compatibility via robust JS CPU fallbacks.
  - Safe browser execution with automatic resource release and feature gating.
- **Negative**:
  - Developers wanting to execute complex neural networks must orchestrate model weight loading separately from the raw compute kernels.
- **Risks**:
  - CPU fallbacks can be slower for extremely large arrays, but they guarantee exact mathematical equivalence and testability.

## Alternatives Considered

| Alternative              | Rejected because                     |
|--------------------------|--------------------------------------|
| Absorb in `ai-core`      | Bloated the AI package, mixed concerns between stateless GPGPU and stateful model runtimes. |
| Abandon in Shelf         | Crucial math kernels (vector-sum, dot) are needed for local state verification and proofs. |
| Strict WebGPU only       | Failed to execute in standard Node.js server environments or Vitest test runners. |
