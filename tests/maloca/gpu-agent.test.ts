import { describe, expect, it, vi, afterEach, beforeEach } from "vitest";
import {
	GpuAgentPlugin,
	runCpuVectorSum,
	runCpuDot,
	runCpuMatrixScale,
	type GpuTask,
} from "../../src/index.js";

describe("GpuAgent - CPU Fallback Calculations", () => {
	it("should correctly compute vector sum on CPU", () => {
		const a = [1, 2, 3];
		const b = [4, 5, 6];
		const result = runCpuVectorSum(a, b);
		expect(result).toEqual([5, 7, 9]);
	});

	it("should throw error on vector sum when lengths do not match", () => {
		const a = [1, 2];
		const b = [4, 5, 6];
		expect(() => runCpuVectorSum(a, b)).toThrow("Mismatched lengths");
	});

	it("should correctly compute dot product on CPU", () => {
		const a = [1, 2, 3];
		const b = [4, 5, 6];
		const result = runCpuDot(a, b); // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
		expect(result).toBe(32);
	});

	it("should throw error on dot product when lengths do not match", () => {
		const a = [1, 2];
		const b = [4, 5, 6];
		expect(() => runCpuDot(a, b)).toThrow("Mismatched lengths");
	});

	it("should correctly compute matrix scaling on CPU", () => {
		const matrix = [1, 2, 3, 4];
		const scalar = 2.5;
		const result = runCpuMatrixScale(matrix, scalar);
		expect(result).toEqual([2.5, 5, 7.5, 10]);
	});
});

describe("GpuAgentPlugin - Task Queue & CPU Fallback Mode", () => {
	let plugin: GpuAgentPlugin;

	beforeEach(() => {
		plugin = new GpuAgentPlugin();
	});

	it("should run a vector-sum task in CPU fallback mode when WebGPU is missing", async () => {
		const task: GpuTask = {
			id: "task-1",
			kernel: "vector-sum",
			inputA: [1, 2, 3],
			inputB: [10, 20, 30],
		};

		const result = await plugin.enqueueTask(task);
		expect(result.success).toBe(true);
		expect(result.fallbackUsed).toBe(true);
		expect(result.result).toEqual([11, 22, 33]);
		expect(plugin.getQueueSize()).toBe(0);
	});

	it("should run a dot task in CPU fallback mode when WebGPU is missing", async () => {
		const task: GpuTask = {
			id: "task-2",
			kernel: "dot",
			inputA: [2, 3],
			inputB: [4, 5],
		};

		const result = await plugin.enqueueTask(task);
		expect(result.success).toBe(true);
		expect(result.fallbackUsed).toBe(true);
		expect(result.result).toBe(23); // 2*4 + 3*5 = 8 + 15 = 23
	});

	it("should run a matrix-scale task in CPU fallback mode when WebGPU is missing", async () => {
		const task: GpuTask = {
			id: "task-3",
			kernel: "matrix-scale",
			inputA: [1, 2, 3],
			scalar: 10,
		};

		const result = await plugin.enqueueTask(task);
		expect(result.success).toBe(true);
		expect(result.fallbackUsed).toBe(true);
		expect(result.result).toEqual([10, 20, 30]);
	});
});

describe("GpuAgentPlugin - Verification Hook (verifyTask)", () => {
	let plugin: GpuAgentPlugin;

	beforeEach(() => {
		plugin = new GpuAgentPlugin();
	});

	it("should verify correct vector-sum tasks successfully", () => {
		const task: GpuTask = {
			id: "task-4",
			kernel: "vector-sum",
			inputA: [1, 2, 3],
			inputB: [4, 5, 6],
		};

		const correctResult = [5, 7, 9];
		const verification = plugin.verifyTask(task, correctResult);
		expect(verification).toBe(true);
	});

	it("should reject incorrect vector-sum tasks", () => {
		const task: GpuTask = {
			id: "task-5",
			kernel: "vector-sum",
			inputA: [1, 2, 3],
			inputB: [4, 5, 6],
		};

		const incorrectResult = [5, 7, 10]; // last element is incorrect
		const verification = plugin.verifyTask(task, incorrectResult);
		expect(verification).toBe(false);
	});

	it("should verify correct dot tasks successfully", () => {
		const task: GpuTask = {
			id: "task-6",
			kernel: "dot",
			inputA: [2, 3],
			inputB: [4, 5],
		};

		const verification = plugin.verifyTask(task, 23);
		expect(verification).toBe(true);
	});

	it("should reject incorrect dot tasks", () => {
		const task: GpuTask = {
			id: "task-7",
			kernel: "dot",
			inputA: [2, 3],
			inputB: [4, 5],
		};

		const verification = plugin.verifyTask(task, 22.9); // outside default tolerance
		expect(verification).toBe(false);
	});

	it("should verify tasks using custom tolerance", () => {
		const task: GpuTask = {
			id: "task-8",
			kernel: "dot",
			inputA: [2, 3],
			inputB: [4, 5],
		};

		// Within tolerance of 0.5
		const verification = plugin.verifyTask(task, 23.4, 0.5);
		expect(verification).toBe(true);
	});
});

describe("GpuAgentPlugin - WebGPU Mock Execution", () => {
	let plugin: GpuAgentPlugin;

	beforeEach(() => {
		plugin = new GpuAgentPlugin();

		// Set global GPUMapMode and GPUBufferUsage
		vi.stubGlobal("GPUMapMode", { READ: 1 });
		vi.stubGlobal("GPUBufferUsage", { STORAGE: 1, COPY_DST: 2, COPY_SRC: 4, MAP_READ: 8 });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("should execute via WebGPU path when WebGPU is supported and device is configured", async () => {
		const createdBuffers: any[] = [];

		const mockDevice = {
			createBuffer: vi.fn().mockImplementation(({ size }) => {
				const arrayBuffer = new ArrayBuffer(size);
				const buf = {
					getMappedRange: vi.fn().mockReturnValue(arrayBuffer),
					unmap: vi.fn(),
					destroy: vi.fn(),
					mapAsync: vi.fn().mockImplementation(async () => {
						// Write the expected result to the read-back buffer
						new Float32Array(arrayBuffer).set([11, 22, 33]);
					}),
				};
				createdBuffers.push(buf);
				return buf;
			}),
			createShaderModule: vi.fn().mockReturnValue({}),
			createComputePipeline: vi.fn().mockReturnValue({
				getBindGroupLayout: vi.fn().mockReturnValue({}),
			}),
			createBindGroup: vi.fn().mockReturnValue({}),
			createCommandEncoder: vi.fn().mockReturnValue({
				beginComputePass: vi.fn().mockReturnValue({
					setPipeline: vi.fn(),
					setBindGroup: vi.fn(),
					dispatchWorkgroups: vi.fn(),
					end: vi.fn(),
				}),
				copyBufferToBuffer: vi.fn(),
				finish: vi.fn().mockReturnValue({}),
			}),
			queue: {
				submit: vi.fn(),
			},
		};

		plugin.setMockDevice(mockDevice);

		const task: GpuTask = {
			id: "gpu-task-1",
			kernel: "vector-sum",
			inputA: [1, 2, 3],
			inputB: [10, 20, 30],
		};

		const result = await plugin.enqueueTask(task);
		expect(result.success).toBe(true);
		expect(result.fallbackUsed).toBe(false);
		expect(result.result).toEqual([11, 22, 33]);
		expect(mockDevice.createBuffer).toHaveBeenCalled();
		expect(mockDevice.queue.submit).toHaveBeenCalled();
	});

	it("should fallback to CPU if WebGPU execution throws an error", async () => {
		const mockDevice = {
			createBuffer: vi.fn().mockImplementation(() => {
				throw new Error("Out of memory on GPU device");
			}),
		};

		plugin.setMockDevice(mockDevice);

		const task: GpuTask = {
			id: "gpu-task-2",
			kernel: "vector-sum",
			inputA: [1, 2, 3],
			inputB: [10, 20, 30],
		};

		const result = await plugin.enqueueTask(task);
		expect(result.success).toBe(true);
		expect(result.fallbackUsed).toBe(true);
		expect(result.result).toEqual([11, 22, 33]);
		expect(result.error).toContain("WebGPU execution failed");
	});
});
