import type { EdgeMesh } from "../../edge-mesh.js";

// Declaración de tipos globales para evitar errores de compilación tsc
// en entornos que no tengan WebGPU instalado por defecto
// biome-ignore lint/suspicious/noExplicitAny: WebGPU global types bypass
declare const GPUBufferUsage: any;
// biome-ignore lint/suspicious/noExplicitAny: WebGPU global types bypass
declare const GPUMapMode: any;

// ─── GPU TASK TYPES ─────────────────────────────────────────────────────────

export type GpuKernelType = "vector-sum" | "dot" | "matrix-scale";

export interface GpuTask {
	readonly id: string;
	readonly kernel: GpuKernelType;
	readonly inputA: readonly number[];
	readonly inputB?: readonly number[]; // Usado para vector-sum y dot
	readonly scalar?: number; // Usado para matrix-scale
}

export interface GpuTaskResult {
	readonly taskId: string;
	readonly result: readonly number[] | number;
	readonly durationMs: number;
	readonly fallbackUsed: boolean;
	readonly success: boolean;
	readonly error?: string;
}

// ─── CPU FALLBACKS ─────────────────────────────────────────────────────────

export function runCpuVectorSum(
	a: readonly number[],
	b: readonly number[],
): number[] {
	if (a.length !== b.length) {
		throw new Error(
			`Mismatched lengths for vector-sum: ${a.length} vs ${b.length}`,
		);
	}
	const result = new Array<number>(a.length);
	for (let i = 0; i < a.length; i++) {
		result[i] = a[i] + b[i];
	}
	return result;
}

export function runCpuDot(a: readonly number[], b: readonly number[]): number {
	if (a.length !== b.length) {
		throw new Error(
			`Mismatched lengths for dot product: ${a.length} vs ${b.length}`,
		);
	}
	let sum = 0;
	for (let i = 0; i < a.length; i++) {
		sum += a[i] * b[i];
	}
	return sum;
}

export function runCpuMatrixScale(
	matrix: readonly number[],
	scalar: number,
): number[] {
	const result = new Array<number>(matrix.length);
	for (let i = 0; i < matrix.length; i++) {
		result[i] = matrix[i] * scalar;
	}
	return result;
}

// ─── WGSL SHADERS ──────────────────────────────────────────────────────────

const SHADER_VECTOR_SUM = `
@group(0) @binding(0) var<storage, read> inputA: array<f32>;
@group(0) @binding(1) var<storage, read> inputB: array<f32>;
@group(0) @binding(2) var<storage, read_write> output: array<f32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let index = global_id.x;
    if (index >= arrayLength(&inputA)) {
        return;
    }
    output[index] = inputA[index] + inputB[index];
}
`;

const SHADER_DOT_MULTIPLY = `
@group(0) @binding(0) var<storage, read> inputA: array<f32>;
@group(0) @binding(1) var<storage, read> inputB: array<f32>;
@group(0) @binding(2) var<storage, read_write> output: array<f32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let index = global_id.x;
    if (index >= arrayLength(&inputA)) {
        return;
    }
    output[index] = inputA[index] * inputB[index];
}
`;

const SHADER_MATRIX_SCALE = `
@group(0) @binding(0) var<storage, read> inputA: array<f32>;
@group(0) @binding(1) var<storage, read> scalar: array<f32>;
@group(0) @binding(2) var<storage, read_write> output: array<f32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let index = global_id.x;
    if (index >= arrayLength(&inputA)) {
        return;
    }
    output[index] = inputA[index] * scalar[0];
}
`;

// ─── GPU AGENT PLUGIN CLASS ────────────────────────────────────────────────

export class GpuAgentPlugin {
	private readonly edgeMesh?: EdgeMesh;
	private readonly taskQueue: GpuTask[] = [];

	// Permitir inyección de mock GPUDevice para facilitar pruebas en el futuro si es necesario
	// biome-ignore lint/suspicious/noExplicitAny: Mock WebGPU device
	private mockDevice: any = null;

	constructor(edgeMesh?: EdgeMesh) {
		this.edgeMesh = edgeMesh;
	}

	/**
	 * Obtiene la instancia asociada de EdgeMesh.
	 */
	getEdgeMesh(): EdgeMesh | undefined {
		return this.edgeMesh;
	}

	/**
	 * Configura un dispositivo mock de WebGPU para propósitos de prueba/depuración.
	 */
	// biome-ignore lint/suspicious/noExplicitAny: Mock WebGPU device
	setMockDevice(device: any): void {
		this.mockDevice = device;
	}

	/**
	 * Obtiene el tamaño de la cola de tareas.
	 */
	getQueueSize(): number {
		return this.taskQueue.length;
	}

	/**
	 * Detecta si WebGPU está soportado y disponible.
	 */
	isWebGpuSupported(): boolean {
		if (this.mockDevice) return true;
		return (
			typeof navigator !== "undefined" &&
			// biome-ignore lint/suspicious/noExplicitAny: WebGPU navigator property
			typeof (navigator as any).gpu !== "undefined"
		);
	}

	/**
	 * Ejecuta un kernel en CPU.
	 */
	executeOnCpu(task: GpuTask): readonly number[] | number {
		switch (task.kernel) {
			case "vector-sum": {
				if (!task.inputB) {
					throw new Error("Missing inputB for vector-sum task");
				}
				return runCpuVectorSum(task.inputA, task.inputB);
			}
			case "dot": {
				if (!task.inputB) {
					throw new Error("Missing inputB for dot task");
				}
				return runCpuDot(task.inputA, task.inputB);
			}
			case "matrix-scale": {
				if (task.scalar === undefined) {
					throw new Error("Missing scalar for matrix-scale task");
				}
				return runCpuMatrixScale(task.inputA, task.scalar);
			}
			default:
				throw new Error("Unknown kernel type");
		}
	}

	/**
	 * Ejecuta una tarea en GPU usando WebGPU.
	 */
	async executeOnGpu(task: GpuTask): Promise<readonly number[] | number> {
		if (!this.isWebGpuSupported()) {
			throw new Error("WebGPU is not supported on this platform");
		}

		// 1. Obtener dispositivo (usar mock si existe)
		let device = this.mockDevice;
		if (!device) {
			// biome-ignore lint/suspicious/noExplicitAny: WebGPU navigator property
			const gpu = (navigator as any).gpu;
			const adapter = await gpu.requestAdapter();
			if (!adapter) {
				throw new Error("No WebGPU adapter found");
			}
			device = await adapter.requestDevice();
			if (!device) {
				throw new Error("No WebGPU device found");
			}
		}

		// 2. Determinar el shader correcto
		let shaderCode = "";
		switch (task.kernel) {
			case "vector-sum":
				shaderCode = SHADER_VECTOR_SUM;
				break;
			case "dot":
				shaderCode = SHADER_DOT_MULTIPLY;
				break;
			case "matrix-scale":
				shaderCode = SHADER_MATRIX_SCALE;
				break;
			default:
				throw new Error(`Unsupported kernel on GPU: ${task.kernel}`);
		}

		// 3. Crear buffers de entrada
		const arrayA = new Float32Array(task.inputA);
		const bufferA = device.createBuffer({
			size: arrayA.byteLength,
			// biome-ignore lint/suspicious/noExplicitAny: WebGPU type bypass
			usage: (GPUBufferUsage as any).STORAGE | (GPUBufferUsage as any).COPY_DST,
			mappedAtCreation: true,
		});
		new Float32Array(bufferA.getMappedRange()).set(arrayA);
		bufferA.unmap();

		// biome-ignore lint/suspicious/noExplicitAny: WebGPU buffer type bypass
		let bufferB: any = null;
		if (task.kernel === "vector-sum" || task.kernel === "dot") {
			if (!task.inputB) {
				throw new Error(`Missing inputB for ${task.kernel}`);
			}
			const arrayB = new Float32Array(task.inputB);
			bufferB = device.createBuffer({
				size: arrayB.byteLength,
				usage:
					// biome-ignore lint/suspicious/noExplicitAny: WebGPU type bypass
					(GPUBufferUsage as any).STORAGE | (GPUBufferUsage as any).COPY_DST,
				mappedAtCreation: true,
			});
			new Float32Array(bufferB.getMappedRange()).set(arrayB);
			bufferB.unmap();
		} else if (task.kernel === "matrix-scale") {
			if (task.scalar === undefined) {
				throw new Error("Missing scalar for matrix-scale");
			}
			const arrayScalar = new Float32Array([task.scalar]);
			bufferB = device.createBuffer({
				size: arrayScalar.byteLength,
				usage:
					// biome-ignore lint/suspicious/noExplicitAny: WebGPU type bypass
					(GPUBufferUsage as any).STORAGE | (GPUBufferUsage as any).COPY_DST,
				mappedAtCreation: true,
			});
			new Float32Array(bufferB.getMappedRange()).set(arrayScalar);
			bufferB.unmap();
		}

		// Buffer de salida
		const outputSize = arrayA.byteLength;
		const bufferOutput = device.createBuffer({
			size: outputSize,
			// biome-ignore lint/suspicious/noExplicitAny: WebGPU type bypass
			usage: (GPUBufferUsage as any).STORAGE | (GPUBufferUsage as any).COPY_SRC,
		});

		// Buffer para leer resultados en CPU
		const bufferRead = device.createBuffer({
			size: outputSize,
			usage:
				// biome-ignore lint/suspicious/noExplicitAny: WebGPU type bypass
				(GPUBufferUsage as any).COPY_DST | (GPUBufferUsage as any).MAP_READ,
		});

		// 4. Configurar pipeline y bindgroups
		const shaderModule = device.createShaderModule({ code: shaderCode });
		const computePipeline = device.createComputePipeline({
			layout: "auto",
			compute: {
				module: shaderModule,
				entryPoint: "main",
			},
		});

		const bindGroup = device.createBindGroup({
			layout: computePipeline.getBindGroupLayout(0),
			entries: [
				{ binding: 0, resource: { buffer: bufferA } },
				{ binding: 1, resource: { buffer: bufferB } },
				{ binding: 2, resource: { buffer: bufferOutput } },
			],
		});

		// 5. Grabar y enviar comandos
		const commandEncoder = device.createCommandEncoder();
		const passEncoder = commandEncoder.beginComputePass();
		passEncoder.setPipeline(computePipeline);
		passEncoder.setBindGroup(0, bindGroup);
		const workgroupCount = Math.ceil(task.inputA.length / 64);
		passEncoder.dispatchWorkgroups(workgroupCount);
		passEncoder.end();

		commandEncoder.copyBufferToBuffer(
			bufferOutput,
			0,
			bufferRead,
			0,
			outputSize,
		);

		device.queue.submit([commandEncoder.finish()]);

		// 6. Leer resultados
		// biome-ignore lint/suspicious/noExplicitAny: WebGPU type bypass
		await bufferRead.mapAsync((GPUMapMode as any).READ);
		const arrayBuffer = bufferRead.getMappedRange();
		const outputArray = Array.from(new Float32Array(arrayBuffer));
		bufferRead.unmap();

		// Liberar buffers
		bufferA.destroy();
		bufferB.destroy();
		bufferOutput.destroy();
		bufferRead.destroy();

		// 7. Procesar resultado final según tipo de kernel
		if (task.kernel === "dot") {
			// Reducción final en CPU de la multiplicación elemento por elemento
			let sum = 0;
			for (let i = 0; i < outputArray.length; i++) {
				sum += outputArray[i];
			}
			return sum;
		}

		return outputArray;
	}

	/**
	 * Encola y ejecuta una tarea. Si WebGPU está disponible e inicia correctamente,
	 * se ejecuta en GPU. De lo contrario, se activa automáticamente el CPU fallback.
	 */
	async enqueueTask(task: GpuTask): Promise<GpuTaskResult> {
		this.taskQueue.push(task);
		const startTime = Date.now();

		let result: readonly number[] | number = [];
		let fallbackUsed = true;
		let success = false;
		let errorMsg: string | undefined;

		try {
			if (this.isWebGpuSupported()) {
				try {
					result = await this.executeOnGpu(task);
					fallbackUsed = false;
					success = true;
				} catch (gpuError) {
					// Fallback silencioso a CPU si la ejecución en GPU falla
					result = this.executeOnCpu(task);
					fallbackUsed = true;
					success = true;
					errorMsg = `WebGPU execution failed, fell back to CPU: ${(gpuError as Error).message}`;
				}
			} else {
				result = this.executeOnCpu(task);
				fallbackUsed = true;
				success = true;
			}
		} catch (err) {
			success = false;
			errorMsg = (err as Error).message;
		} finally {
			// Quitar la tarea de la cola
			const idx = this.taskQueue.findIndex((t) => t.id === task.id);
			if (idx !== -1) {
				this.taskQueue.splice(idx, 1);
			}
		}

		const durationMs = Date.now() - startTime;

		return {
			taskId: task.id,
			result,
			durationMs,
			fallbackUsed,
			success,
			error: errorMsg,
		};
	}

	/**
	 * Hook/Método de verificación para validar que el resultado de una tarea sea correcto.
	 * Ejecuta el cálculo correspondiente en CPU y lo compara con un margen de tolerancia (épsilon).
	 */
	verifyTask(
		task: GpuTask,
		resultToVerify: readonly number[] | number,
		tolerance = 1e-5,
	): boolean {
		try {
			const expected = this.executeOnCpu(task);

			if (typeof expected === "number") {
				if (typeof resultToVerify !== "number") return false;
				return Math.abs(expected - resultToVerify) <= tolerance;
			}

			if (Array.isArray(expected)) {
				if (!Array.isArray(resultToVerify)) return false;
				if (expected.length !== resultToVerify.length) return false;

				for (let i = 0; i < expected.length; i++) {
					if (
						Math.abs(expected[i] - (resultToVerify as readonly number[])[i]) >
						tolerance
					) {
						return false;
					}
				}
				return true;
			}

			return false;
		} catch {
			return false;
		}
	}
}
