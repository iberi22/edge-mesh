type ZstdModule = typeof import("@bokuweb/zstd-wasm");
type CborModule = typeof import("cbor-x");

/**
 * Lazily loads the optional `@bokuweb/zstd-wasm` and `cbor-x` peer
 * dependencies.
 *
 * Both are optional: importing `@swal/edge-mesh` must work without them.
 * Only `PayloadOptimizer` needs them, so the imports happen here — inside
 * the functions that need them — instead of at module top level.
 */
async function loadCodec(): Promise<{ zstd: ZstdModule; cbor: CborModule }> {
	try {
		const [zstd, cbor] = await Promise.all([
			import("@bokuweb/zstd-wasm"),
			import("cbor-x"),
		]);
		return { zstd, cbor };
	} catch {
		throw new Error(
			"[edge-mesh] PayloadOptimizer requires the optional peer dependencies '@bokuweb/zstd-wasm' and 'cbor-x'. Install them with: npm i @bokuweb/zstd-wasm cbor-x",
		);
	}
}

let isZstdInitialized = false;

/**
 * Initializes the WASM module for Zstd.
 * Must be called once before compressing or decompressing.
 */
export async function initializeOptimizer(): Promise<void> {
	if (!isZstdInitialized) {
		const { zstd } = await loadCodec();
		await zstd.init();
		isZstdInitialized = true;
	}
}

/**
 * Utility class to compress large payloads before storing them in local databases (IndexedDB/OPFS)
 * or broadcasting them across the P2P network.
 *
 * It serializes objects to CBOR (Concise Binary Object Representation) and then compresses
 * the binary stream using Zstandard (Zstd), significantly reducing the required space.
 */
export class PayloadOptimizer {
	/**
	 * Serializes an object to CBOR and compresses it with Zstd.
	 * @param payload Any serializable JavaScript object.
	 * @param level Compression level (default 10).
	 * @returns A Uint8Array containing the compressed binary data.
	 */
	static async compressPayload<T>(
		payload: T,
		level: number = 10,
	): Promise<Uint8Array> {
		await initializeOptimizer();
		const { zstd, cbor } = await loadCodec();

		// 1. Serialize to CBOR
		const cborBuffer = cbor.encode(payload);

		// 2. Compress with Zstd
		const compressed = zstd.compress(new Uint8Array(cborBuffer), level);

		return compressed;
	}

	/**
	 * Decompresses Zstd data and deserializes it from CBOR back to the original object.
	 * @param buffer The compressed binary data (Uint8Array).
	 * @returns The original parsed object.
	 */
	static async decompressPayload<T>(buffer: Uint8Array): Promise<T> {
		await initializeOptimizer();
		const { zstd, cbor } = await loadCodec();

		// 1. Decompress from Zstd
		const decompressed = zstd.decompress(buffer);

		// 2. Deserialize from CBOR
		const payload = cbor.decode(decompressed) as T;

		return payload;
	}
}
