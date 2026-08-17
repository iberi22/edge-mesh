import { compress, decompress, init } from "@bokuweb/zstd-wasm";
import { decode, encode } from "cbor-x";

let isZstdInitialized = false;

/**
 * Initializes the WASM module for Zstd.
 * Must be called once before compressing or decompressing.
 */
export async function initializeOptimizer(): Promise<void> {
	if (!isZstdInitialized) {
		await init();
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

		// 1. Serialize to CBOR
		const cborBuffer = encode(payload);

		// 2. Compress with Zstd
		const compressed = compress(new Uint8Array(cborBuffer), level);

		return compressed;
	}

	/**
	 * Decompresses Zstd data and deserializes it from CBOR back to the original object.
	 * @param buffer The compressed binary data (Uint8Array).
	 * @returns The original parsed object.
	 */
	static async decompressPayload<T>(buffer: Uint8Array): Promise<T> {
		await initializeOptimizer();

		// 1. Decompress from Zstd
		const decompressed = decompress(buffer);

		// 2. Deserialize from CBOR
		const payload = decode(decompressed) as T;

		return payload;
	}
}
