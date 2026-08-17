import { describe, expect, it } from "vitest";
import { PayloadOptimizer } from "../src/storage/optimizer.js";

describe("PayloadOptimizer", () => {
	it("debería comprimir y descomprimir un payload complejo manteniendo la fidelidad", async () => {
		const originalPayload = {
			id: "doc_123",
			content:
				"Este es un texto de prueba que se va a comprimir con Zstd y serializar con CBOR.",
			timestamp: Date.now(),
			tags: ["test", "cbor", "zstd"],
			metadata: {
				active: true,
				version: 1.5,
				scores: [100, 95, 87],
			},
		};

		// Compress
		const compressedData =
			await PayloadOptimizer.compressPayload(originalPayload);

		// Verify it's a Uint8Array
		expect(compressedData).toBeInstanceOf(Uint8Array);
		expect(compressedData.length).toBeGreaterThan(0);

		// Decompress
		const recoveredPayload =
			await PayloadOptimizer.decompressPayload<typeof originalPayload>(
				compressedData,
			);

		// Verify fidelity
		expect(recoveredPayload).toEqual(originalPayload);
	});
});
