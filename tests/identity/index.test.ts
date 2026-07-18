import { describe, expect, it } from "vitest";
import {
	deserializeKeypair,
	generateKeypair,
	serializeKeypair,
	TIPO_IDENTIDAD,
} from "../../src/identity/index.js";

describe("identity", () => {
	describe("generateKeypair", () => {
		it("should generate a valid keypair with ML-DSA-65 algorithm", () => {
			const keypair = generateKeypair();
			expect(keypair.algoritmo).toBe("ML-DSA-65");
			expect(keypair.parPrivado).toBeInstanceOf(Uint8Array);
			expect(keypair.parPublico).toBeInstanceOf(Uint8Array);
			expect(keypair.tipo).toBe(TIPO_IDENTIDAD.EPHEMERA);
		});

		it("should respect the specified identity type", () => {
			const keypair = generateKeypair(TIPO_IDENTIDAD.MAESTRA);
			expect(keypair.tipo).toBe(TIPO_IDENTIDAD.MAESTRA);
		});
	});

	describe("serialization roundtrip", () => {
		it("should correctly serialize and deserialize a keypair", () => {
			const original = generateKeypair();
			const serialized = serializeKeypair(original);
			expect(typeof serialized).toBe("string");

			const deserialized = deserializeKeypair(serialized);
			expect(deserialized.parPrivado).toEqual(original.parPrivado);
			expect(deserialized.parPublico).toEqual(original.parPublico);
			expect(deserialized.algoritmo).toBe(original.algoritmo);
		});
	});
});
