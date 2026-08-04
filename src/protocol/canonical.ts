import { bytesAHex } from "./utils.js";

/**
 * Deterministic stringify of any value by sorting object keys alphabetically.
 * Uint8Array instances are serialized as their hex representation.
 */
export function canonicalStringify(val: any): string {
	if (val === null || val === undefined) {
		return "null";
	}
	if (val instanceof Uint8Array) {
		return JSON.stringify(bytesAHex(val));
	}
	if (typeof val !== "object") {
		return JSON.stringify(val);
	}
	if (Array.isArray(val)) {
		return "[" + val.map((v) => canonicalStringify(v)).join(",") + "]";
	}
	const keys = Object.keys(val).sort();
	return (
		"{" +
		keys
			.map(
				(k) =>
					`${JSON.stringify(k)}:${canonicalStringify((val as Record<string, unknown>)[k])}`,
			)
			.join(",") +
		"}"
	);
}

/**
 * Returns canonical byte serialization of any value.
 */
export function canonicalSerialize(val: any): Uint8Array {
	return new TextEncoder().encode(canonicalStringify(val));
}
