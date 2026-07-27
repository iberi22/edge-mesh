/**
 * Deterministically stringifies an object for signing.
 */
export function canonicalStringify(obj: unknown): string {
	if (obj === null || typeof obj !== "object") {
		return JSON.stringify(obj);
	}
	if (Array.isArray(obj)) {
		return "[" + obj.map(canonicalStringify).join(",") + "]";
	}
	const keys = Object.keys(obj as Record<string, unknown>).sort();
	return (
		"{" +
		keys
			.map(
				(k) =>
					`${JSON.stringify(k)}:${canonicalStringify((obj as Record<string, unknown>)[k])}`,
			)
			.join(",") +
		"}"
	);
}
