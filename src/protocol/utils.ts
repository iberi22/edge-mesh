// ─── CRYPTO UTILITIES ──────────────────────────────────────────────────────

export function generarNonce(): string {
	const buf = new Uint8Array(16);
	crypto.getRandomValues(buf);
	return Array.from(buf)
		.map((b) => b.toString(36).padStart(2, "0"))
		.join("");
}

export function generarId(): string {
	const ts = Date.now().toString(36);
	const rand = Math.random().toString(36).slice(2, 8);
	return `${ts}-${rand}`;
}

export function bytesAHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export function hexABytes(hex: string): Uint8Array {
	const limpio = hex.replace(/[^0-9a-fA-F]/g, "");
	const bytes = new Uint8Array(limpio.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = Number.parseInt(limpio.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}
