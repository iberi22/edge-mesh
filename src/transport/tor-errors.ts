export class TorUnavailableError extends Error {
	readonly name = "TorUnavailableError";

	constructor(
		public readonly host: string,
		public readonly port: number,
		public readonly cause?: unknown,
	) {
		super(`Tor SOCKS proxy not reachable at ${host}:${port}`);
		// Set prototype explicitly if targeting ES5 or lower, though usually vitest/node is ES2022+
		Object.setPrototypeOf(this, TorUnavailableError.prototype);
	}
}
