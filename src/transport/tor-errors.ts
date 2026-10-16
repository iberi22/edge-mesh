export class TorUnavailableError extends Error {
	public readonly name = "TorUnavailableError";
	public readonly host: string;
	public readonly port: number;

	constructor(
		host: string,
		port: number,
		public readonly cause?: Error | unknown,
	) {
		super(`Tor SOCKS proxy not reachable at ${host}:${port}`);
		this.host = host;
		this.port = port;
	}
}
