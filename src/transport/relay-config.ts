export interface ParsedRelayConfig {
	host: string;
	port: number;
	path: string;
	secure: boolean;
	rawUrl: string;
}

export function resolveRelayUrl(optionsUrl?: string): string {
	if (optionsUrl && optionsUrl.trim().length > 0) {
		return optionsUrl.trim();
	}

	if (typeof process !== "undefined" && process.env) {
		if (process.env.SWAL_RELAY_URL && process.env.SWAL_RELAY_URL.trim().length > 0) {
			return process.env.SWAL_RELAY_URL.trim();
		}

		const host = process.env.SWAL_RELAY_HOST || "localhost";
		const portStr = process.env.SWAL_RELAY_PORT || "9000";
		const port = parseInt(portStr, 10);
		const validPort = !isNaN(port) && port > 0 ? port : 9000;
		return `http://${host}:${validPort}/`;
	}

	return "http://localhost:9000/";
}

export function parseRelayUrl(relayUrl: string): ParsedRelayConfig {
	try {
		const url = new URL(relayUrl);
		const secure = url.protocol === "https:" || url.protocol === "wss:";
		const defaultPort = secure ? 443 : 80;
		const port = url.port ? parseInt(url.port, 10) : defaultPort;
		const path = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;

		return {
			host: url.hostname,
			port,
			path,
			secure,
			rawUrl: relayUrl,
		};
	} catch {
		// Fallback parse if URL parsing fails
		return {
			host: "localhost",
			port: 9000,
			path: "/",
			secure: false,
			rawUrl: relayUrl,
		};
	}
}

export function getRelayConfig(optionsUrl?: string): ParsedRelayConfig {
	const resolved = resolveRelayUrl(optionsUrl);
	return parseRelayUrl(resolved);
}
