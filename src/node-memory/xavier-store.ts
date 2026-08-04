import type { MemoryRecord, NodeMemoryOptions } from "./types.js";

export class XavierStore {
	private readonly xavierUrl: string;
	private readonly xavierToken?: string;
	private readonly appId: string;
	private readonly instanceId: string;

	constructor(opts: NodeMemoryOptions) {
		this.appId = opts.appId;
		this.instanceId = opts.instanceId;
		this.xavierUrl = opts.xavierUrl ?? "http://127.0.0.1:8006";
		this.xavierToken = opts.xavierToken;
	}

	private getHeaders(): Record<string, string> {
		const headers: Record<string, string> = {
			"Content-Type": "application/json",
		};
		if (this.xavierToken) {
			headers["X-Xavier-Token"] = this.xavierToken;
		}
		return headers;
	}

	async postRecord(record: MemoryRecord): Promise<boolean> {
		let baseUrl = this.xavierUrl;
		if (!baseUrl.endsWith("/")) {
			baseUrl += "/";
		}
		const url = `${baseUrl}app/${this.appId}/instance/${this.instanceId}`;

		try {
			const res = await globalThis.fetch(url, {
				method: "POST",
				headers: this.getHeaders(),
				body: JSON.stringify(record),
			});

			return res.ok;
		} catch (e) {
			console.warn(
				`[XavierStore] Failed to post record to Xavier at ${url}`,
				e,
			);
			return false;
		}
	}

	async loadRecords(
		path: string,
		query: string,
		limit?: number,
	): Promise<MemoryRecord[]> {
		let baseUrl = this.xavierUrl;
		if (!baseUrl.endsWith("/")) {
			baseUrl += "/";
		}

		const fullUrl =
			path.startsWith("http://") || path.startsWith("https://")
				? path
				: `${baseUrl}${path.startsWith("/") ? path.slice(1) : path}`;

		const urlObj = new URL(fullUrl);
		if (query) {
			urlObj.searchParams.set("query", query);
		}
		if (limit !== undefined) {
			urlObj.searchParams.set("limit", limit.toString());
		}

		try {
			const res = await globalThis.fetch(urlObj.toString(), {
				method: "GET",
				headers: this.getHeaders(),
			});

			if (!res.ok) {
				return [];
			}

			const data = await res.json();
			if (Array.isArray(data)) {
				return data as MemoryRecord[];
			}
			return [];
		} catch (e) {
			console.warn(
				`[XavierStore] Failed to load records from Xavier at ${urlObj.toString()}`,
				e,
			);
			return [];
		}
	}
}
