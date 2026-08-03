import type { IStorage } from "../storage/index.js";
import type { Mensaje } from "./index.js";

export type ChatMessage = Mensaje;

export interface OfflineMessageQueue {
	enqueue(channelId: string, message: ChatMessage): Promise<void>;
	dequeue(channelId: string): Promise<ChatMessage | null>;
	peek(channelId: string): Promise<ChatMessage[]>;
	flush(channelId: string): Promise<number>; // returns count flushed
	size(channelId: string): Promise<number>;
}

export class MeshPresence {
	private static readonly onlineNodes = new Set<string>();

	static isOnline(peerId: string): boolean {
		return MeshPresence.onlineNodes.has(peerId);
	}

	static setOnline(peerId: string, online: boolean): void {
		if (online) {
			MeshPresence.onlineNodes.add(peerId);
		} else {
			MeshPresence.onlineNodes.delete(peerId);
		}
	}

	static clear(): void {
		MeshPresence.onlineNodes.clear();
	}
}

export class PersistentOfflineQueue implements OfflineMessageQueue {
	private readonly storage: IStorage;
	private readonly maxCapacity: number;
	private readonly senders: Map<string, (msg: ChatMessage) => Promise<void>> =
		new Map();
	private readonly channelPeers: Map<string, string> = new Map(); // channelId -> peerId

	constructor(storage: IStorage, maxCapacity = 1000) {
		this.storage = storage;
		this.maxCapacity = maxCapacity;
	}

	private obtenerKey(channelId: string): string {
		return `offline:queue:${channelId}`;
	}

	async enqueue(channelId: string, message: ChatMessage): Promise<void> {
		const key = this.obtenerKey(channelId);
		const entry = await this.storage.get<ChatMessage[]>(key);
		const queue: ChatMessage[] = entry ? entry.valor || [] : [];

		if (queue.length >= this.maxCapacity) {
			console.warn(
				`[OfflineQueue] Límite de tamaño alcanzado para el canal ${channelId}. Descartando el mensaje más viejo.`,
			);
			queue.shift(); // FIFO/LRU: discard oldest
		}

		queue.push(message);
		await this.storage.set(key, queue);
	}

	async dequeue(channelId: string): Promise<ChatMessage | null> {
		const key = this.obtenerKey(channelId);
		const entry = await this.storage.get<ChatMessage[]>(key);
		const queue: ChatMessage[] = entry ? entry.valor || [] : [];

		if (queue.length === 0) return null;

		const message = queue.shift()!;
		await this.storage.set(key, queue);
		return message;
	}

	async peek(channelId: string): Promise<ChatMessage[]> {
		const key = this.obtenerKey(channelId);
		const entry = await this.storage.get<ChatMessage[]>(key);
		return entry ? entry.valor || [] : [];
	}

	async size(channelId: string): Promise<number> {
		const key = this.obtenerKey(channelId);
		const entry = await this.storage.get<ChatMessage[]>(key);
		return entry ? (entry.valor || []).length : 0;
	}

	async flush(channelId: string): Promise<number> {
		const key = this.obtenerKey(channelId);
		const entry = await this.storage.get<ChatMessage[]>(key);
		if (!entry || !entry.valor || entry.valor.length === 0) return 0;

		const queue = entry.valor;
		const count = queue.length;

		const sender = this.senders.get(channelId);
		if (sender) {
			for (const msg of queue) {
				await sender(msg);
			}
		}

		await this.storage.set(key, []);
		return count;
	}

	registerChannel(
		channelId: string,
		peerId: string,
		sender: (msg: ChatMessage) => Promise<void>,
	): void {
		this.channelPeers.set(channelId, peerId);
		this.senders.set(channelId, sender);
	}

	async handlePeerReconnect(peerId: string): Promise<void> {
		// Flush all channels registered to this peerId
		for (const [channelId, associatedPeerId] of this.channelPeers.entries()) {
			if (associatedPeerId === peerId) {
				await this.flush(channelId);
			}
		}
		// Also support flushing if the channel name itself is the peerId or private:peerId
		await this.flush(peerId);
		await this.flush(`private:${peerId}`);
	}
}
