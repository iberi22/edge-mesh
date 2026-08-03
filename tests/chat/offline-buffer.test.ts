import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	ChatChannel,
	type ChatMessage,
	MeshPresence,
	PersistentOfflineQueue,
	TIPO_CANAL,
} from "../../src/chat/index.js";
import { YjsAdapter } from "../../src/edge-mesh.js";
import { PresenceManager } from "../../src/presence/index.js";
import { InMemoryStorage } from "../../src/storage/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("Offline Message Buffer Tests", () => {
	let storage: InMemoryStorage;
	let presence: PresenceManager;
	let yjsAdapter: YjsAdapter;
	const localNodeId = "local-node" as NodoId;
	const remotePeerId = "remote-peer";
	const channelId = "private:remote-peer";

	beforeEach(() => {
		storage = new InMemoryStorage();
		presence = new PresenceManager();
		yjsAdapter = new YjsAdapter();
		MeshPresence.clear();
	});

	afterEach(() => {
		presence.detener();
		yjsAdapter.destroy();
		MeshPresence.clear();
	});

	it("1. should enqueue and dequeue messages correctly maintaining strict FIFO order", async () => {
		const queue = new PersistentOfflineQueue(storage);

		const msg1: ChatMessage = {
			id: "msg-1",
			sender: localNodeId,
			text: "First message",
			timestamp: Date.now(),
			type: "texto",
			canal: channelId,
		};

		const msg2: ChatMessage = {
			id: "msg-2",
			sender: localNodeId,
			text: "Second message",
			timestamp: Date.now() + 1,
			type: "texto",
			canal: channelId,
		};

		await queue.enqueue(channelId, msg1);
		await queue.enqueue(channelId, msg2);

		expect(await queue.size(channelId)).toBe(2);

		const firstOut = await queue.dequeue(channelId);
		expect(firstOut).toEqual(msg1);

		const secondOut = await queue.dequeue(channelId);
		expect(secondOut).toEqual(msg2);

		expect(await queue.size(channelId)).toBe(0);
	});

	it("2. should peek and check size without removing messages from queue", async () => {
		const queue = new PersistentOfflineQueue(storage);
		const msg: ChatMessage = {
			id: "msg-1",
			sender: localNodeId,
			text: "Hello",
			timestamp: Date.now(),
			type: "texto",
			canal: channelId,
		};

		await queue.enqueue(channelId, msg);

		const peeked = await queue.peek(channelId);
		expect(peeked).toHaveLength(1);
		expect(peeked[0]).toEqual(msg);

		expect(await queue.size(channelId)).toBe(1);

		const dequeued = await queue.dequeue(channelId);
		expect(dequeued).toEqual(msg);
	});

	it("3. should enforce size limit and discard oldest messages with a warning", async () => {
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const queue = new PersistentOfflineQueue(storage, 3); // Max capacity of 3

		const createMsg = (id: string, text: string): ChatMessage => ({
			id,
			sender: localNodeId,
			text,
			timestamp: Date.now(),
			type: "texto",
			canal: channelId,
		});

		await queue.enqueue(channelId, createMsg("1", "Msg 1"));
		await queue.enqueue(channelId, createMsg("2", "Msg 2"));
		await queue.enqueue(channelId, createMsg("3", "Msg 3"));

		expect(await queue.size(channelId)).toBe(3);

		// Enqueue 4th message - should trigger discard of oldest ("Msg 1")
		await queue.enqueue(channelId, createMsg("4", "Msg 4"));

		expect(warnSpy).toHaveBeenCalled();
		expect(await queue.size(channelId)).toBe(3);

		const firstOut = await queue.dequeue(channelId);
		expect(firstOut?.text).toBe("Msg 2"); // Msg 1 was discarded

		warnSpy.mockRestore();
	});

	it("4. should flush all messages correctly calling registered senders", async () => {
		const queue = new PersistentOfflineQueue(storage);
		const sentMessages: ChatMessage[] = [];
		const senderSpy = vi.fn(async (msg: ChatMessage) => {
			sentMessages.push(msg);
		});

		queue.registerChannel(channelId, remotePeerId, senderSpy);

		const msg1: ChatMessage = {
			id: "msg-1",
			sender: localNodeId,
			text: "Msg 1",
			timestamp: Date.now(),
			type: "texto",
			canal: channelId,
		};

		await queue.enqueue(channelId, msg1);
		const count = await queue.flush(channelId);

		expect(count).toBe(1);
		expect(senderSpy).toHaveBeenCalledWith(msg1);
		expect(sentMessages).toContain(msg1);
		expect(await queue.size(channelId)).toBe(0);
	});

	it("5. should automatically enqueue messages when peer is offline", async () => {
		const queue = new PersistentOfflineQueue(storage);
		const channel = new ChatChannel(
			localNodeId,
			channelId,
			yjsAdapter,
			TIPO_CANAL.PRIVADO,
			queue,
		);

		// peer is offline by default (MeshPresence.isOnline(remotePeerId) is false)
		expect(MeshPresence.isOnline(remotePeerId)).toBe(false);

		const msgId = await channel.sendMessage("Hello offline peer");

		// Message should be enqueued instead of sent directly to YJS Messages array
		expect(await queue.size(channelId)).toBe(1);
		const peeked = await queue.peek(channelId);
		expect(peeked[0].id).toBe(msgId);
		expect(peeked[0].text).toBe("Hello offline peer");

		// Historial from Yjs should be empty
		const yjsMessages = await channel.obtenerHistorial();
		expect(yjsMessages).toHaveLength(0);
	});

	it("6. should automatically flush queue when peer reconnects", async () => {
		const queue = new PersistentOfflineQueue(storage);
		const channel = new ChatChannel(
			localNodeId,
			channelId,
			yjsAdapter,
			TIPO_CANAL.PRIVADO,
			queue,
		);

		// Hook up the presence manager and offline queue together
		presence.onOnline(remotePeerId, async (pId) => {
			await queue.handlePeerReconnect(pId);
		});

		// Send message while offline
		await channel.sendMessage("Msg offline 1");
		await channel.sendMessage("Msg offline 2");

		expect(await queue.size(channelId)).toBe(2);
		expect((await channel.obtenerHistorial()).length).toBe(0);

		// Simulate peer coming online via presence.onOnline(remotePeerId)
		presence.onOnline(remotePeerId);

		// Wait for any async flush tasks to settle
		await new Promise((resolve) => setTimeout(resolve, 50));

		// Queue should be empty and messages successfully synced/pushed into Yjs
		expect(await queue.size(channelId)).toBe(0);
		const history = await channel.obtenerHistorial();
		expect(history).toHaveLength(2);
		expect(history[0].text).toBe("Msg offline 1");
		expect(history[1].text).toBe("Msg offline 2");
	});

	it("7. should send messages normally via Yjs when peer is online", async () => {
		const queue = new PersistentOfflineQueue(storage);
		const channel = new ChatChannel(
			localNodeId,
			channelId,
			yjsAdapter,
			TIPO_CANAL.PRIVADO,
			queue,
		);

		// Set peer as online
		MeshPresence.setOnline(remotePeerId, true);
		expect(MeshPresence.isOnline(remotePeerId)).toBe(true);

		const msgId = await channel.sendMessage("Hello online peer");

		// No messages in offline queue
		expect(await queue.size(channelId)).toBe(0);

		// Messages immediately in Yjs history
		const history = await channel.obtenerHistorial();
		expect(history).toHaveLength(1);
		expect(history[0].id).toBe(msgId);
		expect(history[0].text).toBe("Hello online peer");
	});
});
