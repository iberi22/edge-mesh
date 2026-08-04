/// <reference types="node" />
import type * as Y from "yjs";
import type { EdgeMesh } from "../edge-mesh.js";

export type MemoryKind = "ydoc" | "semantic" | "agent" | string;

export interface NodeMemoryOptions {
	appId: string;
	instanceId: string;
	xavierUrl?: string; // default http://127.0.0.1:8006
	xavierToken?: string; // opcional (header X-Xavier-Token)
	ttlMs?: number; // default 30 días
	mesh?: EdgeMesh; // opcional — wire swal/{appId}/{instanceId}
}

export interface MemoryRecord {
	id: string; // unique ID
	appId: string;
	instanceId: string;
	kind: MemoryKind;
	content: string; // base64/hex of Y.Doc update or raw semantic text
	contentHash: string; // dedup
	timestamp: number;
	title?: string;
	synced: boolean;
}

export interface MemoryEvent {
	type: "saved" | "synced" | "loaded";
	record: MemoryRecord;
}

export interface NodeMemory {
	persistYDoc(doc: Y.Doc, kind: MemoryKind): Promise<void>;
	loadFromXavier(
		path: string,
		query: string,
		limit?: number,
	): Promise<MemoryRecord[]>;
	saveMemory(content: string, title: string, kind: MemoryKind): Promise<void>;
	subscribeChanges(cb: (ev: MemoryEvent) => void): () => void;
	flushOffline(): Promise<number>; // devuelve cuántos registros flush-eó
}
