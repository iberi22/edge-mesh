// Storage contracts for web/oplog + in-memory implementations. An IndexedDB implementation (T2, Fize `fize-mesh`)
// only has to satisfy these interfaces: ops keyed by [author, seq], quarantine keyed by `key`.
import type { QuarantineEntry, StoredOp } from "./types.js";

export interface OpStore {
	/** last stored op of `author` (highest seq) */
	head(author: string): Promise<StoredOp | undefined>;
	get(author: string, seq: number): Promise<StoredOp | undefined>;
	/** called only with seq == head.seq + 1 (validated by OpLog) */
	append(entry: StoredOp): Promise<void>;
	/** inclusive range, ascending; missing (pruned) seqs are skipped */
	range(author: string, from: number, to: number): Promise<StoredOp[]>;
	/** author -> head seq */
	heads(): Promise<Record<string, number>>;
	all(): Promise<StoredOp[]>;
	/** optional compaction: drop ops of `author` with seq < beforeSeq (keep the head) */
	prune?(author: string, beforeSeq: number): Promise<void>;
}

export interface QuarantineStore {
	put(entry: QuarantineEntry): Promise<void>;
	delete(key: string): Promise<void>;
	list(): Promise<QuarantineEntry[]>;
}

export class MemoryOpStore implements OpStore {
	private readonly logs = new Map<string, StoredOp[]>(); // index = seq - base
	private readonly base = new Map<string, number>(); // first seq kept per author

	async head(author: string) {
		const l = this.logs.get(author);
		return l?.[l.length - 1];
	}
	async get(author: string, seq: number) {
		const l = this.logs.get(author);
		if (!l?.length) return undefined;
		return l[seq - (this.base.get(author) ?? 1)];
	}
	async append(entry: StoredOp) {
		const a = entry.op.author;
		let l = this.logs.get(a);
		if (!l) {
			l = [];
			this.logs.set(a, l);
			this.base.set(a, entry.op.seq);
		}
		const expected = (this.base.get(a) ?? 1) + l.length;
		if (entry.op.seq !== expected)
			throw new Error(
				`non-contiguous append ${a}#${entry.op.seq} (expected ${expected})`,
			);
		l.push(entry);
	}
	async range(author: string, from: number, to: number) {
		const l = this.logs.get(author) ?? [];
		const b = this.base.get(author) ?? 1;
		return l.slice(Math.max(0, from - b), Math.max(0, to - b + 1));
	}
	async heads() {
		const out: Record<string, number> = {};
		for (const [a, l] of this.logs) {
			const h = l[l.length - 1];
			if (h) out[a] = h.op.seq;
		}
		return out;
	}
	async all() {
		return [...this.logs.values()].flat();
	}
	async prune(author: string, beforeSeq: number) {
		const l = this.logs.get(author);
		if (!l?.length) return;
		const b = this.base.get(author) ?? 1;
		const drop = Math.min(Math.max(0, beforeSeq - b), l.length - 1);
		l.splice(0, drop);
		this.base.set(author, b + drop);
	}
}

export class MemoryQuarantineStore implements QuarantineStore {
	private readonly m = new Map<string, QuarantineEntry>();
	constructor(private readonly maxRejected = 5000) {}
	async put(e: QuarantineEntry) {
		this.m.delete(e.key);
		this.m.set(e.key, e);
		if (e.kind !== "rejected") return;
		let rejected = 0;
		for (const x of this.m.values()) if (x.kind === "rejected") rejected++;
		for (const [k, x] of this.m) {
			if (rejected <= this.maxRejected) break;
			if (x.kind === "rejected") {
				this.m.delete(k);
				rejected--;
			}
		}
	}
	async delete(key: string) {
		this.m.delete(key);
	}
	async list() {
		return [...this.m.values()];
	}
}
