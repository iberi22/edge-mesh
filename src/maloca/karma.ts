import type { YjsAdapter } from "../edge-mesh.js";
import type { PostQuantumIdentity } from "../identity/index.js";
import type { NodoId, ParPublico } from "../types/index.js";
import type { Karma, TransaccionKarma } from "./types.js";
import type * as Y from "yjs";

/**
 * Deterministically stringifies an object for signing.
 */
function canonicalStringify(obj: any): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => `${JSON.stringify(k)}:${canonicalStringify(obj[k])}`).join(",") + "}";
}

export class KarmaManager {
  private readonly yjs: YjsAdapter;
  private readonly identity: PostQuantumIdentity;
  private readonly karmaMap: Y.Map<Karma>;

  constructor(yjs: YjsAdapter, identity: PostQuantumIdentity) {
    this.yjs = yjs;
    this.identity = identity;
    this.karmaMap = this.yjs.getMap("maloca:karma") as Y.Map<Karma>;
  }

  async emit(txData: Omit<TransaccionKarma, "id" | "timestamp" | "firma">): Promise<TransaccionKarma> {
    const timestamp = Date.now();
    const id = `${txData.emisor}:${timestamp}:${Math.random().toString(36).substring(2, 9)}`;

    const payloadData = { ...txData, id, timestamp };
    const payload = canonicalStringify(payloadData);
    const firma = await this.identity.firmar(new TextEncoder().encode(payload));

    const tx: TransaccionKarma = {
      ...txData,
      id,
      timestamp,
      firma,
    };

    this.saveTransaction(tx);
    return tx;
  }

  private saveTransaction(tx: TransaccionKarma): void {
    const target = tx.sujeto;

    const currentKarma = this.karmaMap.get(target) || {
      total: 0,
      historial: [],
      pesosPorProyecto: {},
      ultimoDecay: Date.now(),
    };

    const updatedKarma: Karma = {
      ...currentKarma,
      total: currentKarma.total + tx.delta,
      historial: [...currentKarma.historial, tx],
      pesosPorProyecto: {
        ...currentKarma.pesosPorProyecto,
        [tx.proyecto]: (currentKarma.pesosPorProyecto[tx.proyecto] || 0) + tx.delta,
      },
    };

    this.karmaMap.set(target, updatedKarma);
  }

  getScore(nodeId: NodoId): number {
    return this.karmaMap.get(nodeId)?.total || 0;
  }

  getHistory(nodeId: NodoId): readonly TransaccionKarma[] {
    return this.karmaMap.get(nodeId)?.historial || [];
  }

  applyDecay(nodeId: NodoId, factor: number = 0.95): void {
    const current = this.karmaMap.get(nodeId);
    if (!current) return;

    const updated: Karma = {
      ...current,
      total: current.total * factor,
      ultimoDecay: Date.now(),
    };
    this.karmaMap.set(nodeId, updated);
  }

  async verify(tx: TransaccionKarma, publicKey: ParPublico): Promise<boolean> {
    const { firma, ...rest } = tx;
    const payload = canonicalStringify(rest);
    return this.identity.verificar(new TextEncoder().encode(payload), firma, publicKey);
  }
}
