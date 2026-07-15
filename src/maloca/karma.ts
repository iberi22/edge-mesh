import type { NodoId } from "../types/index.js";
import type { OpLog } from "../op-log/index.js";
import type { PostQuantumIdentity } from "../identity/index.js";

export interface Karma {
  total: number;
  historial: TransaccionKarma[];
  pesos: Record<string, number>;
  ultimaActualizacion: number;
  decay: number;
}

export interface TransaccionKarma {
  id: string;
  tipo: string;
  proyecto: string;
  delta: number;
  razon: string;
  emitidoPor: NodoId;
  firma: Uint8Array;
  timestamp: number;
  nodeId: NodoId;
}

export class KarmaManager {
  private histories: Map<string, TransaccionKarma[]> = new Map();
  private opLog: OpLog;
  private identity: PostQuantumIdentity;
  private decayRate: number = 0; // Decay rate per day, for example

  constructor(opLog: OpLog, identity: PostQuantumIdentity) {
    this.opLog = opLog;
    this.identity = identity;

    this.opLog.on("operacionAgregada", (ev) => {
      const { operacion } = ev.detail;
      if (operacion.tipo === "karma_tx") {
        const tx = operacion.datos as TransaccionKarma;
        this.applyTransaction(tx);
      }
    });
  }

  async emit(tx: Omit<TransaccionKarma, "firma" | "timestamp" | "id">): Promise<void> {
    const timestamp = Date.now();
    const id = `${tx.nodeId}-${timestamp}-${Math.random().toString(36).substr(2, 9)}`;

    const txToSign = this.getStableTx(tx, id, timestamp);
    const dataToSign = new TextEncoder().encode(JSON.stringify(txToSign));
    const firma = await this.identity.firmar(dataToSign);

    const fullTx: TransaccionKarma = {
      ...tx,
      id,
      timestamp,
      firma,
    };

    await this.opLog.append("karma_tx", fullTx, this.identity.nodoId);
    this.applyTransaction(fullTx);
  }

  private applyTransaction(tx: TransaccionKarma): void {
    const history = this.histories.get(tx.nodeId) || [];
    if (!history.some(h => h.id === tx.id)) {
      history.push(tx);
      history.sort((a, b) => a.timestamp - b.timestamp);
      this.histories.set(tx.nodeId, history);
    }
  }

  getScore(nodeId: NodoId, proyecto?: string): number {
    const history = this.histories.get(nodeId) || [];
    const now = Date.now();

    return history
      .filter((tx) => !proyecto || tx.proyecto === proyecto)
      .reduce((acc, tx) => {
        const ageMs = now - tx.timestamp;
        const ageDays = ageMs / (1000 * 60 * 60 * 24);
        const decayedDelta = tx.delta * Math.pow(1 - this.decayRate, ageDays);
        return acc + decayedDelta;
      }, 0);
  }

  getHistory(nodeId: NodoId): TransaccionKarma[] {
    return this.histories.get(nodeId) || [];
  }

  setDecayRate(rate: number): void {
    this.decayRate = rate;
  }

  async verifySignature(tx: TransaccionKarma, publicKey: Uint8Array): Promise<boolean> {
    const txToVerify = this.getStableTx(tx, tx.id, tx.timestamp);
    const dataToVerify = new TextEncoder().encode(JSON.stringify(txToVerify));
    return this.identity.verificar(dataToVerify, tx.firma, publicKey);
  }

  private getStableTx(tx: any, id: string, timestamp: number) {
    return {
      nodeId: tx.nodeId,
      tipo: tx.tipo,
      proyecto: tx.proyecto,
      delta: tx.delta,
      razon: tx.razon,
      emitidoPor: tx.emitidoPor,
      id,
      timestamp
    };
  }

  async loadFromOpLog(): Promise<void> {
    const ops = await this.opLog.obtenerTodas();
    for (const op of ops) {
      if (op.tipo === "karma_tx") {
        const tx = op.datos as TransaccionKarma;
        this.applyTransaction(tx);
      }
    }
  }
}
