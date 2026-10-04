export interface Env {
  MESH_ROOM: DurableObjectNamespace;
  MESH_ENTITLEMENT_SECRET: string;
  ALLOWED_ORIGINS: string;
  /** Optional overrides (tests). */
  RATE_BURST?: string;
  RATE_PER_SEC?: string;
}

export const RID_RE = /^[A-Za-z0-9_-]{22}$/;
export const MAX_PEERS = 16;
export const MAX_MESSAGE_BYTES = 16 * 1024;
export const PAIR_MAX_PEERS = 2;
export const PAIR_MAX_MESSAGES = 10;
export const PAIR_LIFETIME_MS = 5 * 60 * 1000;
export const DEFAULT_BURST = 30;
export const DEFAULT_PER_SEC = 10;

export const isPairRid = (rid: string): boolean => rid.startsWith('p_');

export type ClientMsg =
  | { type: 'join'; rid: string; from: string; token?: string; pairProof?: string }
  | { type: 'signal'; rid: string; from: string; to: string; payload: string }
  | { type: 'leave'; rid: string; from: string };

export type ServerMsg =
  | { type: 'peers'; peers: string[] }
  | { type: 'peer-joined' | 'peer-left'; id: string }
  | { type: 'signal'; from: string; payload: string }
  | { type: 'error'; code: string };

/** Persisted via ws.serializeAttachment (survives hibernation, not billed as storage). */
export interface Attachment {
  rid: string;
  /** deviceId once joined */
  id?: string;
  /** room creation time as seen by this socket (pairing rooms lifetime) */
  t0: number;
  /** signal messages sent by this socket (pairing rooms message budget) */
  sent: number;
}
