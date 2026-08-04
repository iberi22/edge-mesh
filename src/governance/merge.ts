import type { ParPublico, PostQuantumIdentity } from "../identity/index.js";
import type { NodoId, PayloadVotacion } from "../types/index.js";
import { ESTADO_PROPUESTA, type Propuesta } from "./index.js";

// ─── ALIASES ───────────────────────────────────────────────────────────────

export type Proposal = Propuesta;
export type Vote = PayloadVotacion;

// ─── GOVERNANCE EVENT ──────────────────────────────────────────────────────

export interface GovernanceEvent {
	readonly id: string;
	readonly tipo: string; // "propuestaCreada", "votoRecibido", "propuestaResultado", "expulsion", etc.
	readonly timestamp: number;
	readonly payload: unknown;
}

// ─── GOVERNANCE SNAPSHOT ───────────────────────────────────────────────────

export interface GovernanceSnapshot {
	readonly propuestas: Proposal[];
	readonly timestamp: number;
	readonly firma?: Uint8Array;
	readonly publicNodeId?: NodoId;
}

// ─── GOVERNANCE MERGE INTERFACE ────────────────────────────────────────────

export interface GovernanceMerge {
	resolveProposalConflicts(
		local: Proposal[],
		remote: Proposal[],
	): Promise<Proposal[]>;
	resolveVoteConflicts(local: Vote[], remote: Vote[]): Promise<Vote[]>;
	detectGovernanceFork(
		localEvents: GovernanceEvent[],
		remoteEvents: GovernanceEvent[],
	): Promise<boolean>;
}

// ─── STABLE STRINGIFY ──────────────────────────────────────────────────────

export function stableStringify(val: unknown): string {
	if (typeof val !== "object" || val === null) {
		return JSON.stringify(val);
	}
	if (Array.isArray(val)) {
		return `[${val.map(stableStringify).join(",")}]`;
	}
	const keys = Object.keys(val).sort();
	const parts = keys.map(
		(k) =>
			`${JSON.stringify(k)}:${stableStringify((val as Record<string, unknown>)[k])}`,
	);
	return `{${parts.join(",")}}`;
}

// ─── SIGN & VERIFY SNAPSHOT ───────────────────────────────────────────────

export async function signGovernanceSnapshot(
	snapshot: Omit<GovernanceSnapshot, "firma" | "publicNodeId">,
	identity: PostQuantumIdentity,
): Promise<GovernanceSnapshot> {
	const encoder = new TextEncoder();
	const serialized = encoder.encode(stableStringify(snapshot));
	const firma = await identity.firmar(serialized);
	return {
		...snapshot,
		firma,
		publicNodeId: identity.nodoId,
	};
}

export async function verifyGovernanceSnapshot(
	snapshot: GovernanceSnapshot,
	parPublico: ParPublico,
	identity: PostQuantumIdentity,
): Promise<boolean> {
	if (!snapshot.firma) return false;
	const { firma, publicNodeId, ...rest } = snapshot;
	const encoder = new TextEncoder();
	const serialized = encoder.encode(stableStringify(rest));
	return identity.verificar(serialized, firma, parPublico);
}

// ─── GOVERNANCE MERGER IMPLEMENTATION ─────────────────────────────────────

export class GovernanceMerger implements GovernanceMerge {
	async resolveProposalConflicts(
		local: Proposal[],
		remote: Proposal[],
	): Promise<Proposal[]> {
		const merged: Proposal[] = [];
		const remoteMap = new Map<string, Proposal>();
		for (const p of remote) {
			remoteMap.set(p.id, p);
		}

		for (const localProp of local) {
			const remoteProp = remoteMap.get(localProp.id);
			if (!remoteProp) {
				// Propuestas con id único: ambas sobreviven
				merged.push({ ...localProp });
			} else {
				// Propuestas con mismo id
				if (localProp.tipo === "expulsion" || remoteProp.tipo === "expulsion") {
					// Expulsiones: la expulsión más reciente gana (por timestamp)
					if (localProp.timestamp >= remoteProp.timestamp) {
						merged.push({ ...localProp });
					} else {
						merged.push({ ...remoteProp });
					}
				} else if (localProp.estado !== remoteProp.estado) {
					// Propuestas con mismo id pero diferente resultado: se re-votan con todos los peers
					merged.push({
						...localProp,
						estado: ESTADO_PROPUESTA.ABIERTA,
						votos: [], // Reset votos to re-vote
						expiracion: Date.now() + 30_000, // Extend expiration
					});
				} else {
					// Same result: no conflict, merge votes cleanly
					const allVotes = [...localProp.votos];
					for (const rv of remoteProp.votos) {
						if (!allVotes.some((lv) => lv.nodoId === rv.nodoId)) {
							allVotes.push(rv);
						}
					}
					merged.push({
						...localProp,
						votos: allVotes,
					});
				}
				remoteMap.delete(localProp.id);
			}
		}

		// Add remaining remote proposals (id único)
		for (const remoteProp of remoteMap.values()) {
			merged.push({ ...remoteProp });
		}

		return merged;
	}

	async resolveVoteConflicts(local: Vote[], remote: Vote[]): Promise<Vote[]> {
		const merged: Vote[] = [...local];
		for (const rVote of remote) {
			const exists = merged.find(
				(lVote) =>
					lVote.propuesta === rVote.propuesta && lVote.nodoId === rVote.nodoId,
			);
			if (!exists) {
				merged.push(rVote);
			} else {
				// If they exist but differ, we can deterministically keep the local one.
				// (No changes needed since it's already in merged)
			}
		}
		return merged;
	}

	async detectGovernanceFork(
		localEvents: GovernanceEvent[],
		remoteEvents: GovernanceEvent[],
	): Promise<boolean> {
		const localProps = new Map<string, Proposal>();
		const remoteProps = new Map<string, Proposal>();

		const localExpulsions = new Map<string, GovernanceEvent>();
		const remoteExpulsions = new Map<string, GovernanceEvent>();

		// Helper to extract proposal
		const extractProp = (ev: GovernanceEvent): Proposal | null => {
			const payload = ev.payload as Record<string, unknown> | null;
			if (payload && typeof payload === "object") {
				if (payload.propuesta && typeof payload.propuesta === "object") {
					return payload.propuesta as Proposal;
				}
			}
			return null;
		};

		for (const ev of localEvents) {
			const prop = extractProp(ev);
			if (prop?.id) {
				localProps.set(prop.id, prop);
			}
			if (ev.tipo === "expulsion") {
				const pp = ev.payload as Record<string, unknown> | null;
				const target = (pp?.target ?? pp?.nodoId ?? ev.id) as string;
				localExpulsions.set(target, ev);
			}
		}

		for (const ev of remoteEvents) {
			const prop = extractProp(ev);
			if (prop?.id) {
				remoteProps.set(prop.id, prop);
			}
			if (ev.tipo === "expulsion") {
				const pp = ev.payload as Record<string, unknown> | null;
				const target = (pp?.target ?? pp?.nodoId ?? ev.id) as string;
				remoteExpulsions.set(target, ev);
			}
		}

		// Check proposal conflicts
		for (const [id, localProp] of localProps) {
			const remoteProp = remoteProps.get(id);
			if (remoteProp) {
				if (localProp.estado !== remoteProp.estado) {
					return true;
				}
				// Check if vote sets are different
				if (
					stableStringify(localProp.votos) !== stableStringify(remoteProp.votos)
				) {
					return true;
				}
			}
		}

		// Check expulsion conflicts
		for (const [target, localExp] of localExpulsions) {
			const remoteExp = remoteExpulsions.get(target);
			if (remoteExp) {
				if (
					localExp.timestamp !== remoteExp.timestamp ||
					(localExp.payload as Record<string, unknown>)?.resultado !==
						(remoteExp.payload as Record<string, unknown>)?.resultado
				) {
					return true;
				}
			}
		}

		return false;
	}
}
