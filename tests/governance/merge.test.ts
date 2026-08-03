import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createGovernanceManager,
	ESTADO_PROPUESTA,
	type GovernanceManager,
	GovernanceMerger,
	type Proposal,
	type Vote,
	type GovernanceEvent,
	signGovernanceSnapshot,
	verifyGovernanceSnapshot,
} from "../../src/governance/index.js";
import { createPostQuantumIdentity } from "../../src/identity/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("Governance Merger & offline-partition Merge Protocol", () => {
	let merger: GovernanceMerger;
	let manager: GovernanceManager;

	beforeEach(() => {
		vi.useFakeTimers();
		merger = new GovernanceMerger();
		manager = createGovernanceManager();
	});

	afterEach(() => {
		manager.destruir();
		vi.useRealTimers();
	});

	it("1. Merge de propuestas independientes", async () => {
		const localProps: Proposal[] = [
			{
				id: "prop1",
				tipo: "upgrade",
				proponente: "node1" as NodoId,
				datos: {},
				timestamp: 1000,
				expiracion: 5000,
				votos: [
					{
						propuesta: "prop1",
						voto: "a_favor",
						nodoId: "node1" as NodoId,
						peso: 1,
						justificacion: null,
					},
				],
				estado: ESTADO_PROPUESTA.APROBADA,
			},
		];

		const remoteProps: Proposal[] = [
			{
				id: "prop2",
				tipo: "param_change",
				proponente: "node2" as NodoId,
				datos: {},
				timestamp: 2000,
				expiracion: 6000,
				votos: [
					{
						propuesta: "prop2",
						voto: "a_favor",
						nodoId: "node2" as NodoId,
						peso: 1,
						justificacion: null,
					},
				],
				estado: ESTADO_PROPUESTA.ABIERTA,
			},
		];

		const merged = await merger.resolveProposalConflicts(
			localProps,
			remoteProps,
		);

		expect(merged.length).toBe(2);
		expect(merged.some((p) => p.id === "prop1")).toBe(true);
		expect(merged.some((p) => p.id === "prop2")).toBe(true);

		const p1 = merged.find((p) => p.id === "prop1")!;
		const p2 = merged.find((p) => p.id === "prop2")!;

		expect(p1.estado).toBe(ESTADO_PROPUESTA.APROBADA);
		expect(p2.estado).toBe(ESTADO_PROPUESTA.ABIERTA);
	});

	it("2. Conflicto de resultado de propuesta -> re-votación", async () => {
		const localProps: Proposal[] = [
			{
				id: "prop3",
				tipo: "upgrade",
				proponente: "node1" as NodoId,
				datos: {},
				timestamp: 1000,
				expiracion: 5000,
				votos: [
					{
						propuesta: "prop3",
						voto: "a_favor",
						nodoId: "node1" as NodoId,
						peso: 1,
						justificacion: null,
					},
				],
				estado: ESTADO_PROPUESTA.APROBADA,
			},
		];

		const remoteProps: Proposal[] = [
			{
				id: "prop3",
				tipo: "upgrade",
				proponente: "node1" as NodoId,
				datos: {},
				timestamp: 1000,
				expiracion: 5000,
				votos: [
					{
						propuesta: "prop3",
						voto: "en_contra",
						nodoId: "node2" as NodoId,
						peso: 1,
						justificacion: null,
					},
				],
				estado: ESTADO_PROPUESTA.RECHAZADA,
			},
		];

		const merged = await merger.resolveProposalConflicts(
			localProps,
			remoteProps,
		);

		expect(merged.length).toBe(1);
		const prop = merged[0];
		expect(prop.id).toBe("prop3");
		// Divergent results -> re-voted with all peers (status becomes ABIERTA, votes reset)
		expect(prop.estado).toBe(ESTADO_PROPUESTA.ABIERTA);
		expect(prop.votos.length).toBe(0);
	});

	it("3. Expulsión divergente -> gana la más reciente", async () => {
		const localProps: Proposal[] = [
			{
				id: "expulsar-peerA",
				tipo: "expulsion",
				proponente: "admin1" as NodoId,
				datos: { target: "peerA" },
				timestamp: 1000,
				expiracion: 5000,
				votos: [],
				estado: ESTADO_PROPUESTA.APROBADA,
			},
		];

		const remoteProps: Proposal[] = [
			{
				id: "expulsar-peerA",
				tipo: "expulsion",
				proponente: "admin1" as NodoId,
				datos: { target: "peerA" },
				timestamp: 2500, // remote is more recent
				expiracion: 5000,
				votos: [],
				estado: ESTADO_PROPUESTA.RECHAZADA,
			},
		];

		const merged = await merger.resolveProposalConflicts(
			localProps,
			remoteProps,
		);

		expect(merged.length).toBe(1);
		const prop = merged[0];
		expect(prop.id).toBe("expulsar-peerA");
		// Gana la más reciente (remote with status RECHAZADA)
		expect(prop.timestamp).toBe(2500);
		expect(prop.estado).toBe(ESTADO_PROPUESTA.RECHAZADA);
	});

	it("4. Snapshot firmado post-merge", async () => {
		const identity = createPostQuantumIdentity("nodeMaster" as NodoId);
		const publico = identity.exportarPublico();

		const propuestas: Proposal[] = [
			{
				id: "propMerged",
				tipo: "any",
				proponente: "node1" as NodoId,
				datos: {},
				timestamp: 1500,
				expiracion: 4500,
				votos: [],
				estado: ESTADO_PROPUESTA.APROBADA,
			},
		];

		const snapshotRaw = {
			propuestas,
			timestamp: Date.now(),
		};

		const signedSnapshot = await signGovernanceSnapshot(snapshotRaw, identity);

		expect(signedSnapshot.firma).toBeDefined();
		expect(signedSnapshot.firma instanceof Uint8Array).toBe(true);
		expect(signedSnapshot.publicNodeId).toBe("nodeMaster");

		const isValid = await verifyGovernanceSnapshot(
			signedSnapshot,
			publico,
			identity,
		);
		expect(isValid).toBe(true);

		// Tamper detection
		const tamperedSnapshot = {
			...signedSnapshot,
			timestamp: signedSnapshot.timestamp + 1,
		};
		const isTamperedValid = await verifyGovernanceSnapshot(
			tamperedSnapshot,
			publico,
			identity,
		);
		expect(isTamperedValid).toBe(false);
	});

	it("5. Detección de governance fork (detectGovernanceFork)", async () => {
		const localEvents: GovernanceEvent[] = [
			{
				id: "event1",
				tipo: "propuestaCreada",
				timestamp: 1000,
				payload: {
					propuesta: {
						id: "propFork",
						estado: ESTADO_PROPUESTA.APROBADA,
						votos: [],
					},
				},
			},
		];

		const remoteEventsNonConflicting: GovernanceEvent[] = [
			{
				id: "event1",
				tipo: "propuestaCreada",
				timestamp: 1000,
				payload: {
					propuesta: {
						id: "propFork",
						estado: ESTADO_PROPUESTA.APROBADA,
						votos: [],
					},
				},
			},
		];

		const remoteEventsConflicting: GovernanceEvent[] = [
			{
				id: "event1",
				tipo: "propuestaCreada",
				timestamp: 1000,
				payload: {
					propuesta: {
						id: "propFork",
						estado: ESTADO_PROPUESTA.RECHAZADA, // conflicting outcome
						votos: [],
					},
				},
			},
		];

		const isForkFalse = await merger.detectGovernanceFork(
			localEvents,
			remoteEventsNonConflicting,
		);
		expect(isForkFalse).toBe(false);

		const isForkTrue = await merger.detectGovernanceFork(
			localEvents,
			remoteEventsConflicting,
		);
		expect(isForkTrue).toBe(true);
	});

	it("6. Integración con GovernanceManager (importarPropuestas)", async () => {
		const propsToImport: Proposal[] = [
			{
				id: "importedProp1",
				tipo: "any",
				proponente: "node1" as NodoId,
				datos: {},
				timestamp: Date.now(),
				expiracion: Date.now() + 10000,
				votos: [],
				estado: ESTADO_PROPUESTA.ABIERTA,
			},
		];

		manager.importarPropuestas(propsToImport);

		const retrieved = manager.obtenerPropuesta("importedProp1");
		expect(retrieved).not.toBeNull();
		expect(retrieved?.id).toBe("importedProp1");
		expect(retrieved?.estado).toBe(ESTADO_PROPUESTA.ABIERTA);

		// Expect it to close after expiration
		vi.advanceTimersByTime(11000);
		expect(retrieved?.estado).toBe(ESTADO_PROPUESTA.RECHAZADA);
	});

	it("7. ResolveVoteConflicts merges non-conflicting and resolves conflicting", async () => {
		const localVotes: Vote[] = [
			{
				propuesta: "p1",
				voto: "a_favor",
				nodoId: "n1" as NodoId,
				peso: 1,
				justificacion: null,
			},
		];
		const remoteVotes: Vote[] = [
			{
				propuesta: "p1",
				voto: "en_contra", // conflict
				nodoId: "n1" as NodoId,
				peso: 1,
				justificacion: null,
			},
			{
				propuesta: "p1",
				voto: "a_favor", // new vote
				nodoId: "n2" as NodoId,
				peso: 1,
				justificacion: null,
			},
		];

		const resolved = await merger.resolveVoteConflicts(localVotes, remoteVotes);
		expect(resolved.length).toBe(2);

		const v1 = resolved.find((v) => v.nodoId === "n1")!;
		const v2 = resolved.find((v) => v.nodoId === "n2")!;

		expect(v1.voto).toBe("a_favor"); // local preferred
		expect(v2.voto).toBe("a_favor");
	});
});
