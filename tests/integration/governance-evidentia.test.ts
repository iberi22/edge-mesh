import { beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import {
	createPostQuantumIdentity,
	generateKeypair,
} from "../../src/identity/index.js";
import { EvidentiaManager } from "../../src/maloca/evidentia.js";
import { MeshManager } from "../../src/mesh/index.js";
import {
	createGovernanceManager,
	ESTADO_PROPUESTA,
	type Propuesta,
} from "../../src/governance/index.js";
import type { NodoId, GovernancePolicy } from "../../src/types/index.js";
import { POLITICA_GOBERNANZA } from "../../src/types/index.js";

// Ensure global.crypto is defined
if (global.crypto === undefined) {
	const { crypto } = await import("node:crypto");
	// @ts-expect-error
	global.crypto = crypto;
}

describe("Integration: Governance + Evidentia (Notarized Proposals)", () => {
	let identity: ReturnType<typeof createPostQuantumIdentity>;
	let mesh: MeshManager;
	let governance: ReturnType<typeof createGovernanceManager>;
	let evidentia: EvidentiaManager;

	const idNode = "voter-node" as NodoId;

	beforeEach(() => {
		const keypair = generateKeypair("maestra");
		identity = createPostQuantumIdentity(idNode, keypair);

		// Mock firmar for stable and fast ML-DSA test execution
		vi.spyOn(identity, "firmar").mockResolvedValue(new Uint8Array(64).fill(1));

		mesh = new MeshManager({ nodoId: idNode }, {} as EdgeMesh);
		vi.spyOn(mesh, "transmitirConGossip").mockResolvedValue(undefined);

		// Democratic policy: 51% threshold, 1 vote to pass if weight is 1
		const policy: GovernancePolicy = {
			politica: POLITICA_GOBERNANZA.DEMOCRATICA,
			umbral: 1.0,
			ventanaMs: 10_000,
			pesoNodo: { [idNode]: 1 },
			reglas: [],
		};
		governance = createGovernanceManager(policy);
		evidentia = new EvidentiaManager(identity, mesh);
	});

	it("should notarize a newly created governance proposal using Evidentia", async () => {
		const propuesta = governance.crearPropuesta(
			"prop-123",
			"CONSTITUTION_AMENDMENT",
			idNode,
			{ clause: "No physical weapons allowed in Maloca salons" },
		);

		const proof = await evidentia.notarize(propuesta, "GOVERNANCE_PROPOSAL_CREATION");

		expect(proof.hash).toBeDefined();
		expect(proof.contenidoHash).toBeDefined();
		expect(proof.tipo).toBe("GOVERNANCE_PROPOSAL_CREATION");
		expect(proof.emisor).toBe(idNode);
		expect(proof.firmaPQC).toBeDefined();
	});

	it("should notarize the outcome of a proposal when it is approved", async () => {
		const propuesta = governance.crearPropuesta(
			"prop-456",
			"RESOURCE_ALLOCATION",
			idNode,
			{ amount: 500, asset: "karma" },
		);

		// Vote in favor to reach quorum and approve the proposal
		governance.votar("prop-456", {
			nodoId: idNode,
			voto: "a_favor",
			timestamp: Date.now(),
			firma: new Uint8Array(0),
		});

		const approvedProp = governance.obtenerPropuesta("prop-456");
		expect(approvedProp).not.toBeNull();
		expect(approvedProp!.estado).toBe(ESTADO_PROPUESTA.APROBADA);

		// Notarize the outcome
		const outcomeProof = await evidentia.notarize(approvedProp, "GOVERNANCE_PROPOSAL_OUTCOME");

		expect(outcomeProof.tipo).toBe("GOVERNANCE_PROPOSAL_OUTCOME");
		expect(outcomeProof.hash).toBeDefined();
		expect(outcomeProof.contenidoHash).toBeDefined();
	});

	it("should retrieve and verify a notarized proposal proof from Evidentia", async () => {
		const propuesta = governance.crearPropuesta(
			"prop-789",
			"ADMIN_ELECTION",
			idNode,
			{ candidate: "peer-alice" },
		);

		const proof = await evidentia.notarize(propuesta, "GOVERNANCE_PROPOSAL_CREATION");

		const retrieved = evidentia.getProof(proof.hash);
		expect(retrieved).not.toBeNull();
		expect(retrieved?.hash).toBe(proof.hash);

		const isVerified = await evidentia.verify(proof.hash);
		expect(isVerified).toBe(true);
	});

	it("should broadcast the notarized proposal to the blockchain namespace using gossip protocol", async () => {
		const gossipSpy = vi.spyOn(mesh, "transmitirConGossip");

		const propuesta = governance.crearPropuesta(
			"prop-abc",
			"CUSTOM_RULE",
			idNode,
			{ rule: "Be kind to other nodes" },
		);

		const proof = await evidentia.notarize(propuesta, "GOVERNANCE_PROPOSAL_CREATION");

		expect(gossipSpy).toHaveBeenCalledWith("_maloca:evidentia", {
			tipo: "DOC_NOTARIZED",
			evidentia: proof,
		});
	});

	it("should return false when verifying non-existent notarization hashes", async () => {
		const result = await evidentia.verify("invalid-hash");
		expect(result).toBe(false);
	});
});
