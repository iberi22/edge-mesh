import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createGovernanceManager,
	ESTADO_PROPUESTA,
	type GovernanceManager,
} from "../../src/governance/index.js";
import { type NodoId, POLITICA_GOBERNANZA } from "../../src/types/index.js";

describe("GovernanceManager - Comprehensive Unit Tests", () => {
	let governanceManager: GovernanceManager;

	beforeEach(() => {
		vi.useFakeTimers();
		governanceManager = createGovernanceManager();
	});

	afterEach(() => {
		governanceManager.destruir();
		vi.useRealTimers();
	});

	it("should support proposal creation and initial open state", () => {
		const id = "prop1";
		const tipo = "update";
		const proponente = "node1" as NodoId;
		const datos = { foo: "bar" };

		const createdSpy = vi.fn();
		governanceManager.on("propuestaCreada", createdSpy);

		const propuesta = governanceManager.crearPropuesta(
			id,
			tipo,
			proponente,
			datos,
		);

		expect(propuesta.id).toBe(id);
		expect(propuesta.estado).toBe(ESTADO_PROPUESTA.ABIERTA);
		expect(governanceManager.obtenerPropuesta(id)).toBe(propuesta);
		expect(createdSpy).toHaveBeenCalledTimes(1);
	});

	it("should handle voting with different payloads (accept/reject/abstain) and update voting records", () => {
		// Set high threshold of 10 so the proposal remains open during multiple votes
		governanceManager.actualizarPolitica({ umbral: 10 });

		const id = "prop_vote";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {});

		const voter1 = "node2" as NodoId;
		const voter3 = "node3" as NodoId;
		const voter4 = "node4" as NodoId;

		const voteSpy = vi.fn();
		governanceManager.on("votoRecibido", voteSpy);

		// Cast accept vote
		const v1Result = governanceManager.votar(id, {
			nodoId: voter1,
			voto: "a_favor",
			propuesta: id,
			peso: 1,
			justificacion: "Highly beneficial",
		});
		expect(v1Result).toBe(true);
		expect(voteSpy).toHaveBeenCalledTimes(1);

		// Try voting again with same node (should fail/return false)
		const v1Duplicate = governanceManager.votar(id, {
			nodoId: voter1,
			voto: "en_contra",
			propuesta: id,
			peso: 1,
			justificacion: "Changed mind",
		});
		expect(v1Duplicate).toBe(false);

		// Cast reject/en_contra vote
		const v3Result = governanceManager.votar(id, {
			nodoId: voter3,
			voto: "en_contra",
			propuesta: id,
			peso: 1,
			justificacion: "Strong disagreement",
		});
		expect(v3Result).toBe(true);

		// Cast abstain/abstencion vote
		const v4Result = governanceManager.votar(id, {
			nodoId: voter4,
			voto: "abstencion",
			propuesta: id,
			peso: 1,
			justificacion: "Neutral stance",
		});
		expect(v4Result).toBe(true);

		const updatedProp = governanceManager.obtenerPropuesta(id);
		expect(updatedProp?.votos).toHaveLength(3);
		expect(updatedProp?.votos.find((v) => v.nodoId === voter1)?.voto).toBe("a_favor");
		expect(updatedProp?.votos.find((v) => v.nodoId === voter3)?.voto).toBe("en_contra");
		expect(updatedProp?.votos.find((v) => v.nodoId === voter4)?.voto).toBe("abstencion");
	});

	it("should transition proposal state and trigger events on reaching quorum/threshold", () => {
		const id = "prop_threshold";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {});

		const voter1 = "node2" as NodoId;
		const resultSpy = vi.fn();
		governanceManager.on("propuestaResultado", resultSpy);

		// Democratic policy has umbral of 0.51. Voting a_favor with weight 1 (>=0.51) immediately approves it.
		governanceManager.votar(id, {
			nodoId: voter1,
			voto: "a_favor",
			propuesta: id,
			peso: 1,
			justificacion: null,
		});

		const prop = governanceManager.obtenerPropuesta(id);
		expect(prop?.estado).toBe(ESTADO_PROPUESTA.APROBADA);
		expect(resultSpy).toHaveBeenCalledTimes(1);
		expect(resultSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { propuesta: id, resultado: ESTADO_PROPUESTA.APROBADA },
			}),
		);
	});

	it("should reject/expire a proposal on timeout if the quorum/threshold is not reached", () => {
		const id = "prop_timeout";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {}, 1000);

		const resultSpy = vi.fn();
		governanceManager.on("propuestaResultado", resultSpy);

		// Advance time past 1000ms
		vi.advanceTimersByTime(1500);

		const prop = governanceManager.obtenerPropuesta(id);
		expect(prop?.estado).toBe(ESTADO_PROPUESTA.RECHAZADA);
		expect(resultSpy).toHaveBeenCalledTimes(1);
		expect(resultSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { propuesta: id, resultado: ESTADO_PROPUESTA.RECHAZADA },
			}),
		);
	});

	it("should update and respect governance policies and custom node weights", () => {
		// Set high threshold of 10 and map node weights
		governanceManager.actualizarPolitica({
			umbral: 10,
			pesoNodo: { "node-boss": 10, "node-pawn": 1 },
		});

		const id = "prop_weights";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {});

		// Node with weight 1 votes a_favor (Total = 1 < 10, remains ABIERTA)
		governanceManager.votar(id, {
			nodoId: "node-pawn" as NodoId,
			voto: "a_favor",
			propuesta: id,
			peso: 1,
			justificacion: null,
		});
		expect(governanceManager.obtenerPropuesta(id)?.estado).toBe(ESTADO_PROPUESTA.ABIERTA);

		// Node with weight 10 votes a_favor (Total = 11 >= 10, transitions to APROBADA)
		governanceManager.votar(id, {
			nodoId: "node-boss" as NodoId,
			voto: "a_favor",
			propuesta: id,
			peso: 10,
			justificacion: null,
		});
		expect(governanceManager.obtenerPropuesta(id)?.estado).toBe(ESTADO_PROPUESTA.APROBADA);
	});
});
