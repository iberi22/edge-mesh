import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createGovernanceManager,
	ESTADO_PROPUESTA,
	type GovernanceManager,
} from "../../src/governance/index.js";
import { type NodoId, POLITICA_GOBERNANZA } from "../../src/types/index.js";

describe("GovernanceManager", () => {
	let governanceManager: GovernanceManager;

	beforeEach(() => {
		vi.useFakeTimers();
		governanceManager = createGovernanceManager();
	});

	afterEach(() => {
		governanceManager.destruir();
		vi.useRealTimers();
	});

	it("should create a proposal", () => {
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
			5000,
		);

		expect(propuesta.id).toBe(id);
		expect(propuesta.estado).toBe(ESTADO_PROPUESTA.ABIERTA);
		expect(propuesta.expiracion).toBe(propuesta.timestamp + 5000);
		expect(governanceManager.obtenerPropuesta(id)).toBe(propuesta);
		expect(createdSpy).toHaveBeenCalled();
	});

	it("should handle voting outcomes: a_favor, en_contra, and abstencion", () => {
		const id = "prop_votes";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {});

		const vote1 = {
			nodoId: "node2" as NodoId,
			voto: "a_favor" as const,
			propuesta: id,
			peso: 1,
			justificacion: null,
		};
		const vote2 = {
			nodoId: "node3" as NodoId,
			voto: "en_contra" as const,
			propuesta: id,
			peso: 1,
			justificacion: "no like",
		};
		const vote3 = {
			nodoId: "node4" as NodoId,
			voto: "abstencion" as const,
			propuesta: id,
			peso: 1,
			justificacion: "neutral",
		};

		// Set high threshold so votes don't trigger immediate approval
		governanceManager.actualizarPolitica({ umbral: 5.0 });

		const success1 = governanceManager.votar(id, vote1);
		const success2 = governanceManager.votar(id, vote2);
		const success3 = governanceManager.votar(id, vote3);

		expect(success1).toBe(true);
		expect(success2).toBe(true);
		expect(success3).toBe(true);

		const propuesta = governanceManager.obtenerPropuesta(id);
		expect(propuesta?.votos.length).toBe(3);
		expect(propuesta?.votos.map(v => v.voto)).toEqual(["a_favor", "en_contra", "abstencion"]);
		expect(propuesta?.estado).toBe(ESTADO_PROPUESTA.ABIERTA);
	});

	it("should prevent duplicate voting from the same node", () => {
		const id = "prop_dup";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {});
		governanceManager.actualizarPolitica({ umbral: 5.0 });

		const vote = {
			nodoId: "node2" as NodoId,
			voto: "a_favor" as const,
			propuesta: id,
			peso: 1,
			justificacion: null,
		};

		const successFirst = governanceManager.votar(id, vote);
		const successSecond = governanceManager.votar(id, vote);

		expect(successFirst).toBe(true);
		expect(successSecond).toBe(false); // Duplicate vote should fail
		expect(governanceManager.obtenerPropuesta(id)?.votos.length).toBe(1);
	});

	it("should prevent voting on closed or expired proposals", () => {
		const id = "prop_closed";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {}, 1000);

		// Expire the proposal
		vi.advanceTimersByTime(1500);
		expect(governanceManager.obtenerPropuesta(id)?.estado).toBe(ESTADO_PROPUESTA.RECHAZADA);

		const vote = {
			nodoId: "node2" as NodoId,
			voto: "a_favor" as const,
			propuesta: id,
			peso: 1,
			justificacion: null,
		};

		const success = governanceManager.votar(id, vote);
		expect(success).toBe(false);
	});

	it("should handle voting and threshold (state transitions & quorum)", () => {
		const id = "prop2";
		const proponente = "node1" as NodoId;
		governanceManager.crearPropuesta(id, "test", proponente, {});

		const voter1 = "node2" as NodoId;

		const resultSpy = vi.fn();
		governanceManager.on("propuestaResultado", resultSpy);

		// Default threshold is 0.51, default weight is 1.
		// Positive vote (a_favor) of weight 1 will cross 0.51 threshold.
		governanceManager.votar(id, {
			nodoId: voter1,
			voto: "a_favor",
			propuesta: id,
			peso: 1,
			justificacion: null,
		});

		expect(governanceManager.obtenerPropuesta(id)?.estado).toBe(
			ESTADO_PROPUESTA.APROBADA,
		);
		expect(resultSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { propuesta: id, resultado: ESTADO_PROPUESTA.APROBADA },
			}),
		);
	});

	it("should reject proposal on timeout if threshold not reached", () => {
		const id = "prop3";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {}, 1000);

		vi.advanceTimersByTime(1500);

		expect(governanceManager.obtenerPropuesta(id)?.estado).toBe(
			ESTADO_PROPUESTA.RECHAZADA,
		);
	});

	it("should update policy", () => {
		const newPolicy = {
			politica: POLITICA_GOBERNANZA.AUTORITARIA,
			umbral: 0.9,
		};

		governanceManager.actualizarPolitica(newPolicy);
		expect(governanceManager.obtenerPolitica().politica).toBe(
			POLITICA_GOBERNANZA.AUTORITARIA,
		);
		expect(governanceManager.obtenerPolitica().umbral).toBe(0.9);
	});

	it("should respect node weights for quorum calculation", () => {
		governanceManager.actualizarPolitica({
			umbral: 10,
			pesoNodo: { "node-boss": 10, "node-pawn": 1 },
		});

		const id = "prop4";
		governanceManager.crearPropuesta(id, "test", "node1" as NodoId, {});

		// Pawn votes
		governanceManager.votar(id, {
			nodoId: "node-pawn" as NodoId,
			voto: "a_favor",
			propuesta: id,
			peso: 1,
			justificacion: null,
		});
		expect(governanceManager.obtenerPropuesta(id)?.estado).toBe(
			ESTADO_PROPUESTA.ABIERTA,
		);

		// Boss votes
		governanceManager.votar(id, {
			nodoId: "node-boss" as NodoId,
			voto: "a_favor",
			propuesta: id,
			peso: 10,
			justificacion: null,
		});
		expect(governanceManager.obtenerPropuesta(id)?.estado).toBe(
			ESTADO_PROPUESTA.APROBADA,
		);
	});
});