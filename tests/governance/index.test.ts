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
		);

		expect(propuesta.id).toBe(id);
		expect(propuesta.estado).toBe(ESTADO_PROPUESTA.ABIERTA);
		expect(governanceManager.obtenerPropuesta(id)).toBe(propuesta);
		expect(createdSpy).toHaveBeenCalled();
	});

	it("should handle voting and threshold", () => {
		const id = "prop2";
		const proponente = "node1" as NodoId;
		governanceManager.crearPropuesta(id, "test", proponente, {});

		const voter1 = "node2" as NodoId;
		const voter2 = "node3" as NodoId;

		const resultSpy = vi.fn();
		governanceManager.on("propuestaResultado", resultSpy);

		// Default threshold is 0.51, default weight is 1.
		// We need more than 0.51 to pass. 1 vote = 1.0 weight if not specified.
		// Wait, the code says:
		// pesoTotal = this.calcularPesoTotal(propuesta);
		// return pesoTotal >= this.politica.umbral;
		// umbral is 0.51.

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

	it("should respect node weights", () => {
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
