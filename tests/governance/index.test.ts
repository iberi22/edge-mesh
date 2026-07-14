import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { GovernanceManager, ESTADO_PROPUESTA } from "../../src/governance/index.js";
import { POLITICA_GOBERNANZA, type NodoId, type PayloadVotacion } from "../../src/types/index.js";

describe("GovernanceManager", () => {
  let governanceManager: GovernanceManager;
  const proponente = "node-1" as NodoId;
  const voter1 = "node-2" as NodoId;
  const voter2 = "node-3" as NodoId;

  const config = {
    politica: POLITICA_GOBERNANZA.DEMOCRATICA,
    umbral: 2, // Need 2 votes (weight 1 each)
    ventanaMs: 1000,
    pesoNodo: {},
    reglas: [],
  };

  beforeEach(() => {
    vi.useFakeTimers();
    governanceManager = new GovernanceManager(config);
  });

  afterEach(() => {
    governanceManager.destruir();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("should create a proposal", () => {
    const spy = vi.fn();
    governanceManager.on("propuestaCreada", spy);

    const propuesta = governanceManager.crearPropuesta(
      "prop-1",
      "test-type",
      proponente,
      { key: "value" }
    );

    expect(propuesta.id).toBe("prop-1");
    expect(propuesta.estado).toBe(ESTADO_PROPUESTA.ABIERTA);
    expect(spy).toHaveBeenCalled();
  });

  it("should accept votes and transition to approved when threshold is reached", () => {
    const resultSpy = vi.fn();
    governanceManager.on("propuestaResultado", resultSpy);

    governanceManager.crearPropuesta("prop-1", "test", proponente, {});

    const voto1: PayloadVotacion = {
      propuesta: "prop-1",
      voto: "a_favor",
      nodoId: voter1,
      peso: 1,
      justificacion: null,
    };

    const voto2: PayloadVotacion = {
      propuesta: "prop-1",
      voto: "a_favor",
      nodoId: voter2,
      peso: 1,
      justificacion: null,
    };

    governanceManager.votar("prop-1", voto1);
    expect(governanceManager.obtenerPropuesta("prop-1")?.estado).toBe(ESTADO_PROPUESTA.ABIERTA);

    governanceManager.votar("prop-1", voto2);
    expect(governanceManager.obtenerPropuesta("prop-1")?.estado).toBe(ESTADO_PROPUESTA.APROBADA);

    expect(resultSpy).toHaveBeenCalledWith(expect.objectContaining({
      detail: { propuesta: "prop-1", resultado: ESTADO_PROPUESTA.APROBADA }
    }));
  });

  it("should reject proposal if threshold not reached before expiration", () => {
    const resultSpy = vi.fn();
    governanceManager.on("propuestaResultado", resultSpy);

    governanceManager.crearPropuesta("prop-1", "test", proponente, {});

    const voto1: PayloadVotacion = {
      propuesta: "prop-1",
      voto: "a_favor",
      nodoId: voter1,
      peso: 1,
      justificacion: null,
    };

    governanceManager.votar("prop-1", voto1);

    vi.advanceTimersByTime(2000); // Beyond ventanaMs

    expect(governanceManager.obtenerPropuesta("prop-1")?.estado).toBe(ESTADO_PROPUESTA.RECHAZADA);
    expect(resultSpy).toHaveBeenCalledWith(expect.objectContaining({
      detail: { propuesta: "prop-1", resultado: ESTADO_PROPUESTA.RECHAZADA }
    }));
  });

  it("should not allow double voting from same node", () => {
    governanceManager.crearPropuesta("prop-1", "test", proponente, {});

    const voto1: PayloadVotacion = {
      propuesta: "prop-1",
      voto: "a_favor",
      nodoId: voter1,
      peso: 1,
      justificacion: null,
    };

    expect(governanceManager.votar("prop-1", voto1)).toBe(true);
    expect(governanceManager.votar("prop-1", voto1)).toBe(false);
    expect(governanceManager.obtenerPropuesta("prop-1")?.votos.length).toBe(1);
  });

  it("should respect node weights", () => {
    const weightedManager = new GovernanceManager({
      ...config,
      umbral: 10,
      pesoNodo: { [voter1]: 10 },
    });

    weightedManager.crearPropuesta("prop-1", "test", proponente, {});

    const voto1: PayloadVotacion = {
      propuesta: "prop-1",
      voto: "a_favor",
      nodoId: voter1,
      peso: 1,
      justificacion: null,
    };

    weightedManager.votar("prop-1", voto1);
    expect(weightedManager.obtenerPropuesta("prop-1")?.estado).toBe(ESTADO_PROPUESTA.APROBADA);
    weightedManager.destruir();
  });
});
