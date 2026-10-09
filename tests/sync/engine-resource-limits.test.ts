import { beforeEach, describe, expect, it, vi } from "vitest";
import { OpLog } from "../../src/op-log/index.js";
import {
	MAX_BATCH_SIZE,
	MAX_ENVELOPE_BYTES,
	SyncEngine,
} from "../../src/sync/engine.js";
import type { NodoId } from "../../src/types/index.js";

/**
 * SHELF-113: resource limits on inbound sync batches.
 *
 * These tests assert *observable behaviour* — what landed in the OpLog, what the
 * counters say, and which events fired. A test that only asserted "the limit
 * function was called" would survive someone deleting the limit, which is
 * precisely the regression this file exists to prevent. Every limit test below
 * would fail if `aplicarLimitesDeRecurso` were removed from the engine.
 */
describe("SyncEngine resource limits (SHELF-113)", () => {
	const docId = "doc-limites";
	const peerId = "peer-1" as NodoId;
	let oplog: OpLog;

	beforeEach(() => {
		oplog = new OpLog({ docId });
	});

	/** A valid, signed remote operation with a small payload. */
	function op(
		seq: number,
		datos: unknown = { val: seq },
	): Record<string, unknown> {
		return {
			id: `remote:${seq}`,
			tipo: "t1",
			datos,
			timestamp: Date.now(),
			autor: peerId,
			secuencia: seq,
			firma: "firma-valida",
		};
	}

	function ops(desde: number, cantidad: number): Record<string, unknown>[] {
		return Array.from({ length: cantidad }, (_, i) => op(desde + i));
	}

	const noop = async () => {};

	// ─── LÍMITE DE TAMAÑO DE LOTE ─────────────────────────────────────

	describe("batch size limit", () => {
		it("rejects the whole batch when it exceeds the default cap and counts every operation", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });

			const rechazoSpy = vi.fn();
			engine.on("loteRechazado", rechazoSpy);

			const exceso = MAX_BATCH_SIZE + 1;
			const result = await engine.sincronizar(peerId, noop, async () =>
				ops(1, exceso),
			);

			// Nothing was applied: the log is untouched, not partially written.
			expect(result.exito).toBe(true);
			expect(result.operacionesRecibidas).toBe(0);
			expect(result.operacionesRechazadas).toBe(exceso);
			expect(oplog.obtenerUltimaSecuencia()).toBe(0);

			// The peer is told why, with the numbers an operator needs.
			expect(rechazoSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: expect.objectContaining({
						lotesOperaciones: exceso,
						maximoPermitido: MAX_BATCH_SIZE,
					}),
				}),
			);
		});

		it("rejects a batch of a million operations without exhausting the node", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });

			// Simulate the memory-exhaustion attack shape: an enormous array built by
			// a hostile peer. The engine must reject it without applying any of it.
			const million = 1_000_000;
			const hostile = new Array<Record<string, unknown>>(million);
			for (let i = 0; i < million; i++) hostile[i] = op(i + 1);

			const result = await engine.sincronizar(
				peerId,
				noop,
				async () => hostile,
			);

			expect(result.operacionesRecibidas).toBe(0);
			expect(result.operacionesRechazadas).toBe(million);
			expect(oplog.obtenerUltimaSecuencia()).toBe(0);
		});

		it("rejects an oversized batch without measuring any envelope in it", async () => {
			// The batch-count cap must short-circuit on `length`. If the per-envelope
			// pass ran first, each oversized envelope would also fire its own
			// rejection event — an event storm proportional to the hostile batch size,
			// which is exactly the amplification this ordering prevents.
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				maxBatchOperations: 5,
			});

			const sobreSpy = vi.fn();
			const loteSpy = vi.fn();
			engine.on("sobreRechazadoPorTamano", sobreSpy);
			engine.on("loteRechazado", loteSpy);

			// 50 envelopes, each individually over the per-envelope cap.
			const todosEnormes = Array.from({ length: 50 }, (_, i) =>
				op(i + 1, { blob: "x".repeat(MAX_ENVELOPE_BYTES * 2) }),
			);

			const result = await engine.sincronizar(
				peerId,
				noop,
				async () => todosEnormes,
			);

			expect(result.operacionesRecibidas).toBe(0);
			expect(result.operacionesRechazadas).toBe(50);
			// Exactly one event for the batch, none for the individual envelopes.
			expect(sobreSpy).not.toHaveBeenCalled();
			expect(loteSpy).toHaveBeenCalledTimes(1);
		});

		it("accepts a batch exactly at the limit (boundary is inclusive)", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });

			const result = await engine.sincronizar(peerId, noop, async () =>
				ops(1, MAX_BATCH_SIZE),
			);

			expect(result.exito).toBe(true);
			expect(result.operacionesRecibidas).toBe(MAX_BATCH_SIZE);
			expect(result.operacionesRechazadas).toBe(0);
			expect(oplog.obtenerUltimaSecuencia()).toBe(MAX_BATCH_SIZE);
		});

		it("honours an explicit maxBatchOperations override in both directions", async () => {
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				maxBatchOperations: 3,
			});

			const justo = await engine.sincronizar(peerId, noop, async () =>
				ops(1, 3),
			);
			expect(justo.operacionesRecibidas).toBe(3);
			expect(justo.operacionesRechazadas).toBe(0);

			const exceso = await engine.sincronizar(peerId, noop, async () =>
				ops(4, 4),
			);
			expect(exceso.operacionesRecibidas).toBe(0);
			expect(exceso.operacionesRechazadas).toBe(4);
		});
	});

	// ─── LÍMITE DE TAMAÑO POR SOBRE ───────────────────────────────────

	describe("per-envelope size limit", () => {
		it("rejects a single oversized envelope without truncating it", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });

			const rechazoSpy = vi.fn();
			engine.on("sobreRechazadoPorTamano", rechazoSpy);

			// One envelope well over the cap, sitting between two small valid ones.
			const enorme = {
				...op(2),
				datos: { blob: "x".repeat(MAX_ENVELOPE_BYTES * 2) },
			};
			const lote = [op(1), enorme, op(3)];

			const result = await engine.sincronizar(peerId, noop, async () => lote);

			// The oversized envelope is dropped; its neighbours still sync. Truncating
			// instead would have applied a partial operation and advanced the sequence
			// inconsistently — the log must jump from 1 to 3, never through 2.
			expect(result.operacionesRecibidas).toBe(2);
			expect(result.operacionesRechazadas).toBe(1);
			expect(oplog.obtenerUltimaSecuencia()).toBe(3);

			expect(rechazoSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					detail: expect.objectContaining({
						secuencia: 2,
						maximoPermitido: MAX_ENVELOPE_BYTES,
						bytes: expect.any(Number),
					}),
				}),
			);
			const detail = vi.mocked(rechazoSpy.mock.calls[0][0])
				.detail as unknown as {
				bytes: number;
				maximoPermitido: number;
			};
			expect(detail.bytes).toBeGreaterThan(detail.maximoPermitido);
		});

		it("accepts a large-but-legal envelope just under the cap", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });

			// ~100 KiB: big for a clinical edit, well under the 256 KiB cap.
			const grande = op(1, { nota: "x".repeat(100 * 1024) });
			const result = await engine.sincronizar(peerId, noop, async () => [
				grande,
			]);

			expect(result.operacionesRecibidas).toBe(1);
			expect(result.operacionesRechazadas).toBe(0);
		});

		it("rejects an unserializable envelope instead of throwing", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });

			// A cyclic payload makes JSON.stringify throw. The engine must treat it as
			// an oversized/unusable envelope, not crash the sync round.
			const ciclico: Record<string, unknown> = {
				id: "remote:1",
				tipo: "t1",
				secuencia: 1,
			};
			ciclico.datos = ciclico;
			const conCiclico = { ...op(1), datos: ciclico };

			const result = await engine.sincronizar(peerId, noop, async () => [
				conCiclico,
				op(2),
			]);

			expect(result.exito).toBe(true);
			expect(result.operacionesRechazadas).toBe(1);
			expect(result.operacionesRecibidas).toBe(1);
			expect(oplog.obtenerUltimaSecuencia()).toBe(2);
		});

		it("honours an explicit maxEnvelopeBytes override", async () => {
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				maxEnvelopeBytes: 200,
			});

			const grande = op(1, { nota: "x".repeat(500) });
			const result = await engine.sincronizar(peerId, noop, async () => [
				grande,
			]);

			expect(result.operacionesRecibidas).toBe(0);
			expect(result.operacionesRechazadas).toBe(1);
		});
	});

	// ─── INTERACCIÓN CON EL GATE DE FIRMAS ────────────────────────────
	//
	// ADAPTADO al linaje del core: este motor NO tiene el gate de firmas de
	// sobres (SHELF-111), que pertenece a otra rama del fork y no forma parte de
	// las 5 correcciones de seguridad de este porte. Las pruebas originales de
	// esta seccion afirmaban que el gate de firmas seguiría aplicandose a las
	// operaciones que pasan los limites, y que sus rechazos se sumarian a los de
	// recursos en el mismo contador.
	//
	// La propiedad equivalente que SI existe en este linaje es la que de verdad
	// importa para un limite de recurso: los limites son ortogonales a la
	// validacion estructural, asi que un lote invalido que pasa el tope se
	// descarta igual por `esOperacionValida`, y un lote sobredimensionado se
	// rechaza sin llegar a validarse. Ninguno de los dos caminos puede dejar
	// basura en el log.
	describe("interaction with structural validation", () => {
		it("applies structural validation to operations that pass the limits", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });

			// Structurally invalid: no `secuencia`, no `id`. Small, so the resource
			// limits let them through.
			const invalidas = [
				{ tipo: "t1", datos: {}, timestamp: Date.now(), autor: peerId },
				{ id: "r:2", tipo: "t1", timestamp: Date.now(), autor: peerId },
				{ id: "r:3", tipo: "t1", datos: {}, timestamp: Date.now() },
			];

			const result = await engine.sincronizar(
				peerId,
				noop,
				async () => invalidas,
			);

			// The resource limit rejected nothing (all three are small); structural
			// validation is what kept them out of the log.
			expect(result.operacionesRechazadas).toBe(0);
			expect(result.operacionesRecibidas).toBe(0);
			expect(oplog.obtenerUltimaSecuencia()).toBe(0);
		});

		it("never reaches structural validation for an oversized batch", async () => {
			// Ordering check: the batch cap short-circuits on `length`, so a huge
			// batch of invalid ops is rejected wholesale and reports the full count,
			// never a partial merge of whichever ones happened to look valid.
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				maxBatchOperations: 10,
			});

			const invalidas = Array.from({ length: 500 }, (_, i) => ({
				tipo: "t1",
				datos: {},
				timestamp: Date.now(),
				autor: peerId,
				secuencia: i,
			}));

			const result = await engine.sincronizar(
				peerId,
				noop,
				async () => invalidas,
			);

			expect(result.operacionesRecibidas).toBe(0);
			expect(result.operacionesRechazadas).toBe(500);
			expect(oplog.obtenerUltimaSecuencia()).toBe(0);
		});

		it("counts size rejections and valid-operation filtering without either masking the other", async () => {
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				maxBatchOperations: 10,
			});

			// 2 oversized (resource limit) + 2 structurally invalid + 1 valid.
			const lote = [
				{ ...op(1), datos: { blob: "x".repeat(MAX_ENVELOPE_BYTES * 2) } },
				{ ...op(2), datos: { blob: "y".repeat(MAX_ENVELOPE_BYTES * 3) } },
				{ tipo: "t1", datos: {}, timestamp: Date.now(), autor: peerId },
				{ id: "r:4", tipo: "t1", timestamp: Date.now() },
				op(5),
			];

			const result = await engine.sincronizar(peerId, noop, async () => lote);

			// Only the one structurally valid, in-budget operation lands.
			expect(result.operacionesRecibidas).toBe(1);
			// The two oversized ones are reported as resource rejections.
			expect(result.operacionesRechazadas).toBe(2);
			expect(oplog.obtenerUltimaSecuencia()).toBe(5);
		});
	});

	// ─── NO REGRESIÓN ─────────────────────────────────────────────────

	describe("normal sync is unchanged", () => {
		it("applies a normal-sized batch exactly as before", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });
			await oplog.append("local", { val: 0 }, "local" as NodoId);

			const remoto = [op(2), op(3), op(4)];
			const result = await engine.sincronizar(peerId, noop, async () => remoto);

			expect(result.exito).toBe(true);
			expect(result.operacionesRecibidas).toBe(3);
			expect(result.operacionesRechazadas).toBe(0);
			expect(result.conflictos).toBe(0);
			expect(result.operacionesEnviadas).toBe(1);
			expect(oplog.obtenerUltimaSecuencia()).toBe(4);
			expect(engine.obtenerClockRemoto(peerId)).toBe(4);
		});

		it("leaves an empty batch alone", async () => {
			const engine = new SyncEngine({ docId, opLog: oplog });
			const result = await engine.sincronizar(peerId, noop, async () => []);

			expect(result.exito).toBe(true);
			expect(result.operacionesRecibidas).toBe(0);
			expect(result.operacionesRechazadas).toBe(0);
		});

		it("does not advance the peer clock for a rejected batch", async () => {
			// Otherwise the next round would skip the operations we refused, turning a
			// transient size rejection into permanent data loss.
			const engine = new SyncEngine({ docId, opLog: oplog });

			await engine.sincronizar(peerId, noop, async () =>
				ops(1, MAX_BATCH_SIZE + 1),
			);
			expect(engine.obtenerClockRemoto(peerId)).toBe(0);

			const recuperacion = await engine.sincronizar(peerId, noop, async () =>
				ops(1, 5),
			);
			expect(recuperacion.operacionesRecibidas).toBe(5);
			expect(oplog.obtenerUltimaSecuencia()).toBe(5);
		});

		it("does not apply the limits on the send path", async () => {
			// Outbound batching is driven by `batchSize`, which is independent of the
			// new inbound cap: a local log larger than `maxBatchOperations` must still
			// go out in full, and nothing outgoing may be counted as rejected.
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				batchSize: 2,
				maxBatchOperations: 2,
			});
			for (let i = 0; i < 5; i++)
				await oplog.append("t", { i }, "local" as NodoId);

			const enviar = vi.fn().mockResolvedValue(undefined);
			const result = await engine.sincronizar(peerId, enviar, async () => []);

			expect(result.operacionesEnviadas).toBe(5);
			expect(result.operacionesRechazadas).toBe(0);
			expect(enviar).toHaveBeenCalledTimes(3);
		});
	});

	// ─── EL LÍMITE ES REAL, NO ACCIDENTAL ─────────────────────────────

	describe("the limits are real, not accidental", () => {
		it("exposes the documented default caps", () => {
			// If someone deletes the constants and hardcodes a giant number, this fails.
			expect(MAX_BATCH_SIZE).toBe(500);
			expect(MAX_ENVELOPE_BYTES).toBe(256 * 1024);
		});

		it("rejects a batch of one operation over the cap but not one under it", async () => {
			// The sharpest possible regression test: a single-operation difference must
			// flip the outcome. If the limit were deleted, both calls apply and this
			// fails on the first assertion.
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				maxBatchOperations: 10,
			});

			const bajo = await engine.sincronizar(peerId, noop, async () =>
				ops(1, 9),
			);
			expect(bajo.operacionesRecibidas).toBe(9);
			expect(bajo.operacionesRechazadas).toBe(0);

			const justo = await engine.sincronizar(peerId, noop, async () =>
				ops(10, 10),
			);
			expect(justo.operacionesRecibidas).toBe(10);
			expect(justo.operacionesRechazadas).toBe(0);

			const encima = await engine.sincronizar(peerId, noop, async () =>
				ops(20, 11),
			);
			expect(encima.operacionesRecibidas).toBe(0);
			expect(encima.operacionesRechazadas).toBe(11);
			// The rejected batch (seq 20..30) left no trace: the log still ends at the
			// last operation that was actually accepted.
			expect(oplog.obtenerUltimaSecuencia()).toBe(19);
		});

		it("rejects an envelope one byte over the cap but not one byte under", async () => {
			const engine = new SyncEngine({
				docId,
				opLog: oplog,
				maxEnvelopeBytes: 4096,
			});

			const medir = (nota: number) =>
				new TextEncoder().encode(
					JSON.stringify(op(1, { nota: "x".repeat(nota) })),
				).length;
			const base = medir(0);

			const debajo = await engine.sincronizar(peerId, noop, async () => [
				op(1, { nota: "x".repeat(4096 - base - 1) }),
			]);
			expect(debajo.operacionesRecibidas).toBe(1);
			expect(debajo.operacionesRechazadas).toBe(0);

			const encima = await engine.sincronizar(peerId, noop, async () => [
				op(1, { nota: "x".repeat(4096 - base + 1) }),
			]);
			expect(encima.operacionesRecibidas).toBe(0);
			expect(encima.operacionesRechazadas).toBe(1);
		});
	});
});
