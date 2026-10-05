import { beforeEach, describe, expect, it } from 'vitest';
import { createPostQuantumIdentity, generateKeypair, TIPO_IDENTIDAD } from '../../src/identity/index.js';
import { MalocaKernel } from '../../src/maloca/kernel.js';
import type { TransaccionKarma } from '../../src/maloca/types.js';
import type { NodoId } from '../../src/types/index.js';

/**
* Mirror of KarmaManager's internal canonical stringify, so a test can build the
* exact byte string that a remote peer would have signed. Kept in the test rather
* than exported from src so the module's public API does not grow a signing helper
* that application code could misuse.
*/
function canonicalTestPayload(obj: unknown): string {
	if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
	if (Array.isArray(obj)) return `[${obj.map(canonicalTestPayload).join(',')}]`;
	const keys = Object.keys(obj as Record<string, unknown>).sort();
	return (
		'{' +
		keys.map((k) => `${JSON.stringify(k)}:${canonicalTestPayload((obj as Record<string, unknown>)[k])}`).join(',') +
		'}'
	);
}

/**
* Reputation-tampering tests for KarmaManager.
*
* The mesh is destined for a network of verified physicians, where a forged or
* self-issued endorsement is a patient-safety problem, not a cosmetic bug. These
* tests pin down the attacks that were previously possible: self-awarded karma,
* unbounded deltas and unsigned transactions.
*/
describe('KarmaManager', () => {
	let kernel: MalocaKernel;
	let nodoId: NodoId;

	beforeEach(async () => {
		const kp = generateKeypair('maestra');

		kernel = new MalocaKernel({
			nodoId: 'test-node' as NodoId,
			storageBackend: 'mem',
			identitySecret: kp.parPrivado,
		});
		await kernel.iniciar();
		nodoId = kernel.config.nodoId as NodoId;
	});

	it('should emit and retrieve karma score', async () => {
		const otro = 'medico-b' as NodoId;

		await kernel.karma.emit({
			tipo: 'contribution',
			proyecto: 'maloca',
			sujeto: otro,
			delta: 10,
			razon: 'feature implementation',
			emisor: nodoId,
		});

		const score = kernel.karma.getScore(otro);
		expect(score).toBe(10);
	});

	it('should track scores and history', async () => {
		const otro = 'medico-b' as NodoId;

		await kernel.karma.emit({
			tipo: 'contribution',
			proyecto: 'maloca',
			sujeto: otro,
			delta: 5,
			razon: 'bug fix',
			emisor: nodoId,
		});

		await kernel.karma.emit({
			tipo: 'contribution',
			proyecto: 'maloca',
			sujeto: otro,
			delta: 3,
			razon: 'docs',
			emisor: nodoId,
		});

		expect(kernel.karma.getScore(otro)).toBe(8);
		expect(kernel.karma.getHistory(otro)).toHaveLength(2);
	});

	it('should apply decay', async () => {
		const otro = 'medico-b' as NodoId;

		await kernel.karma.emit({
			tipo: 'initial',
			proyecto: 'maloca',
			sujeto: otro,
			delta: 20,
			razon: 'setup',
			emisor: nodoId,
		});

		await kernel.karma.applyDecay(otro, 0.9);
		expect(kernel.karma.getScore(otro)).toBeCloseTo(18, 10);
	});

	// ─── LEGITIMATE PATH ──────────────────────────────────────────────────

	it('should keep the signature on applied transactions so it can be re-verified', async () => {
		const otro = 'medico-b' as NodoId;

		const tx = await kernel.karma.emit({
			tipo: 'avalo',
			proyecto: 'clinica-norte',
			sujeto: otro,
			delta: 12,
			razon: 'verified board certification',
			emisor: nodoId,
		});

		const historial = kernel.karma.getHistory(otro);
		expect(historial).toHaveLength(1);
		expect(historial[0].firma.length).toBeGreaterThan(0);
		expect(historial[0].firma).toEqual(tx.firma);

		// The stored endorsement still verifies against the issuer's public key.
		const valida = await kernel.karma.verify(historial[0], kernel.identity.exportarPublico());
		expect(valida).toBe(true);
	});

	it('should accept a legitimate remote endorsement signed by the peer', async () => {
		const emisor = 'medico-a' as NodoId;
		const sujeto = 'medico-b' as NodoId;

		// Build a real ML-DSA identity for the issuer and publish its public key.
		const kpEmisor = generateKeypair('maestra');
		const identidadEmisor = createPostQuantumIdentity(emisor, {
			...kpEmisor,
			tipo: TIPO_IDENTIDAD.MAESTRA,
		});
		kernel.karma.registrarClavePublica(emisor, identidadEmisor.exportarPublico());

		// The peer signs the endorsement exactly the way KarmaManager.emit would.
		const cuerpo = {
			tipo: 'avalo',
			proyecto: 'clinica-norte',
			sujeto,
			delta: 15,
			razon: 'peer review',
			emisor,
		};
		const firma = await identidadEmisor.firmar(
			new TextEncoder().encode(canonicalTestPayload({ ...cuerpo, id: 'tx-legitima-1', timestamp: 1234567890 })),
		);

		const motivo = await kernel.karma.aplicarTransaccion({
			...cuerpo,
			id: 'tx-legitima-1',
			timestamp: 1234567890,
			firma,
		});

		expect(motivo).toBeNull();
		expect(kernel.karma.getScore(sujeto)).toBe(15);
		expect(kernel.karma.getHistory(sujeto)).toHaveLength(1);
	});

	it('should refuse a remote endorsement whose issuer key is not registered', async () => {
		const emisor = 'medico-a' as NodoId;
		const sujeto = 'medico-b' as NodoId;
		const identidadEmisor = createPostQuantumIdentity(emisor, {
			...generateKeypair('maestra'),
			tipo: TIPO_IDENTIDAD.MAESTRA,
		});
		// NOTE: the public key is deliberately NOT registered.

		const cuerpo = {
			tipo: 'avalo',
			proyecto: 'clinica-norte',
			sujeto,
			delta: 15,
			razon: 'peer review',
			emisor,
		};
		const firma = await identidadEmisor.firmar(
			new TextEncoder().encode(canonicalTestPayload({ ...cuerpo, id: 'tx-sin-registro-1', timestamp: 1234567890 })),
		);

		const motivo = await kernel.karma.aplicarTransaccion({
			...cuerpo,
			id: 'tx-sin-registro-1',
			timestamp: 1234567890,
			firma,
		});

		expect(motivo).toBe('emisor_desconocido');
		expect(kernel.karma.getScore(sujeto)).toBe(0);
	});

	// ─── ATTACK: self-awarded karma ───────────────────────────────────────

	it('should reject self-awarded karma (emisor === sujeto)', async () => {
		await expect(
			kernel.karma.emit({
				tipo: 'auto_avalo',
				proyecto: 'maloca',
				sujeto: nodoId,
				delta: 1000,
				razon: 'i trust myself',
				emisor: nodoId,
			}),
		).rejects.toThrow(/auto_emision/);

		expect(kernel.karma.getScore(nodoId)).toBe(0);
		expect(kernel.karma.getHistory(nodoId)).toHaveLength(0);
	});

	it('should reject self-awarded karma sent as a remote transaction', async () => {
		kernel.karma.registrarClavePublica(nodoId, kernel.identity.exportarPublico());

		const motivo = await kernel.karma.aplicarTransaccion({
			tipo: 'auto_avalo',
			proyecto: 'maloca',
			sujeto: nodoId,
			delta: 1e9,
			razon: 'i trust myself',
			emisor: nodoId,
			id: 'tx-auto-1',
			timestamp: Date.now(),
			firma: kernel.identity.exportarPublico(),
		});

		expect(motivo).toBe('auto_emision');
		expect(kernel.karma.getScore(nodoId)).toBe(0);
	});

	// ─── ATTACK: unbounded delta ──────────────────────────────────────────

	it('should reject a giant delta aimed at a peer', async () => {
		await expect(
			kernel.karma.emit({
				tipo: 'contribution',
				proyecto: 'maloca',
				sujeto: 'medico-b' as NodoId,
				delta: 1e9,
				razon: 'gift',
				emisor: nodoId,
			}),
		).rejects.toThrow(/delta_sobre_techo/);

		expect(kernel.karma.getScore('medico-b' as NodoId)).toBe(0);
	});

	it('should reject a delta above the documented ceiling', async () => {
		await expect(
			kernel.karma.emit({
				tipo: 'contribution',
				proyecto: 'maloca',
				sujeto: 'medico-b' as NodoId,
				delta: 25.0001,
				razon: 'just over the line',
				emisor: nodoId,
			}),
		).rejects.toThrow(/delta_sobre_techo/);
	});

	// ─── ATTACK: non-positive / hostile deltas ────────────────────────────

	it('should reject a negative delta (griefing a competitor)', async () => {
		await expect(
			kernel.karma.emit({
				tipo: 'penalizacion',
				proyecto: 'maloca',
				sujeto: 'medico-b' as NodoId,
				delta: -500,
				razon: 'bury the competition',
				emisor: nodoId,
			}),
		).rejects.toThrow(/delta_no_positivo/);

		expect(kernel.karma.getScore('medico-b' as NodoId)).toBe(0);
	});

	it('should reject a zero delta', async () => {
		await expect(
			kernel.karma.emit({
				tipo: 'noop',
				proyecto: 'maloca',
				sujeto: 'medico-b' as NodoId,
				delta: 0,
				razon: 'nothing',
				emisor: nodoId,
			}),
		).rejects.toThrow(/delta_no_positivo/);
	});

	it('should reject a NaN or infinite delta', async () => {
		await expect(
			kernel.karma.emit({
				tipo: 'contribution',
				proyecto: 'maloca',
				sujeto: 'medico-b' as NodoId,
				delta: Number.NaN,
				razon: 'nan',
				emisor: nodoId,
			}),
		).rejects.toThrow(/delta_no_positivo/);

		await expect(
			kernel.karma.emit({
				tipo: 'contribution',
				proyecto: 'maloca',
				sujeto: 'medico-b' as NodoId,
				delta: Number.POSITIVE_INFINITY,
				razon: 'infinite',
				emisor: nodoId,
			}),
		).rejects.toThrow(/delta_no_positivo/);
	});

	// ─── ATTACK: no proof at all ──────────────────────────────────────────

	it('should reject a transaction with an empty signature', async () => {
		kernel.karma.registrarClavePublica('medico-a' as NodoId, kernel.identity.exportarPublico());

		const motivo = await kernel.karma.aplicarTransaccion({
			tipo: 'avalo',
			proyecto: 'maloca',
			sujeto: 'medico-b' as NodoId,
			delta: 20,
			razon: 'trust me',
			emisor: 'medico-a' as NodoId,
			id: 'tx-vacia-1',
			timestamp: Date.now(),
			firma: new Uint8Array(0),
		});

		expect(motivo).toBe('firma_vacia');
		expect(kernel.karma.getScore('medico-b' as NodoId)).toBe(0);
	});

	it('should reject a transaction with a tampered signature', async () => {
		const emisor = 'medico-a' as NodoId;
		const sujeto = 'medico-b' as NodoId;
		kernel.karma.registrarClavePublica(emisor, kernel.identity.exportarPublico());

		const tx = await kernel.karma.emit({
			tipo: 'avalo',
			proyecto: 'maloca',
			sujeto,
			delta: 20,
			razon: 'legit endorsement',
			emisor: nodoId,
		});

		// Someone lifts the real signature onto a transaction awarding far more karma.
		const txAlterada = {
			...tx,
			id: 'tx-falsa-1',
			sujeto,
			delta: 24,
		} as TransaccionKarma;

		const motivo = await kernel.karma.aplicarTransaccion(txAlterada);
		expect(motivo).toBe('firma_invalida');
		// The tampered copy did not leak into the score.
		expect(kernel.karma.getScore(sujeto)).toBe(20);
	});

	it('should reject a transaction signed by the wrong key', async () => {
		const emisor = 'medico-a' as NodoId;
		const sujeto = 'medico-b' as NodoId;
		// Register a key that does NOT match the one that produced the signature.
		kernel.karma.registrarClavePublica(emisor, generateKeypair('maestra').parPublico);

		const tx = await kernel.karma.emit({
			tipo: 'avalo',
			proyecto: 'maloca',
			sujeto,
			delta: 20,
			razon: 'signed by node A',
			emisor: nodoId,
		});

		const motivo = await kernel.karma.aplicarTransaccion({
			...tx,
			id: 'tx-llave-erronea-1',
			emisor,
		} as TransaccionKarma);

		expect(motivo).toBe('firma_invalida');
		expect(kernel.karma.getScore(sujeto)).toBe(20); // only the original, valid one counted
	});

	it('should reject an endorsement from an unknown issuer', async () => {
		const motivo = await kernel.karma.aplicarTransaccion({
			tipo: 'avalo',
			proyecto: 'maloca',
			sujeto: 'medico-b' as NodoId,
			delta: 20,
			razon: 'who am I?',
			emisor: 'nodo-fantasma' as NodoId,
			id: 'tx-desconocido-1',
			timestamp: Date.now(),
			firma: new Uint8Array([1, 2, 3]),
		});

		expect(motivo).toBe('emisor_desconocido');
		expect(kernel.karma.getScore('medico-b' as NodoId)).toBe(0);
	});

	// ─── ATTACK: replay ───────────────────────────────────────────────────

	it('should not count the same transaction twice when replayed', async () => {
		const otro = 'medico-b' as NodoId;

		const tx = await kernel.karma.emit({
			tipo: 'avalo',
			proyecto: 'maloca',
			sujeto: otro,
			delta: 10,
			razon: 'once',
			emisor: nodoId,
		});

		await kernel.karma.aplicarTransaccion(tx);
		await kernel.karma.aplicarTransaccion(tx);

		expect(kernel.karma.getScore(otro)).toBe(10);
		expect(kernel.karma.getHistory(otro)).toHaveLength(1);
	});

	it('should survive a reload from the OpLog without double counting', async () => {
		const otro = 'medico-b' as NodoId;

		await kernel.karma.emit({
			tipo: 'avalo',
			proyecto: 'maloca',
			sujeto: otro,
			delta: 10,
			razon: 'persisted',
			emisor: nodoId,
		});

		await kernel.karma.loadFromOpLog();

		expect(kernel.karma.getScore(otro)).toBe(10);
		expect(kernel.karma.getHistory(otro)).toHaveLength(1);
	});

	// ─── DECAY ────────────────────────────────────────────────────────────

	it('should let an idle node lose reputation over repeated decay', async () => {
		const otro = 'medico-b' as NodoId;

		for (let i = 0; i < 4; i++) {
			await kernel.karma.emit({
				tipo: 'avalo',
				proyecto: 'maloca',
				sujeto: otro,
				delta: 25,
				razon: 'endorsement',
				emisor: nodoId,
			});
		}
		expect(kernel.karma.getScore(otro)).toBe(100);

		// Stops being endorsed: standing fades instead of lasting forever.
		for (let i = 0; i < 10; i++) {
			await kernel.karma.applyDecay(otro, 0.5);
		}

		expect(kernel.karma.getScore(otro)).toBeLessThan(1);
		expect(kernel.karma.getScore(otro)).toBeGreaterThanOrEqual(0);
	});

	it('should ignore an out-of-range decay factor instead of corrupting the score', async () => {
		const otro = 'medico-b' as NodoId;

		await kernel.karma.emit({
			tipo: 'avalo',
			proyecto: 'maloca',
			sujeto: otro,
			delta: 20,
			razon: 'endorsement',
			emisor: nodoId,
		});

		await kernel.karma.applyDecay(otro, 0);
		await kernel.karma.applyDecay(otro, -5);
		await kernel.karma.applyDecay(otro, Number.NaN);

		expect(kernel.karma.getScore(otro)).toBe(20);
	});

	it('should decay per-project weights together with the total', async () => {
		const otro = 'medico-b' as NodoId;

		await kernel.karma.emit({
			tipo: 'avalo',
			proyecto: 'clinica-norte',
			sujeto: otro,
			delta: 20,
			razon: 'endorsement',
			emisor: nodoId,
		});

		await kernel.karma.applyDecay(otro, 0.5);

		expect(kernel.karma.getScore(otro)).toBe(10);
		expect(kernel.karma.getBestPeer()).toBe(otro);
	});
});