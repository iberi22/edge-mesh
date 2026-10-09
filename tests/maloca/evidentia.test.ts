import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EdgeMesh } from '../../src/edge-mesh.js';
import { createPostQuantumIdentity, generateKeypair } from '../../src/identity/index.js';
import { EvidentiaManager } from '../../src/maloca/evidentia.js';
import { MeshManager } from '../../src/mesh/index.js';
import type { NodoId } from '../../src/types/index.js';

// Mock global crypto for environment where it might be missing
if (global.crypto === undefined) {
	const { crypto } = await import('node:crypto');
	// @ts-expect-error
	global.crypto = crypto;
}

const nodoId = 'nodo-test' as NodoId;
const nodoExterno = 'medico-verificado' as NodoId;
const nodoIntruso = 'nodo-intruso' as NodoId;

/** Corrupt a hex string by flipping one nibble, keeping it valid hex. */
function corromperHex(hex: string): string {
	const primer = hex.charAt(0);
	return (primer === 'a' ? 'b' : 'a') + hex.slice(1);
}

describe('EvidentiaManager', () => {
	let mesh: MeshManager;
	let identity: ReturnType<typeof createPostQuantumIdentity>;
	let manager: EvidentiaManager;

	beforeEach(() => {
		mesh = new MeshManager({ nodoId }, {} as EdgeMesh);
		vi.spyOn(mesh, 'transmitirConGossip').mockResolvedValue(undefined);

		// Real ML-DSA-65 keypair: verification is no longer mocked, so the
		// signature must be cryptographically genuine.
		identity = createPostQuantumIdentity(nodoId, generateKeypair());

		manager = new EvidentiaManager(identity, mesh);
	});

	it('debería notarizar contenido', async () => {
		const contenido = { docId: 'd1', texto: 'Hola Maloca' };
		const evidentia = await manager.notarize(contenido, 'CHAT_MESSAGE');

		expect(evidentia.hash).toBeDefined();
		expect(evidentia.contenidoHash).toBeDefined();
		expect(evidentia.emisor).toBe(nodoId);
		expect(evidentia.firmaPQC).toBeDefined();
		expect(evidentia.tipo).toBe('CHAT_MESSAGE');
	});

	it('debería recuperar una prueba de notarización', async () => {
		const { hash } = await manager.notarize({ foo: 'bar' }, 'TEST');

		const proof = manager.getProof(hash);
		expect(proof).not.toBeNull();
		expect(proof?.hash).toBe(hash);
	});

	// ─── PROVENANCE ─────────────────────────────────────────────────────────

	describe('procedencia', () => {
		it('expone fecha, emisor y qué respalda la evidencia', async () => {
			const ev = await manager.notarize({ docId: 'vac-1' }, 'MEDICAL_CREDENTIAL', {
				queRespalda: 'Certificado de vacunación contra la fiebre amarilla',
				descripcionEmisor: 'Dra. Maria Lopez, licencia MED-1234',
				referencia: 'registro-medsalud://vac-1',
			});

			expect(ev.procedencia.emisor).toBe(nodoId);
			expect(ev.procedencia.queRespalda).toBe('Certificado de vacunación contra la fiebre amarilla');
			expect(ev.procedencia.descripcionEmisor).toContain('licencia MED-1234');
			expect(ev.procedencia.referencia).toBe('registro-medsalud://vac-1');
			expect(ev.procedencia.fechaEmision).toBeGreaterThan(0);
		});

		it('rechaza evidencia sin queRespalda', async () => {
			const ev = await manager.notarize({ docId: 'x' }, 'DOC', { queRespalda: '   ' });
			expect(await manager.verify(ev.hash)).toBe(false);
		});

		it('rechaza evidencia con procedencia fuera de la ventana temporal', async () => {
			const ev = await manager.notarize({ docId: 'x' }, 'DOC', {
				queRespalda: 'prueba clinica',
				fechaEmision: Date.now() - 10 * 60 * 1000,
			});
			expect(await manager.verify(ev.hash)).toBe(false);
		});

		it('rechaza evidencia cuya procedencia declara otro emisor', async () => {
			const ev = await manager.notarize({ docId: 'x' }, 'DOC', { queRespalda: 'prueba' });
			const suplantada = { ...ev, procedencia: { ...ev.procedencia, emisor: nodoIntruso } };
			expect((await manager.verificarEvidentia(suplantada)).valido).toBe(false);
		});
	});

	// ─── VERIFICACIÓN REAL DE FIRMA ─────────────────────────────────────────

	describe('verify() — real ML-DSA-65 verification', () => {
		it('acepta evidencia con firma válida', async () => {
			const ev = await manager.notarize({ docId: 'd1' }, 'MEDICAL_CREDENTIAL', {
				queRespalda: 'Titulo profesional verificado',
			});
			expect(await manager.verify(ev.hash)).toBe(true);
		});

		it('acepta evidencia con firma válida emitida por un nodo externo registrado', async () => {
			const identidadMedico = createPostQuantumIdentity(nodoExterno, generateKeypair());
			const redMedica = new EvidentiaManager(identidadMedico, mesh);
			// Trusted out-of-band roster entry (identity handshake / admin list).
			manager.registrarEmisor(nodoExterno, identidadMedico.exportarPublico());

			const ev = await redMedica.notarize({ registro: 'vac-42' }, 'MEDICAL_CREDENTIAL', {
				queRespalda: 'Historia clinica del paciente 42',
			});

			// Proof travels the mesh, issuer key is already known locally.
			const res = await manager.verificarEvidentia(ev);
			expect(res.motivo).toBe('ok');
			expect(res.valido).toBe(true);
		});

		it('rechaza evidencia con firma corrupta', async () => {
			const ev = await manager.notarize({ docId: 'd1' }, 'DOC', { queRespalda: 'algo' });
			const corrupta = { ...ev, firmaPQC: corromperHex(ev.firmaPQC) };

			const res = await manager.verificarEvidentia(corrupta);
			expect(res.valido).toBe(false);
			expect(res.motivo).toBe('hash inconsistente');
		});

		it('rechaza evidencia con firma corrupta aunque el hash se recalcule', async () => {
			// A peer recomputes the record id after tampering: only the real
			// signature check can catch this.
			const ev = await manager.notarize({ docId: 'd1' }, 'DOC', { queRespalda: 'algo' });
			const firmaCorrupta = corromperHex(ev.firmaPQC);
			const digest = await crypto.subtle.digest(
				'SHA-256',
				new TextEncoder().encode(`${ev.contenidoHash}${firmaCorrupta}${ev.emisor}`),
			);
			const rehashed = {
				...ev,
				firmaPQC: firmaCorrupta,
				hash: Array.from(new Uint8Array(digest))
					.map((b) => b.toString(16).padStart(2, '0'))
					.join(''),
			};

			const res = await manager.verificarEvidentia(rehashed);
			expect(res.valido).toBe(false);
			expect(res.motivo).toBe('firma PQC invalida');
		});

		it('rechaza evidencia con contenido alterado', async () => {
			const ev = await manager.notarize({ docId: 'd1', dosis: 1 }, 'MEDICAL_CREDENTIAL', {
				queRespalda: 'Dosis aplicada',
			});
			const alterada = { ...ev, contenidoHash: 'f'.repeat(64) };

			expect((await manager.verificarEvidentia(alterada)).valido).toBe(false);
		});

		it('rechaza evidencia con tipo alterado', async () => {
			const ev = await manager.notarize({ docId: 'd1' }, 'DOC', { queRespalda: 'algo' });
			const alterada = { ...ev, tipo: 'MEDICAL_LICENCE' };

			expect((await manager.verificarEvidentia(alterada)).valido).toBe(false);
		});

		it('rechaza evidencia con pubkey del emisor ausente', async () => {
			// The evidence carries NO public key field at all, and the issuer was
			// never registered: there is nothing to verify against.
			const identidadMedico = createPostQuantumIdentity(nodoExterno, generateKeypair());
			const redMedica = new EvidentiaManager(identidadMedico, mesh);
			const ev = await redMedica.notarize({ registro: 'vac-42' }, 'MEDICAL_CREDENTIAL', {
				queRespalda: 'Historia clinica',
			});

			expect(ev).not.toHaveProperty('parPublico');
			expect(manager.clavePublicaDe(nodoExterno)).toBeUndefined();

			const res = await manager.verificarEvidentia(ev);
			expect(res.valido).toBe(false);
			expect(res.motivo).toBe('pubkey del emisor no registrada');
		});

		it('rechaza evidencia cuya pubkey registrada no corresponde al emisor', async () => {
			const identidadMedico = createPostQuantumIdentity(nodoExterno, generateKeypair());
			const identidadIntruso = createPostQuantumIdentity(nodoIntruso, generateKeypair());
			const redMedica = new EvidentiaManager(identidadMedico, mesh);
			const ev = await redMedica.notarize({ registro: 'vac-42' }, 'MEDICAL_CREDENTIAL', {
				queRespalda: 'Historia clinica',
			});

			// Registry poisoned: the intruder key is filed under the honest doctor id.
			manager.registrarEmisor(nodoExterno, identidadIntruso.exportarPublico());

			const res = await manager.verificarEvidentia(ev);
			expect(res.valido).toBe(false);
			expect(res.motivo).toBe('firma PQC invalida');
		});

		it('rechaza evidencia sin firma', async () => {
			const ev = await manager.notarize({ docId: 'd1' }, 'DOC', { queRespalda: 'algo' });
			const sinFirma = { ...ev, firmaPQC: '' };

			const res = await manager.verificarEvidentia(sinFirma);
			expect(res.valido).toBe(false);
			expect(res.motivo).toBe('firma ausente');
		});

		it('rechaza evidencia sin procedencia', async () => {
			const ev = await manager.notarize({ docId: 'd1' }, 'DOC', { queRespalda: 'algo' });
			const sinProcedencia = { ...ev, procedencia: undefined } as unknown as typeof ev;

			const res = await manager.verificarEvidentia(sinProcedencia);
			expect(res.valido).toBe(false);
			expect(res.motivo).toBe('procedencia ausente');
		});

		it('devuelve false para un hash desconocido', async () => {
			expect(await manager.verify('hash-inexistente')).toBe(false);
		});

		it('verify() rechaza y reporta el motivo cuando la evidencia local falla', async () => {
			// The local store holds only genuine notarizations, so a locally issued
			// evidence always verifies; the rejection path is exercised with a
			// proof whose issuer key this node does not know.
			const ev = await manager.notarize({ docId: 'd1' }, 'DOC', { queRespalda: 'algo' });
			expect(await manager.verify(ev.hash)).toBe(true);

			const identidadMedico = createPostQuantumIdentity(nodoExterno, generateKeypair());
			const redMedica = new EvidentiaManager(identidadMedico, mesh);
			const ajena = await redMedica.notarize({ registro: 'r1' }, 'DOC', { queRespalda: 'prueba' });

			// Feed the foreign proof into the local store through the gossip path:
			// verificarEvidentia is the entry point callers use for remote proofs.
			const res = await manager.verificarEvidentia(ajena);
			expect(res.valido).toBe(false);
			expect(res.motivo).toBe('pubkey del emisor no registrada');
			expect(await manager.verify(ajena.hash)).toBe(false);
		});
	});

	it('emite el evento notarizacionCreada', async () => {
		const eventos: unknown[] = [];
		manager.addEventListener('notarizacionCreada', (e) => {
			eventos.push((e as CustomEvent).detail);
		});

		await manager.notarize({ docId: 'd1' }, 'DOC', { queRespalda: 'algo' });
		expect(eventos).toHaveLength(1);
	});
});