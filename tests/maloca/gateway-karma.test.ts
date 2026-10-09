import { beforeEach, describe, expect, it } from 'vitest';
import { createPostQuantumIdentity, generateKeypair, TIPO_IDENTIDAD } from '../../src/identity/index.js';
import { MalocaGatewayAPI } from '../../src/maloca/gateway/api.js';
import { MalocaKernel } from '../../src/maloca/kernel.js';
import type { NodoId } from '../../src/types/index.js';

/**
* Deterministic stringification for the signed payload. Must match KarmaManager's
* `canonicalStringify` exactly, or the signature will never verify.
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
* Regression tests for the removed SECOND karma engine in the HTTP gateway.
*
* The gateway used to recompute reputation from `yjsAdapter.getArray('maloca:karma:txs')`
* starting at a hardcoded base of 100, ignoring KarmaManager and verifying no signature.
* That made a brand-new node report 100 karma / "newcomer" with zero backing history.
*
* The gateway must now READ the real engine (MalocaKernel.karma) and report 0 /
* "unrated" for a node with no validated history.
*/
describe('Gateway API reads the real karma engine', () => {
	let kernel: MalocaKernel;
	let api: MalocaGatewayAPI;
	let selfId: NodoId;
	const PEER = 'peer-nodo-verificado' as NodoId;
	let identidadPeer: ReturnType<typeof createPostQuantumIdentity>;

	beforeEach(async () => {
		const kp = generateKeypair('maestra');

		kernel = new MalocaKernel({
			nodoId: 'test-node' as NodoId,
			storageBackend: 'mem',
			identitySecret: kp.parPrivado,
		});
		await kernel.iniciar();

		selfId = kernel.config.nodoId as NodoId;
		api = new MalocaGatewayAPI(kernel);

		// A real ML-DSA identity for the peer, so its endorsements carry a signature that verifies.
		identidadPeer = createPostQuantumIdentity(PEER, {
			...generateKeypair('maestra'),
			tipo: TIPO_IDENTIDAD.MAESTRA,
		});

		// KarmaManager refuses any endorsement from a node whose public key it has never seen, and
		// caps a single delta at DELTA_MAX_ABS so one peer cannot move a score across a band alone.
		// Both rules are the point of the fix, so the fixture registers a real peer identity and the
		// tests below work inside the cap rather than around it.
		kernel.karma.registrarClavePublica(PEER, identidadPeer.exportarPublico());
	});

	/**
	* A remote endorsement, signed by a real peer identity.
	*
	* `KarmaManager.emit()` signs with the KERNEL's own identity, so it can only ever produce a
	* self-signed endorsement. A peer vouching for someone else has to sign its own payload and hand
	* the transaction to `aplicarTransaccion()`, which is the entry point replication uses. The
	* explicit `id` also keeps each call a distinct transaction, which idempotency requires.
	*/
	const aval = async (delta: number, id: string) => {
		const cuerpo = {
			tipo: 'contribution',
			proyecto: 'maloca',
			sujeto: selfId,
			delta,
			razon: 'verified contribution',
			emisor: PEER,
		};
		const payload = { ...cuerpo, id, timestamp: Date.now() };
		const firma = await identidadPeer.firmar(new TextEncoder().encode(canonicalTestPayload(payload)));
		const motivo = await kernel.karma.aplicarTransaccion({ ...cuerpo, id, timestamp: payload.timestamp, firma });
		expect(motivo).toBeNull();
	};

	it('reports 0 for a node with no karma history (no free base-100 score)', async () => {
		const stranger = 'nodo-sin-historial' as NodoId;

		const result = await api.getKarma(stranger);

		expect(result.karma).toBe(0);
		expect(result.reputacion).toBe('unrated');
	});

	it('reflects the exact score computed by KarmaManager', async () => {
		await aval(20, 'tx-gateway-exacta');

		const result = await api.getKarma(selfId);

		// The gateway value must equal the engine value, not a re-derived approximation.
		expect(result.karma).toBe(kernel.karma.getScore(selfId));
		expect(result.karma).toBe(20);
		expect(result.reputacion).toBe('newcomer');
	});

	it('ignores the unsigned Yjs karma log that the old engine read', async () => {
		// This is the array the defective implementation summed over.
		kernel.yjsAdapter
			.getArray('maloca:karma:txs')
			.push([{ from: 'atacante', to: 'nodo-victima', amount: 5000, timestamp: Date.now() }]);

		const result = await api.getKarma('nodo-victima');

		// A forged unsigned entry must not inflate reputation to "legendary".
		expect(result.karma).toBe(0);
		expect(result.reputacion).toBe('unrated');
	});

	it('does not let POST /karma/emit affect the reputation score', async () => {
		await api.emitKarma({ to: selfId, amount: 900, reason: 'unsigned self-report' });

		const result = await api.getKarma(selfId);

		expect(result.karma).toBe(0);
		expect(result.reputacion).toBe('unrated');
	});

	it('maps engine scores to bands without an unearned newcomer floor', async () => {
		// Each endorsement is capped at DELTA_MAX_ABS (25) on purpose: one peer must not be able to
		// move a score across a band alone. Reaching a high band therefore means accumulating many
		// separate endorsements, which is the property the medical mesh needs. Each `aval` call gets a
		// distinct transaction id so idempotency does not collapse them.
		const many = async (delta: number, veces: number, prefijo: string) => {
			for (let i = 0; i < veces; i++) await aval(delta, `${prefijo}-${i}`);
		};

		await many(20, 6, 'banda-member');
		expect((await api.getKarma(selfId)).reputacion).toBe('member');

		await many(20, 20, 'banda-trusted');
		expect((await api.getKarma(selfId)).reputacion).toBe('trusted');

		await many(20, 60, 'banda-legendary');
		expect((await api.getKarma(selfId)).reputacion).toBe('legendary');
		// 86 endorsements, each one a real ML-DSA-65 signature. Post-quantum signing is not cheap, and
		// the suite grew past the point where this fit inside the default 5 s budget. Scoped here rather
		// than by raising the global timeout, which would only hide slow tests elsewhere.
	}, 20_000);

	it('flags that reputation never grants access (medical mesh invariant)', async () => {
		const result = await api.getKarma(selfId);

		expect(result.autorizaAcceso).toBe(false);
	});

	it('returns 0 when no karma engine is attached to the mesh', async () => {
		const { EdgeMesh } = await import('../../src/edge-mesh.js');
		const bareMesh = new EdgeMesh({
			nodoId: 'bare-node' as NodoId,
			storageBackend: 'mem',
		});
		const bareApi = new MalocaGatewayAPI(bareMesh);

		const result = await bareApi.getKarma('cualquiera');

		expect(result.karma).toBe(0);
		expect(result.reputacion).toBe('unrated');
	});

	it('surfaces engine karma through the profile endpoint', async () => {
		const stranger = 'nodo-sin-perfil' as NodoId;

		const profile = await api.getProfile(stranger);

		expect(profile.karma).toBe(0);
	});
});