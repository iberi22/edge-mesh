import { beforeEach, describe, expect, it } from 'vitest';
import { createPostQuantumIdentity, generateKeypair, type PostQuantumIdentity } from '../../src/identity/index.js';
import { KarmaManager } from '../../src/maloca/karma.js';
import type { TransaccionKarma } from '../../src/maloca/types.js';
import {
	type DetalleDivergenciaKarma,
	MAX_DIVERGENCIAS_REGISTRADAS,
	MeshManager,
	PAYLOAD_KARMA_TIPO,
} from '../../src/mesh/index.js';
import { OpLog } from '../../src/op-log/index.js';
import { InMemoryStorage } from '../../src/storage/index.js';
import type { NodoId, ParPublico } from '../../src/types/index.js';

/**
* REPUTATION DIVERGENCE DETECTION TESTS.
*
* The defect these pin down: `procesarGossip` routed a remote endorsement into
* `KarmaManager.aplicarTransaccion` and moved on. The score corrected itself
* correctly, so nothing was broken — but SILENTLY. If node B was offline while
* node A received an endorsement of physician C, then for that whole window B
* was displaying a different reputation for C than every peer in the network,
* and neither node, nor any operator, had any way to learn it. A node that was
* behind looked identical to a node that was current.
*
* Accepted cost, visible defect. The owner decided reputation divergence is a
* valid v1 cost PROVIDED it stops being invisible, so the requirement here is
* detection and nothing more:
*
*   1. when a remote endorsement MOVES a local score, `karmaDivergente` fires
*      naming the subject, the stale score, the new one and the endorsement;
*   2. it fires for the node that was OFFLINE and is catching up — the case that
*      motivates the whole mechanism;
*   3. it does NOT fire for gossip that carries no disagreement, so a single
*      event actually means "the network disagreed with me" and an operator can
*      alert on it;
*   4. nothing is reconciled: no OpLog write, no retraction, no rewriting. A
*      node that has fallen behind must stay behind until the (separately
*      designed) reconciliation phase catches it up.
*
* Determinism is asserted explicitly: the same endorsements in the same order
* produce the same events every time, and the classification is read off the
* score transition itself rather than from any threshold, clock or window.
*/

/** Mirror of KarmaManager's canonical stringify, so a peer can sign exact bytes. */
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

/** Signs a transaction the way KarmaManager.emit does, from an external identity. */
async function firmarComoEmisor(
	identidad: PostQuantumIdentity,
	datos: Omit<TransaccionKarma, 'firma'>,
): Promise<TransaccionKarma> {
	const payload = canonicalTestPayload(datos);
	const firma = await identidad.firmar(new TextEncoder().encode(payload));
	return { ...datos, firma };
}

interface NodoPrueba {
	readonly mesh: MeshManager;
	readonly karma: KarmaManager;
	readonly oplog: OpLog;
	readonly identidad: PostQuantumIdentity;
	readonly edgeMesh: {
		on: () => void;
		off: () => void;
		enviar: () => Promise<void>;
		obtenerClavePublica: (id: NodoId) => ParPublico | undefined;
	};
}

async function crearNodo(nodoId: NodoId, clavesConocidas: Map<NodoId, ParPublico>): Promise<NodoPrueba> {
	const identidad = createPostQuantumIdentity(nodoId, generateKeypair('maestra'));
	clavesConocidas.set(nodoId, identidad.exportarPublico());

	const oplog = new OpLog({ docId: `maloca_karma:${nodoId}`, storage: new InMemoryStorage() });
	const karma = new KarmaManager(oplog, identidad, (id) => clavesConocidas.get(id));

	const edgeMesh = {
		on: () => {},
		off: () => {},
		enviar: async () => {},
		obtenerClavePublica: (id: NodoId) => clavesConocidas.get(id),
	};

	const mesh = new MeshManager({ nodoId }, edgeMesh as never, karma);
	await mesh.iniciar();
	return { mesh, karma, oplog, identidad, edgeMesh };
}

/** Wraps a transaction in the wire shape the mesh gossips, as JSON. */
function gossipDeKarma(tx: unknown, desde: NodoId, id: string, ttl = 5) {
	return {
		id,
		namespace: 'global',
		ttl,
		payload: { tipo: PAYLOAD_KARMA_TIPO, tx },
		origen: desde,
		timestamp: Date.now(),
		ruta: [desde],
	};
}

/** A transaction as it survives a JSON round-trip (signature becomes numbers). */
function serializar(tx: TransaccionKarma): unknown {
	return JSON.parse(JSON.stringify({ ...tx, firma: Array.from(tx.firma) }));
}

/** Collects every `karmaDivergente` a node emits, for assertions. */
function observarDivergencias(mesh: MeshManager): DetalleDivergenciaKarma[] {
	const vistas: DetalleDivergenciaKarma[] = [];
	mesh.addEventListener('karmaDivergente', (ev) => {
		vistas.push((ev as CustomEvent<DetalleDivergenciaKarma>).detail);
	});
	return vistas;
}

describe('reputation divergence detection', () => {
	let clavesConocidas: Map<NodoId, ParPublico>;
	let nodoA: NodoPrueba;
	let nodoB: NodoPrueba;

	const A = 'medico-a' as NodoId;
	const B = 'medico-b' as NodoId;
	const C = 'medico-c' as NodoId;

	beforeEach(async () => {
		clavesConocidas = new Map();
		nodoA = await crearNodo(A, clavesConocidas);
		nodoB = await crearNodo(B, clavesConocidas);
	});

	it('emite karmaDivergente cuando un aval remoto mueve un score que diferia del local', async () => {
		const divergencias = observarDivergencias(nodoB.mesh);

		// Both nodes agree to begin with: neither knows the endorsement.
		expect(nodoA.karma.getScore(C)).toBe(0);
		expect(nodoB.karma.getScore(C)).toBe(0);
		expect(divergencias).toHaveLength(0);

		const tx = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-llegada`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 12,
			razon: 'revalidó 3 resúmenes de alta',
			emisor: A,
			timestamp: Date.now(),
		});

		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-llegada'));
		await nodoB.mesh.esperarPropagacionKarma();

		// The endorsement is applied exactly as before: the engine's verdict, unchanged.
		expect(nodoB.karma.getScore(C)).toBe(12);

		// And now the fact that B was displaying 0 while A displayed 12 is on record.
		expect(divergencias).toHaveLength(1);
		expect(divergencias[0]).toEqual({
			sujeto: C,
			txId: `${A}:tx-llegada`,
			emisor: A,
			desde: A,
			delta: 12,
			scoreLocalAntes: 0,
			scoreLocalDespues: 12,
			motivo: 'aval_tardio',
		});

		// The record is also readable after the fact, for an operator who was not
		// listening live. An event alone would let divergence vanish at the exact
		// moment it mattered.
		expect(nodoB.mesh.obtenerDivergencias()).toEqual(divergencias);
	});

	it('detecta la divergencia en el nodo que estuvo offline y recibe el aval al reconectarse', async () => {
		const divergenciasA = observarDivergencias(nodoA.mesh);
		const divergenciasB = observarDivergencias(nodoB.mesh);

		// ── PHASE 1: A receives the endorsement; B is offline and misses it entirely.
		const tx = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-offline`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 18,
			razon: 'aval emitido mientras B estaba desconectado',
			emisor: A,
			timestamp: Date.now(),
		});
		// Applied on A through the local engine, exactly as a node that was online
		// would have done it.
		await nodoA.karma.aplicarTransaccion(tx);
		expect(nodoA.karma.getScore(C)).toBe(18);

		// The divergence is REAL now, and invisible: A says 18, B says 0, and no
		// event has fired on either node because neither has seen the other's view.
		expect(nodoB.karma.getScore(C)).toBe(0);
		expect(divergenciasA).toHaveLength(0);
		expect(divergenciasB).toHaveLength(0);
		expect(nodoB.mesh.obtenerDivergencias()).toHaveLength(0);

		// ── PHASE 2: B reconnects and the gossip finally reaches it.
		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-reconexion'));
		await nodoB.mesh.esperarPropagacionKarma();

		// The two nodes now converge on the score: same set of endorsements.
		expect(nodoA.karma.getScore(C)).toBe(18);
		expect(nodoB.karma.getScore(C)).toBe(18);

		// And B KNOWS it was wrong while it held 0. This is the assertion that makes
		// the mechanism worth its cost: the node that fell behind is the one that
		// reports it, with the figure it had been showing.
		expect(divergenciasB).toHaveLength(1);
		expect(divergenciasB[0].sujeto).toBe(C);
		expect(divergenciasB[0].scoreLocalAntes).toBe(0);
		expect(divergenciasB[0].scoreLocalDespues).toBe(18);
		expect(divergenciasB[0].txId).toBe(`${A}:tx-offline`);
		expect(divergenciasB[0].motivo).toBe('aval_tardio');

		// A, which was never behind, reports nothing. Divergence is attributed to the
		// node that was actually wrong, not broadcast as a general alarm.
		expect(divergenciasA).toHaveLength(0);
	});

	it('no emite divergencia en gossip normal, para que el evento signifique algo', async () => {
		const divergenciasB = observarDivergencias(nodoB.mesh);

		// Case 1: a payload that is not an endorsement at all (maloca, discovery).
		nodoB.mesh.procesarGossip(gossipDeKarma({ tipo: 'PROFILE_CREATED', payload: {} }, A, 'gossip-otro-1'));
		// Case 2: a malformed endorsement — refused before the engine sees it.
		nodoB.mesh.procesarGossip(
			gossipDeKarma({ tipo: PAYLOAD_KARMA_TIPO, tx: { id: 'x', emisor: A, sujeto: C, delta: 5 } }, A, 'gossip-roto-1'),
		);
		// Case 3: a signed endorsement with an unknown issuer — refused, so it can
		// never move a score and therefore cannot be divergence.
		const txDesconocido = await firmarComoEmisor(
			createPostQuantumIdentity('fantasma' as NodoId, generateKeypair('maestra')),
			{
				id: 'fantasma:tx',
				tipo: 'contribution',
				proyecto: 'maloca-medico',
				sujeto: C,
				delta: 30,
				razon: 'aval de un emisor que B no conoce',
				emisor: 'fantasma' as NodoId,
				timestamp: Date.now(),
			},
		);
		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(txDesconocido), 'fantasma' as NodoId, 'gossip-desconocido-1'));
		// Case 4: an oversized delta — refused by the ceiling rule.
		const txExcesivo = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-excesivo`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 1_000,
			razon: 'delta fuera de techo',
			emisor: A,
			timestamp: Date.now(),
		});
		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(txExcesivo), A, 'gossip-excesivo-1'));

		await nodoB.mesh.esperarPropagacionKarma();

		// Nothing moved, so nothing diverged. Silence here is the contract that makes
		// the event trustworthy enough to alert on.
		expect(nodoB.karma.getScore(C)).toBe(0);
		expect(divergenciasB).toHaveLength(0);
		expect(nodoB.mesh.obtenerDivergencias()).toHaveLength(0);
	});

	it('no reporta divergencia por la redelivery de un aval ya aplicado', async () => {
		const divergenciasB = observarDivergencias(nodoB.mesh);

		const tx = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-redelivery`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 9,
			razon: 'aval que el gossip reenvia varias veces',
			emisor: A,
			timestamp: Date.now(),
		});

		const envelope = serializar(tx);
		nodoB.mesh.procesarGossip(gossipDeKarma(envelope, A, 'gossip-redelivery-1'));
		await nodoB.mesh.esperarPropagacionKarma();

		// First delivery: the score moved from 0, so B was stale. Reported once.
		expect(divergenciasB).toHaveLength(1);
		expect(nodoB.karma.getScore(C)).toBe(9);

		// Re-broadcast hops re-send the same payload under new gossip ids. The score
		// does not move, so there is no disagreement to report: a redelivery is not
		// divergence, and counting it as such would turn a working gossip mesh into a
		// stream of false alarms.
		nodoB.mesh.procesarGossip(gossipDeKarma(envelope, A, 'gossip-redelivery-2'));
		nodoB.mesh.procesarGossip(gossipDeKarma(envelope, A, 'gossip-redelivery-3'));
		await nodoB.mesh.esperarPropagacionKarma();

		expect(divergenciasB).toHaveLength(1);
		expect(nodoB.karma.getScore(C)).toBe(9);
		expect(nodoB.mesh.obtenerDivergencias()).toHaveLength(1);
	});

	it('es determinista: el mismo conjunto de avales en el mismo orden da los mismos eventos', async () => {
		// Two independent nodes start from identical state and receive an identical
		// endorsement sequence. Both must converge on the same score AND report the
		// same divergences in the same order — no clock, no random threshold, no
		// dependence on which peer happened to relay first.
		const nodoD = await crearNodo('medico-d' as NodoId, clavesConocidas);
		const divergenciasB = observarDivergencias(nodoB.mesh);
		const divergenciasD = observarDivergencias(nodoD.mesh);

		const txs = await Promise.all([
			firmarComoEmisor(nodoA.identidad, {
				id: `${A}:tx-det-1`,
				tipo: 'contribution',
				proyecto: 'maloca-medico',
				sujeto: C,
				delta: 10,
				razon: 'primero',
				emisor: A,
				timestamp: 1_000,
			}),
			firmarComoEmisor(nodoA.identidad, {
				id: `${A}:tx-det-2`,
				tipo: 'contribution',
				proyecto: 'maloca-medico',
				sujeto: C,
				delta: 4,
				razon: 'segundo',
				emisor: A,
				timestamp: 2_000,
			}),
			firmarComoEmisor(nodoA.identidad, {
				id: `${A}:tx-det-3`,
				tipo: 'contribution',
				proyecto: 'maloca-medico',
				sujeto: C,
				delta: 6,
				razon: 'tercero',
				emisor: A,
				timestamp: 3_000,
			}),
		]);

		for (const [i, tx] of txs.entries()) {
			const payload = serializar(tx);
			nodoB.mesh.procesarGossip(gossipDeKarma(payload, A, `gossip-det-b-${i}`));
			nodoD.mesh.procesarGossip(gossipDeKarma(payload, A, `gossip-det-d-${i}`));
		}
		await Promise.all([nodoB.mesh.esperarPropagacionKarma(), nodoD.mesh.esperarPropagacionKarma()]);

		expect(nodoB.karma.getScore(C)).toBe(20);
		expect(nodoD.karma.getScore(C)).toBe(nodoB.karma.getScore(C));

		// Every arrival moved a score that the node had not seen catch up, so every
		// arrival is reported — in arrival order, identically on both nodes.
		expect(divergenciasB).toHaveLength(3);
		expect(divergenciasD).toEqual(divergenciasB);
		expect(divergenciasB.map((d) => d.scoreLocalAntes)).toEqual([0, 10, 14]);
		expect(divergenciasB.map((d) => d.scoreLocalDespues)).toEqual([10, 14, 20]);
		expect(divergenciasB.map((d) => d.txId)).toEqual([`${A}:tx-det-1`, `${A}:tx-det-2`, `${A}:tx-det-3`]);
	});

	it('NO reconcilia: la deteccion no escribe en el oplog ni corrige al peer que se quedo atras', async () => {
		const divergenciasB = observarDivergencias(nodoB.mesh);

		const tx = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-no-reconcilia`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 11,
			razon: 'aval que solo debe quedar REGISTRADO',
			emisor: A,
			timestamp: Date.now(),
		});

		const almacenAntes = await nodoB.oplog.obtenerTamanioStorage();
		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-no-reconcilia'));
		await nodoB.mesh.esperarPropagacionKarma();

		// The endorsement is applied to the score — KarmaManager owns that decision
		// and this layer must not second-guess it.
		expect(nodoB.karma.getScore(C)).toBe(11);
		expect(divergenciasB).toHaveLength(1);

		// But NOTHING was persisted. `procesarGossip` is a carrier: it must not write
		// to the OpLog, because a divergence record there would be the first step of
		// the reconciliation phase, which is explicitly out of scope here.
		expect(await nodoB.oplog.obtenerTamanioStorage()).toBe(almacenAntes);
		expect(await nodoB.oplog.obtenerTamanioStorage()).toBe(0);

		// Nor did it try to push anything back at A to make the peers agree.
		const enviados: unknown[] = [];
		nodoB.edgeMesh.enviar = async () => {
			enviados.push(1);
		};
		await nodoB.mesh.conectarPeer(A);
		await nodoB.mesh.iniciar();
		// Give the heartbeat/fan-out machinery a chance to send anything it wanted to.
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(enviados).toHaveLength(0);
	});

	// 261 real ML-DSA-65 signature verifications is genuinely slow (~6s), so the
	// bound is exercised with a raised timeout rather than a mocked engine.
	it('acota el registro de divergencias y expone una copia, no el estado interno', async () => {
		const divergenciasB = observarDivergencias(nodoB.mesh);

		// More arrivals than the bound. Every one moved a score, so every one is
		// reported live — the cap is on the RETAINED history, never on detection.
		const total = MAX_DIVERGENCIAS_REGISTRADAS + 5;
		for (let i = 0; i < total; i++) {
			const tx = await firmarComoEmisor(nodoA.identidad, {
				id: `${A}:tx-cap-${i}`,
				tipo: 'contribution',
				proyecto: 'maloca-medico',
				sujeto: C,
				delta: 1,
				razon: `aval ${i}`,
				emisor: A,
				timestamp: 1_000 + i,
			});
			nodoB.mesh.procesarGossip(gossipDeKarma(serializar(tx), A, `gossip-cap-${i}`));
		}
		await nodoB.mesh.esperarPropagacionKarma();

		expect(divergenciasB).toHaveLength(total);
		expect(nodoB.mesh.obtenerDivergencias()).toHaveLength(MAX_DIVERGENCIAS_REGISTRADAS);

		// The oldest were dropped, the newest kept: an unbounded tail fed by remote
		// peers is a memory-growth bug.
		const registradas = nodoB.mesh.obtenerDivergencias();
		expect(registradas[0].txId).toBe(`${A}:tx-cap-5`);
		expect(registradas[registradas.length - 1].txId).toBe(`${A}:tx-cap-${total - 1}`);

		// The accessor hands back a copy: a caller cannot mutate detection state.
		const copia = nodoB.mesh.obtenerDivergencias() as DetalleDivergenciaKarma[];
		copia.push(registradas[0]);
		expect(nodoB.mesh.obtenerDivergencias()).toHaveLength(MAX_DIVERGENCIAS_REGISTRADAS);
	}, 60_000);

	it('sin consumidor de karma no hay deteccion que hacer y nada se inventa', async () => {
		const identidad = createPostQuantumIdentity('sin-motor' as NodoId, generateKeypair('maestra'));
		const mesh = new MeshManager({ nodoId: 'sin-motor' as NodoId }, {
			on: () => {},
			off: () => {},
			enviar: async () => {},
		} as never);
		await mesh.iniciar();

		const divergencias = observarDivergencias(mesh);
		const tx = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-sin-motor`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 40,
			razon: 'deberia ignorarse por completo',
			emisor: A,
			timestamp: Date.now(),
		});

		mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-sin-motor'));
		await mesh.esperarPropagacionKarma();

		// A mesh with no karma engine has no score to be stale about, so it neither
		// applies anything nor invents a discrepancy.
		expect(divergencias).toHaveLength(0);
		expect(mesh.obtenerDivergencias()).toHaveLength(0);
		expect(identidad.nodoId).toBe('sin-motor');
		await mesh.detener();
	});
});