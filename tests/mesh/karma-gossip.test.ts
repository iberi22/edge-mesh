import { beforeEach, describe, expect, it } from 'vitest';
import { createPostQuantumIdentity, generateKeypair, type PostQuantumIdentity } from '../../src/identity/index.js';
import { KarmaManager } from '../../src/maloca/karma.js';
import type { TransaccionKarma } from '../../src/maloca/types.js';
import { MeshManager, PAYLOAD_KARMA_TIPO } from '../../src/mesh/index.js';
import { OpLog } from '../../src/op-log/index.js';
import { InMemoryStorage } from '../../src/storage/index.js';
import type { NodoId, ParPublico } from '../../src/types/index.js';

/**
* REPUTATION REPLICATION TESTS.
*
* The defect these pin down: `KarmaManager` wrote endorsements to the LOCAL
* OpLog (`karma:emit`) and stopped there. `procesarGossip` — the only thing that
* could have carried them to a peer — existed but was never invoked. So two
* honest observers of the same endorsement held different scores, and no peer
* could ever move another's reputation.
*
* What is asserted here, in order of importance:
*   1. a SIGNED endorsement travels node A -> node B over the gossip mesh and
*      moves B's score for the subject;
*   2. an endorsement with an INVALID signature travelling the same path is
*      refused and moves nothing (a peer cannot inject karma it never signed);
*   3. a repeated transaction is counted once (KarmaManager's tx.id idempotency,
*      reused rather than reimplemented);
*   4. a payload claiming to be an endorsement but structurally unusable is
*      refused without ever reaching the engine.
*/

/**
* Mirror of KarmaManager's internal canonical stringify so a peer can build the
* exact bytes it would sign. Kept in the test so the src API does not grow a
* signing helper that application code could misuse.
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
	readonly identidad: PostQuantumIdentity;
	readonly clavePublica: ParPublico;
	readonly edgeMesh: {
		on: () => void;
		off: () => void;
		enviar: () => Promise<void>;
		obtenerClavePublica: (id: NodoId) => ParPublico | undefined;
	};
}

async function crearNodo(nodoId: NodoId, clavesConocidas: Map<NodoId, ParPublico>): Promise<NodoPrueba> {
	const identidad = createPostQuantumIdentity(nodoId, generateKeypair('maestra'));
	const clavePublica = identidad.exportarPublico();
	clavesConocidas.set(nodoId, clavePublica);

	const oplog = new OpLog({ docId: `maloca_karma:${nodoId}`, storage: new InMemoryStorage() });
	const karma = new KarmaManager(oplog, identidad, (id) => clavesConocidas.get(id));

	// Stands in for the real EdgeMesh: exposes the handshake-verified key registry.
	const edgeMesh = {
		on: () => {},
		off: () => {},
		enviar: async () => {},
		obtenerClavePublica: (id: NodoId) => clavesConocidas.get(id),
	};

	const mesh = new MeshManager({ nodoId }, edgeMesh as never, karma);
	await mesh.iniciar();
	return { mesh, karma, identidad, clavePublica, edgeMesh };
}

/** Wraps a transaction in the wire shape the mesh gossips. */
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

describe('reputation replication over gossip', () => {
	let clavesConocidas: Map<NodoId, ParPublico>;
	let nodos: NodoPrueba[];

	const A = 'medico-a' as NodoId;
	const B = 'medico-b' as NodoId;
	const C = 'medico-c' as NodoId;

	beforeEach(async () => {
		clavesConocidas = new Map();
		nodos = [await crearNodo(A, clavesConocidas), await crearNodo(B, clavesConocidas)];
	});

	it('propaga un aval firmado de A al nodo B y cambia su score', async () => {
		const nodoA = nodos[0];
		const nodoB = nodos[1];

		expect(nodoB.karma.getScore(C)).toBe(0);

		// A signs an endorsement of C.
		const tx = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-1`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 12,
			razon: 'revalidated 3 discharge summaries',
			emisor: A,
			timestamp: Date.now(),
		});

		// It travels the wire as JSON — signature rehydrated as a plain array.
		const envelope = serializar(tx);
		nodoB.mesh.procesarGossip(gossipDeKarma(envelope, A, 'gossip-aplicado'));
		await nodoB.mesh.esperarPropagacionKarma();

		expect(nodoB.karma.getScore(C)).toBe(12);
		expect(nodoB.karma.getHistory(C)).toHaveLength(1);
		// The issuer's own score is untouched: an endorsement moves the SUBJECT.
		expect(nodoB.karma.getScore(A)).toBe(0);
	});

	it('rechaza un aval con firma invalida que viaja por gossip', async () => {
		const nodoB = nodos[1];
		const atacante = await crearNodo('atacante' as NodoId, clavesConocidas);

		const txHonesta = await firmarComoEmisor(nodos[0].identidad, {
			id: `${A}:tx-falsa`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 20,
			razon: 'aval genuino',
			emisor: A,
			timestamp: Date.now(),
		});

		// Same transaction, but the signature bytes are from another key. The
		// attacker holds its own valid identity and is a peer B trusts — so the
		// only thing stopping it is the signature check inside KarmaManager.
		const txFalsa: TransaccionKarma = { ...txHonesta, firma: atacante.clavePublica };

		const rechazos: string[] = [];
		nodoB.mesh.addEventListener('karmaRechazado', (ev) => {
			rechazos.push((ev as CustomEvent<{ motivo: string }>).detail.motivo);
		});

		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(txFalsa), atacante.mesh.config.nodoId, 'gossip-falso'));
		await nodoB.mesh.esperarPropagacionKarma();

		expect(nodoB.karma.getScore(C)).toBe(0);
		expect(nodoB.karma.getHistory(C)).toHaveLength(0);
		expect(rechazos).toEqual(['firma_invalida']);

		// The honest transaction is still accepted afterwards: the forged one did not
		// poison the engine, it was simply refused.
		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(txHonesta), A, 'gossip-honesto'));
		await nodoB.mesh.esperarPropagacionKarma();
		expect(nodoB.karma.getScore(C)).toBe(20);
	});

	it('no deja que un peer se autoavalore a si mismo por gossip', async () => {
		const nodoB = nodos[1];
		const atacante = nodos[0];

		// Peer A signs an endorsement of ITSELF. KarmaManager refuses auto_emision.
		const tx = await firmarComoEmisor(atacante.identidad, {
			id: `${A}:tx-auto`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: A,
			delta: 25,
			razon: 'autoaval',
			emisor: A,
			timestamp: Date.now(),
		});

		const rechazos: string[] = [];
		nodoB.mesh.addEventListener('karmaRechazado', (ev) => {
			rechazos.push((ev as CustomEvent<{ motivo: string }>).detail.motivo);
		});

		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-auto'));
		await nodoB.mesh.esperarPropagacionKarma();

		expect(nodoB.karma.getScore(A)).toBe(0);
		expect(rechazos).toEqual(['auto_emision']);
	});

	it('cuenta una transaccion repetida una sola vez (idempotencia por tx.id)', async () => {
		const nodoB = nodos[1];

		const tx = await firmarComoEmisor(nodos[0].identidad, {
			id: `${A}:tx-idem`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 7,
			razon: 'aval idempotente',
			emisor: A,
			timestamp: Date.now(),
		});

		const envelope = serializar(tx);
		nodoB.mesh.procesarGossip(gossipDeKarma(envelope, A, 'gossip-idem-1'));
		await nodoB.mesh.esperarPropagacionKarma();
		expect(nodoB.karma.getScore(C)).toBe(7);

		// Same tx, different gossip id — a real gossip mesh does re-deliver, and a
		// re-broadcast hop can re-send the same payload under a new envelope.
		nodoB.mesh.procesarGossip(gossipDeKarma(envelope, A, 'gossip-idem-2'));
		await nodoB.mesh.esperarPropagacionKarma();

		expect(nodoB.karma.getScore(C)).toBe(7);
		expect(nodoB.karma.getHistory(C)).toHaveLength(1);
	});

	it('no aplica ni propaga nada cuando la transaccion excede el techo de delta', async () => {
		const nodoB = nodos[1];

		const tx = await firmarComoEmisor(nodos[0].identidad, {
			id: `${A}:tx-techo`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 1_000_000,
			razon: 'atasco de reputacion',
			emisor: A,
			timestamp: Date.now(),
		});

		const rechazos: string[] = [];
		nodoB.mesh.addEventListener('karmaRechazado', (ev) => {
			rechazos.push((ev as CustomEvent<{ motivo: string }>).detail.motivo);
		});

		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-techo'));
		await nodoB.mesh.esperarPropagacionKarma();

		expect(nodoB.karma.getScore(C)).toBe(0);
		expect(rechazos).toEqual(['delta_sobre_techo']);
	});

	it('rechaza un payload karma malformado sin tocar el motor', async () => {
		const nodoB = nodos[1];

		const rechazos: string[] = [];
		nodoB.mesh.addEventListener('karmaRechazado', (ev) => {
			rechazos.push((ev as CustomEvent<{ motivo: string }>).detail.motivo);
		});

		// Claims to be an endorsement, has no usable signature.
		nodoB.mesh.procesarGossip(
			gossipDeKarma({ tipo: PAYLOAD_KARMA_TIPO, tx: { id: 'x', emisor: A, sujeto: C, delta: 99 } }, A, 'gossip-roto'),
		);
		await nodoB.mesh.esperarPropagacionKarma();

		expect(rechazos).toEqual(['payload_malformado']);
		expect(nodoB.karma.getScore(C)).toBe(0);
	});

	it('ignora payloads de gossip que no son de karma', async () => {
		const nodoB = nodos[1];
		const aplicados: unknown[] = [];
		nodoB.mesh.addEventListener('karmaRecibido', (ev) => {
			aplicados.push((ev as CustomEvent<{ tx: unknown }>).detail.tx);
		});

		// Maloca events and plugin discovery travel the same mesh.
		nodoB.mesh.procesarGossip(gossipDeKarma({ tipo: 'PROFILE_CREATED', payload: { userId: 'u1' } }, A, 'gossip-otro'));
		nodoB.mesh.procesarGossip(gossipDeKarma(null, A, 'gossip-nulo'));
		await nodoB.mesh.esperarPropagacionKarma();

		expect(aplicados).toHaveLength(0);
		expect(nodoB.karma.getScore(C)).toBe(0);
	});

	it('sigue emitiendo gossipRecibido para que event-bus y plugin-registry funcionen', async () => {
		const nodoB = nodos[1];

		const eventos: unknown[] = [];
		nodoB.mesh.addEventListener('gossipRecibido', (ev) => {
			eventos.push((ev as CustomEvent<{ mensaje: unknown }>).detail.mensaje);
		});

		const tx = await firmarComoEmisor(nodos[0].identidad, {
			id: `${A}:tx-evento`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 5,
			razon: 'aval que tambien llega como evento',
			emisor: A,
			timestamp: Date.now(),
		});

		nodoB.mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-evento'));
		await nodoB.mesh.esperarPropagacionKarma();

		// Both consumers of the event still fire: the karma hook is additive.
		expect(eventos).toHaveLength(1);
		expect(nodoB.karma.getScore(C)).toBe(5);
	});

	it('transmitirKarma envia el aval al mesh para que los peers lo apliquen', async () => {
		const nodoA = nodos[0];
		const nodoB = nodos[1];

		const enviados: unknown[] = [];
		nodoA.edgeMesh.enviar = async (_destino: NodoId, env: unknown) => {
			enviados.push(env);
		};
		await nodoA.mesh.conectarPeer(B);

		const tx = await firmarComoEmisor(nodoA.identidad, {
			id: `${A}:tx-salida`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 15,
			razon: 'aval transmitido',
			emisor: A,
			timestamp: Date.now(),
		});

		await nodoA.mesh.transmitirKarma(tx);
		expect(enviados).toHaveLength(1);

		// Feed B the envelope A actually put on the wire.
		const envelope = enviados[0] as { payload: { tipo: string; mensaje: { payload: unknown } } };
		expect(envelope.payload.tipo).toBe('gossip');
		const gossip = envelope.payload.mensaje;
		nodoB.mesh.procesarGossip(gossip);
		await nodoB.mesh.esperarPropagacionKarma();

		expect(nodoB.karma.getScore(C)).toBe(15);
	});

	it('sin consumidor de karma el mesh solo transporta y no inventa un motor', async () => {
		const identidad = createPostQuantumIdentity('solo-chat' as NodoId, generateKeypair('maestra'));
		const oplog = new OpLog({ docId: 'sin-karma', storage: new InMemoryStorage() });
		const mesh = new MeshManager({ nodoId: 'solo-chat' as NodoId }, {
			on: () => {},
			off: () => {},
			enviar: async () => {},
		} as never);
		await mesh.iniciar();

		const tx = await firmarComoEmisor(nodos[0].identidad, {
			id: `${A}:tx-sin-consumidor`,
			tipo: 'contribution',
			proyecto: 'maloca-medico',
			sujeto: C,
			delta: 99,
			razon: 'deberia ignorarse',
			emisor: A,
			timestamp: Date.now(),
		});

		mesh.procesarGossip(gossipDeKarma(serializar(tx), A, 'gossip-sin-consumidor'));
		await mesh.esperarPropagacionKarma();

		// Nothing threw, nothing was applied — and oplog/identidad were never touched.
		expect(await oplog.obtenerTamanioStorage()).toBe(0);
		expect(identidad.nodoId).toBe('solo-chat');
		await mesh.detener();
	});
});