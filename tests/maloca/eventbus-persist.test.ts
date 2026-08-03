import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EdgeMesh } from "../../src/edge-mesh.js";
import { EventBus, TIPO_EVENTO_MALOCA, type MeshEvent } from "../../src/maloca/event-bus.js";
import { MeshManager } from "../../src/mesh/index.js";
import { OpLog } from "../../src/op-log/index.js";
import { InMemoryStorage } from "../../src/storage/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("EventBus Persistent Queue & Replay", () => {
	let mesh: MeshManager;
	let opLog: OpLog;
	let bus: EventBus;
	let storage: InMemoryStorage;
	const nodoId = "nodo-test" as NodoId;

	beforeEach(async () => {
		vi.useFakeTimers();
		storage = new InMemoryStorage();

		const mockEdgeMesh = {
			on: vi.fn(),
			off: vi.fn(),
		} as unknown as EdgeMesh;

		mesh = new MeshManager({ nodoId }, mockEdgeMesh);
		await mesh.iniciar();

		opLog = new OpLog({ docId: "events", storage });
		bus = new EventBus(mesh, opLog, storage);
	});

	afterEach(async () => {
		await mesh.detener();
		vi.useRealTimers();
	});

	it("debería realizar Enqueue y Dequeue funcional de manera persistente", async () => {
		const payload = { data: "test-offline-data" };

		// Verificar que no hay peers online en el namespace "_maloca:events"
		const peersBefore = mesh.obtenerPeersEnNamespace("_maloca:events");
		expect(peersBefore).toHaveLength(0);

		// Emitir evento mientras se está offline (sin peers subscriptos)
		await bus.emit(TIPO_EVENTO_MALOCA.NODE_CONNECT, payload);

		// El tamaño de la cola persistente debería ser 1
		const size = await bus.queue.size();
		expect(size).toBe(1);

		// Vaciar la cola con dequeueAll()
		const dequeued = await bus.queue.dequeueAll();
		expect(dequeued).toHaveLength(1);
		expect(dequeued[0].tipo).toBe(TIPO_EVENTO_MALOCA.NODE_CONNECT);
		expect(dequeued[0].payload).toEqual(payload);

		// La cola debería estar vacía ahora
		const finalSize = await bus.queue.size();
		expect(finalSize).toBe(0);
	});

	it("debería realizar replay automático de eventos encolados al reconectar un peer", async () => {
		const spyGossip = vi.spyOn(mesh, "transmitirConGossip").mockResolvedValue(undefined);

		// Emitir un evento mientras no hay peers conectados
		await bus.emit("OFFLINE_EVENT", { value: 42 });

		// Verificar que el evento se ha encolado
		expect(await bus.queue.size()).toBe(1);

		// Simular que el nodo de soporte o cualquier peer se conecta al namespace "_maloca:events"
		const peerSupportId = "peer-support" as NodoId;
		await mesh.conectarPeer(peerSupportId, "_maloca:events");

		// Lanzar el evento de reconexión "peerConectado"
		mesh.dispatchEvent(
			new CustomEvent("peerConectado", {
				detail: { peerId: peerSupportId, namespace: "_maloca:events" },
			})
		);

		// El replay es asíncrono, avanzar promesas/timers
		await vi.advanceTimersByTimeAsync(100);

		// Debería haberse transmitido el evento a través de gossip
		expect(spyGossip).toHaveBeenCalledWith("_maloca:events", expect.objectContaining({
			tipo: "OFFLINE_EVENT",
			payload: { value: 42 },
		}));

		// La cola debería haberse vaciado automáticamente
		expect(await bus.queue.size()).toBe(0);
	});

	it("debería expirar eventos que superen el TTL de 1 hora", async () => {
		// Evento válido
		const validEvent: MeshEvent = {
			tipo: "VALID_EVENT",
			origen: nodoId,
			payload: { x: 1 },
			timestamp: Date.now(),
		};

		// Evento expirado (hace 1 hora y 1 minuto)
		const expiredEvent: MeshEvent = {
			tipo: "EXPIRED_EVENT",
			origen: nodoId,
			payload: { x: 2 },
			timestamp: Date.now() - (60 * 61 * 1000), // 61 minutos atrás
		};

		await bus.queue.enqueue(validEvent);
		await bus.queue.enqueue(expiredEvent);

		// El tamaño de la cola debe reportar solo 1 ya que el expirado se descarta (y se borra del storage)
		const size = await bus.queue.size();
		expect(size).toBe(1);

		// DequeueAll debería retornar solo el evento válido
		const dequeued = await bus.queue.dequeueAll();
		expect(dequeued).toHaveLength(1);
		expect(dequeued[0].tipo).toBe("VALID_EVENT");
	});

	it("debería integrarse con Support Distribuido como sink para recibir eventos tras reconexión", async () => {
		// Simulamos que el "Soporte Distribuido" está offline en este momento
		const supportPeerId = "support-distribuido-peer" as NodoId;
		const supportReceivedEvents: MeshEvent[] = [];

		// Espiar en el método de transmitir con gossip para capturar el replay
		const spyGossip = vi.spyOn(mesh, "transmitirConGossip").mockImplementation(
			async (ns, payload) => {
				if (ns === "_maloca:events") {
					supportReceivedEvents.push(payload as MeshEvent);
				}
			}
		);

		// Emitimos un evento crítico de Maloca, p. ej. una transacción de Karma
		const payloadKarma = { id: "tx-001", delta: 10, sujeto: "nodo-receptor" };
		await bus.emit(TIPO_EVENTO_MALOCA.KARMA_TRANSACTION, payloadKarma);

		// El evento debe haber quedado retenido en la cola offline ya que Support está desconectado
		expect(await bus.queue.size()).toBe(1);
		expect(supportReceivedEvents).toHaveLength(0);

		// El Soporte Distribuido se conecta (vuelve a estar online)
		await mesh.conectarPeer(supportPeerId, "_maloca:events");

		// Despachar evento de reconexión
		mesh.dispatchEvent(
			new CustomEvent("peerConectado", {
				detail: { peerId: supportPeerId, namespace: "_maloca:events" },
			})
		);

		await vi.advanceTimersByTimeAsync(100);

		// El sink de Soporte Distribuido debe haber recibido el evento retransmitido por replay
		expect(supportReceivedEvents).toHaveLength(1);
		expect(supportReceivedEvents[0].tipo).toBe(TIPO_EVENTO_MALOCA.KARMA_TRANSACTION);
		expect(supportReceivedEvents[0].payload).toEqual(payloadKarma);

		// La cola persistente se ha limpiado
		expect(await bus.queue.size()).toBe(0);
	});
});
