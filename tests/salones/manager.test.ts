import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SalonVirtual, TIPO_SALON, ESTADO_SALON, type SalonConfig, SalonesManager } from '../../src/salones/manager.js';
import { EdgeMesh, YjsAdapter } from '../../src/edge-mesh.js';
import type { NodoId } from '../../src/types/index.js';

describe('SalonVirtual', () => {
  let edgeMesh: EdgeMesh;
  const creatorId = 'peer1' as NodoId;

  beforeEach(() => {
    edgeMesh = new EdgeMesh({ nodoId: creatorId, storageBackend: "mem" });
  });

  it('debería crear un salón correctamente', () => {
    const config: SalonConfig = {
      creatorId,
      nombre: 'Mi Salon',
      tipo: TIPO_SALON.CHAT,
      maxParticipantes: 10,
      yjsAdapter: edgeMesh.yjsAdapter,
      edgeMesh,
    };
    const salon = new SalonVirtual(config);

    expect(salon.id).toBeDefined();
    expect(salon.obtenerEstado()).toBe(ESTADO_SALON.ACTIVO);
    expect(salon.obtenerInfo().nombre).toBe('Mi Salon');
  });

  it('debería permitir que un participante se una y salga', async () => {
    const config: SalonConfig = {
      creatorId,
      nombre: 'Mi Salon',
      tipo: TIPO_SALON.CHAT,
      maxParticipantes: 10,
      yjsAdapter: edgeMesh.yjsAdapter,
      edgeMesh,
    };
    const salon = new SalonVirtual(config);
    const peer2 = 'peer2' as NodoId;

    await salon.unirse(peer2);
    expect(await salon.obtenerParticipantes()).toContain(peer2);

    await salon.abandonar(peer2);
    expect(await salon.obtenerParticipantes()).not.toContain(peer2);
  });

  it('debería re-enviar mensajes del chat', async () => {
    const config: SalonConfig = {
      creatorId,
      nombre: 'Mi Salon',
      tipo: TIPO_SALON.CHAT,
      maxParticipantes: 10,
      yjsAdapter: edgeMesh.yjsAdapter,
      edgeMesh,
    };
    const salon = new SalonVirtual(config);
    const mensajeListener = vi.fn();
    salon.addEventListener('mensaje', (mensajeListener) as EventListener);

    await salon.enviarMensaje('Hola salon');

    // El chat tarda un poco en procesar y disparar eventos
    await new Promise(resolve => setTimeout(resolve, 100));

    // Nota: El ChatChannel no dispara el evento 'mensaje' para el sender mismo por defecto en su lógica actual:
    // if (m.sender !== this.nodoId) { ... }
    // Así que para testear el re-envio necesitamos un mensaje de otro peer.

    const yjsMensajes = edgeMesh.yjsAdapter.getArray(`chat:salon:${salon.id}:mensajes`);
    yjsMensajes.push([{
      id: 'msg-remote',
      sender: 'peer2',
      text: 'Hola desde fuera',
      timestamp: Date.now(),
      type: 'texto',
      canal: `salon:${salon.id}`
    }]);

    await new Promise(resolve => setTimeout(resolve, 100));
    expect(mensajeListener).toHaveBeenCalled();
    const event = mensajeListener.mock.calls[0][0] as CustomEvent;
    expect(event.detail.mensaje.text).toBe('Hola desde fuera');
  });

  it('debería cerrar el salón', async () => {
    const config: SalonConfig = {
      creatorId,
      nombre: 'Mi Salon',
      tipo: TIPO_SALON.CHAT,
      maxParticipantes: 10,
      yjsAdapter: edgeMesh.yjsAdapter,
      edgeMesh,
    };
    const salon = new SalonVirtual(config);

    await salon.cerrar();
    expect(salon.obtenerEstado()).toBe(ESTADO_SALON.CERRADO);
  });
});

describe('SalonesManager', () => {
  let edgeMesh: EdgeMesh;
  const creatorId = 'peer1' as NodoId;

  beforeEach(() => {
    edgeMesh = new EdgeMesh({ nodoId: creatorId, storageBackend: "mem" });
  });

  it('debería orquestar salones', async () => {
    const manager = new SalonesManager(edgeMesh);
    const salon = await manager.crearSalon('Salon 1', TIPO_SALON.EXAMEN);

    expect(manager.listarSalones().length).toBe(1);
    expect(manager.obtenerSalon(salon.id)).toBe(salon);
    expect(manager.obtenerTotalSalones()).toBe(1);
    expect(manager.obtenerSalonesActivos().length).toBe(1);
  });

  it('debería permitir unirse y abandonar un salón vía manager', async () => {
    const manager = new SalonesManager(edgeMesh);
    const salon = await manager.crearSalon('Salon 1');

    // El creador ya está unido
    expect(await salon.obtenerParticipantes()).toContain(creatorId);

    await manager.abandonarSalon(salon.id);
    expect(await salon.obtenerParticipantes()).not.toContain(creatorId);

    await manager.unirseSalon(salon.id);
    expect(await salon.obtenerParticipantes()).toContain(creatorId);
  });

  it('solo el creador debería poder cerrar el salón', async () => {
    const manager = new SalonesManager(edgeMesh);
    const salon = await manager.crearSalon('Salon 1');

    // Intentar cerrar con otro peer (simulando cambio de identidad en edgeMesh)
    const otherPeerEdgeMesh = new EdgeMesh({ nodoId: 'peer2' as NodoId, storageBackend: "mem" });
    const otherManager = new SalonesManager(otherPeerEdgeMesh);

    // Hack: forzar al otherManager a conocer el salón
    // En un entorno real, esto se sincronizaría por el mesh
    (otherManager as any).salones.set(salon.id, salon);
    (otherManager as any).creadorPorSalon.set(salon.id, creatorId);

    await expect(otherManager.cerrarSalon(salon.id)).rejects.toThrow(/Solo el creador/);

    // El creador sí puede
    await manager.cerrarSalon(salon.id);
    expect(manager.obtenerTotalSalones()).toBe(0);
  });
});
