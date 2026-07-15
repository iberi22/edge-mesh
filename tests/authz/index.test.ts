import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NamespaceAuthorizer, CAPACIDAD_ESTANDAR } from '../../src/authz/index.js';
import type { NodoId } from '../../src/types/index.js';

describe('NamespaceAuthorizer', () => {
  let authz: NamespaceAuthorizer;
  const espacio = 'espacio-1';
  const sujeto = 'peer-1' as NodoId;

  beforeEach(() => {
    authz = new NamespaceAuthorizer();
  });

  it('debería conceder y verificar capacidades', () => {
    authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);

    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(true);
    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.ESCRIBIR)).toBe(false);
  });

  it('debería revocar capacidades', () => {
    authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(true);

    authz.revocarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(false);
  });

  it('el permiso "admin" debería otorgar todas las capacidades', () => {
    authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.ADMIN);

    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(true);
    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.ESCRIBIR)).toBe(true);
    expect(authz.verificarCapacidad(espacio, sujeto, 'cualquier-cosa')).toBe(true);
  });

  it('debería manejar la expiración de permisos', async () => {
    // Conceder permiso que expira en 100ms
    authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER, 100);
    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(true);

    // Esperar a que expire
    await new Promise(resolve => setTimeout(resolve, 150));

    expect(authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(false);
  });

  it('debería disparar eventos al conceder/revocar', () => {
    const concedidaListener = vi.fn();
    const revocadaListener = vi.fn();

    authz.on('capacidadConcedida', (concedidaListener) as EventListener);
    authz.on('capacidadRevocada', (revocadaListener) as EventListener);

    authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
    expect(concedidaListener).toHaveBeenCalled();

    authz.revocarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
    expect(revocadaListener).toHaveBeenCalled();
  });

  it('debería disparar evento de autorización fallida', () => {
    const fallidaListener = vi.fn();
    authz.on('autorizacionFallida', (fallidaListener) as EventListener);

    authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
    expect(fallidaListener).toHaveBeenCalled();
    expect(fallidaListener.mock.calls[0][0].detail.razon).toBe('Sin permiso concedido');
  });

  it('debería permitir agregar y verificar reglas locales', () => {
    authz.agregarReglaLocal(espacio, 'solo-lectura');
    expect(authz.verificarReglaLocal(espacio, 'solo-lectura')).toBe(true);
    expect(authz.verificarReglaLocal(espacio, 'otra-regla')).toBe(false);

    authz.removerReglaLocal(espacio, 'solo-lectura');
    expect(authz.verificarReglaLocal(espacio, 'solo-lectura')).toBe(false);
  });
});
