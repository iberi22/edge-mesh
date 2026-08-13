import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	CAPACIDAD_ESTANDAR,
	NamespaceAuthorizer,
} from "../../src/authz/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("NamespaceAuthorizer", () => {
	let authz: NamespaceAuthorizer;
	const espacio = "espacio-1";
	const sujeto = "peer-1" as NodoId;

	beforeEach(() => {
		authz = new NamespaceAuthorizer();
	});

	it("debería conceder y verificar capacidades", () => {
		authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);

		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(true);
		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.ESCRIBIR),
		).toBe(false);
	});

	it("debería revocar capacidades", () => {
		authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(true);

		authz.revocarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(false);
	});

	it('el permiso "admin" debería otorgar todas las capacidades', () => {
		authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.ADMIN);

		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(true);
		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.ESCRIBIR),
		).toBe(true);
		expect(authz.verificarCapacidad(espacio, sujeto, "cualquier-cosa")).toBe(
			true,
		);
	});

	it("debería manejar la expiración de permisos", async () => {
		// Conceder permiso que expira en 100ms
		authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER, 100);
		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(true);

		// Esperar a que expire
		await new Promise((resolve) => setTimeout(resolve, 150));

		expect(
			authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(false);
	});

	it("debería disparar eventos al conceder/revocar", () => {
		const concedidaListener = vi.fn();
		const revocadaListener = vi.fn();

		authz.on("capacidadConcedida", concedidaListener as EventListener);
		authz.on("capacidadRevocada", revocadaListener as EventListener);

		authz.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
		expect(concedidaListener).toHaveBeenCalled();

		authz.revocarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
		expect(revocadaListener).toHaveBeenCalled();
	});

	it("debería disparar evento de autorización fallida", () => {
		const fallidaListener = vi.fn();
		authz.on("autorizacionFallida", fallidaListener as EventListener);

		authz.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
		expect(fallidaListener).toHaveBeenCalled();
		expect(fallidaListener.mock.calls[0][0].detail.razon).toBe(
			"Sin permiso concedido",
		);
	});

	it("debería permitir agregar y verificar reglas locales", () => {
		authz.agregarReglaLocal(espacio, "solo-lectura");
		expect(authz.verificarReglaLocal(espacio, "solo-lectura")).toBe(true);
		expect(authz.verificarReglaLocal(espacio, "otra-regla")).toBe(false);

		authz.removerReglaLocal(espacio, "solo-lectura");
		expect(authz.verificarReglaLocal(espacio, "solo-lectura")).toBe(false);
	});

	it("debería soportar todas las constantes de CAPACIDAD_ESTANDAR", () => {
		const caps = Object.values(CAPACIDAD_ESTANDAR);
		expect(caps).toContain("read");
		expect(caps).toContain("write");
		expect(caps).toContain("admin");
		expect(caps).toContain("sync");
		expect(caps).toContain("presence");
		expect(caps).toContain("governance");

		for (const cap of caps) {
			authz.concederCapacidad(espacio, sujeto, cap);
			expect(authz.verificarCapacidad(espacio, sujeto, cap)).toBe(true);
		}
	});

	it("debería soportar asignaciones de roles y capacidades personalizadas por espacio", () => {
		// Test updateRole and obtenerRoles
		authz.updateRole(sujeto, "editor");
		const roles = authz.obtenerRoles();
		expect(roles.has(sujeto)).toBe(true);
		expect(roles.get(sujeto)?.rol).toBe("editor");

		// Test revokeRole
		authz.revokeRole(sujeto);
		expect(authz.obtenerRoles().has(sujeto)).toBe(false);

		// Test concederCapacidades y obtenerCapacidades
		const caps = [
			{ nombre: "personalizada_1", descripcion: "Desc 1" },
			{ nombre: "personalizada_2" }
		];
		authz.concederCapacidades(espacio, caps);
		const resultCaps = authz.obtenerCapacidades(espacio);
		expect(resultCaps).toBeDefined();
		expect(resultCaps?.length).toBe(2);
		expect(resultCaps?.[0].nombre).toBe("personalizada_1");
		expect(resultCaps?.[1].nombre).toBe("personalizada_2");
	});

	it("debería negar permisos por defecto a menos que se concedan o exista regla", () => {
		const nuevoSujeto = "peer-desconocido" as NodoId;
		// Por defecto no debería tener capacidades
		expect(authz.verificarCapacidad(espacio, nuevoSujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(false);
		expect(authz.verificarCapacidad(espacio, nuevoSujeto, CAPACIDAD_ESTANDAR.ESCRIBIR)).toBe(false);

		// El admin tiene acceso completo por defecto/fallback
		authz.concederCapacidad(espacio, nuevoSujeto, CAPACIDAD_ESTANDAR.ADMIN);
		expect(authz.verificarCapacidad(espacio, nuevoSujeto, CAPACIDAD_ESTANDAR.LEER)).toBe(true);
		expect(authz.verificarCapacidad(espacio, nuevoSujeto, CAPACIDAD_ESTANDAR.ESCRIBIR)).toBe(true);
	});
});
