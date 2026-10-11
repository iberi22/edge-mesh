import { describe, expect, it } from "vitest";
import {
	CAPACIDAD_ESTANDAR,
	NamespaceAuthorizer,
} from "../../src/authz/index.js";
import { InMemoryStorage } from "../../src/storage/index.js";
import type {
	NamespaceCapabilityGrant,
	NodoId,
} from "../../src/types/index.js";

describe("Authz Persistence", () => {
	it("debería persistir grants y cargarlos tras un reinicio simulado", async () => {
		const storage = new InMemoryStorage();
		const authorizer1 = new NamespaceAuthorizer(storage);

		const espacio = "espacio-test";
		const sujeto = "nodo-1" as NodoId;
		authorizer1.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);

		// Esperar que se guarden
		await authorizer1.saveGrants();

		// Crear un nuevo autorizador con el mismo storage
		const authorizer2 = new NamespaceAuthorizer(storage);
		await authorizer2.loadGrants();

		expect(
			authorizer2.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(true);
	});

	it("debería guardar en el storage un grant migrado de memoria", async () => {
		const storage = new InMemoryStorage();
		const authorizer = new NamespaceAuthorizer(storage);

		const espacio = "espacio-migrar";
		const sujeto = "nodo-2" as NodoId;
		authorizer.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.ESCRIBIR);

		// Forzar guardado para asegurar persistencia sincrónica en el test
		await authorizer.saveGrants();

		// Verificar que el storage realmente contiene la llave 'authz:grants'
		const entry =
			await storage.get<[string, NamespaceCapabilityGrant][]>("authz:grants");
		expect(entry).not.toBeNull();
		expect(entry?.valor).toBeInstanceOf(Array);

		const dataArray = entry?.valor;
		expect(dataArray?.length).toBeGreaterThan(0);
		const found = dataArray?.find(
			([, v]) =>
				v.sujeto === sujeto && v.capacidad === CAPACIDAD_ESTANDAR.ESCRIBIR,
		);
		expect(found).toBeDefined();
	});

	it("debería persistir y cargar asignaciones de roles tras un reinicio", async () => {
		const storage = new InMemoryStorage();
		const authorizer1 = new NamespaceAuthorizer(storage);

		const sujeto = "nodo-3" as NodoId;
		authorizer1.updateRole(sujeto, "admin");

		// Asegurar que se guardó
		await authorizer1.saveRoleAssignments();

		// Crear nuevo authorizador y cargar
		const authorizer2 = new NamespaceAuthorizer(storage);
		await authorizer2.loadRoleAssignments();

		const roles = authorizer2.obtenerRoles();
		expect(roles.has(sujeto)).toBe(true);
		expect(roles.get(sujeto)?.rol).toBe("admin");
	});

	it("loads grants seeded directly as a stored entry list (valor wrapper)", async () => {
		const storage = new InMemoryStorage();
		const espacio = "espacio-legacy";
		const sujeto = "nodo-legacy" as NodoId;
		const grant: NamespaceCapabilityGrant = {
			id: "grant-legacy-1",
			espacio,
			sujeto,
			capacidad: CAPACIDAD_ESTANDAR.LEER,
			fechaEmision: Date.now(),
			fechaExpiracion: Date.now() + 3_600_000,
			firma: new Uint8Array(0),
		};
		// Simulate entries written by another version: the loader must read
		// them through the `{ valor: [...] }` storage-entry branch.
		await storage.put("authz:grants", [
			[`${espacio}::${sujeto}::${CAPACIDAD_ESTANDAR.LEER}`, grant],
		]);

		const authorizer = new NamespaceAuthorizer(storage);
		await authorizer.loadGrants();

		expect(
			authorizer.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(true);
	});

	it("does not overwrite in-memory grants when loading stored entries", async () => {
		const storage = new InMemoryStorage();
		const espacio = "espacio-merge";
		const sujeto = "nodo-merge" as NodoId;
		await storage.put("authz:grants", []);

		const authorizer = new NamespaceAuthorizer(storage);
		authorizer.concederCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER);
		await authorizer.loadGrants();

		expect(
			authorizer.verificarCapacidad(espacio, sujeto, CAPACIDAD_ESTANDAR.LEER),
		).toBe(true);
		expect(authorizer.obtenerTodosLosGrants().length).toBe(1);
	});

	it("debería persistir y cargar capacidades de espacios tras un reinicio", async () => {
		const storage = new InMemoryStorage();
		const authorizer1 = new NamespaceAuthorizer(storage);

		const espacio = "espacio-admin";
		const caps = [
			{ nombre: "leer_reportes", descripcion: "Permite leer reportes" },
			{ nombre: "escribir_reportes" },
		];
		authorizer1.concederCapacidades(espacio, caps);

		// Asegurar que se guardó
		await authorizer1.saveCapabilities();

		// Crear nuevo authorizador y cargar
		const authorizer2 = new NamespaceAuthorizer(storage);
		await authorizer2.loadCapabilities();

		const loadedCaps = authorizer2.obtenerCapacidades(espacio);
		expect(loadedCaps).toBeDefined();
		expect(loadedCaps?.length).toBe(2);
		expect(loadedCaps?.[0].nombre).toBe("leer_reportes");
	});
});
