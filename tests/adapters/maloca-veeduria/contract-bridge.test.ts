import { beforeEach, describe, expect, it, vi } from "vitest";
import { ContractBridge } from "../../../src/adapters/maloca-veeduria/contract-bridge.js";
import type {
	Contrato,
	PerfilLicitante,
} from "../../../src/adapters/maloca-veeduria/types.js";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import type { NodoId } from "../../../src/types/index.js";

describe("ContractBridge", () => {
	let mesh: EdgeMesh;
	let bridge: ContractBridge;

	beforeEach(() => {
		mesh = new EdgeMesh({
			nodoId: "test-node" as NodoId,
			storageBackend: "mem",
		});
		// Forzar un par de claves válido para ML-DSA-65 en el mock si es necesario,
		// pero EdgeMesh ya genera uno válido por defecto.
		bridge = new ContractBridge(mesh);

		// Mock transmitir
		vi.spyOn(mesh, "transmitir").mockResolvedValue(undefined);
	});

	it("debe registrar un contrato", async () => {
		const contrato: Contrato = {
			id: "1",
			hash: "abc",
			contenido: "Contrato de prueba",
			firmas: [],
			timestamp: Date.now(),
			estado: "pendiente",
		};

		// Mock firmar para evitar problemas con longitudes de clave en el entorno de test
		vi.spyOn(mesh.identity, "firmar").mockResolvedValue(
			new Uint8Array([1, 2, 3]),
		);

		await bridge.submitContract(contrato);

		const estado = bridge.getContractStatus("abc");
		expect(estado).toBe("registrado");
		expect(mesh.transmitir).toHaveBeenCalled();
	});

	it("no deja un Uint8Array dentro del Y.Map y aun assim conserva la firma", async () => {
		// `Y.Map.set` -> `ContentAny` -> `deepFreeze`, y `Object.freeze` no
		// puede congelar un typed array con elementos. Solo se manifiesta con
		// NODE_ENV=development, asi que este test afirma la PROPIEDAD (que la
		// firma sobrevive el round-trip) en vez de confiar en que el entorno
		// la dispare.
		const contrato: Contrato = {
			id: "2",
			hash: "def",
			contenido: "Segundo contrato",
			firmas: [],
			timestamp: Date.now(),
			estado: "pendiente",
		};
		const firmaFalsa = new Uint8Array([9, 8, 7, 6]);
		vi.spyOn(mesh.identity, "firmar").mockResolvedValue(firmaFalsa);

		await bridge.submitContract(contrato);

		// 1. Lo que hay en el mapa no puede contener bytes crudos.
		const crudo = mesh.yjsAdapter.getMap("veeduria:contratos").get("def") as {
			firmas: { firma: unknown }[];
		};
		expect(typeof crudo.firmas[0].firma).toBe("string");
		expect(crudo.firmas[0].firma).not.toBeInstanceOf(Uint8Array);

		// 2. Y al releer, los bytes vuelven EXACTOS: no se pierde la firma.
		const releido = bridge.getContract("def");
		expect(releido).not.toBeNull();
		const firmas = releido?.firmas ?? [];
		expect(firmas).toHaveLength(1);
		expect(firmas[0].firma).toBeInstanceOf(Uint8Array);
		expect(Array.from(firmas[0].firma)).toEqual([9, 8, 7, 6]);
		expect(firmas[0].nodoId).toBe("test-node");

		// 3. Lo que viaja por la red conserva los bytes, no el base64.
		const enviado = vi.mocked(mesh.transmitir).mock.calls[0][0] as {
			contrato: Contrato;
		};
		expect(enviado.contrato.firmas[0].firma).toBeInstanceOf(Uint8Array);
		expect(Array.from(enviado.contrato.firmas[0].firma)).toEqual([9, 8, 7, 6]);
	});

	it("debe vincular un licitante", async () => {
		const perfil: PerfilLicitante = {
			id: "lic-1",
			nodoId: "test-node" as NodoId,
			nombre: "Juan Perez",
			rut: "12.345.678-9",
			karma: 100,
			fechaRegistro: Date.now(),
		};

		await bridge.linkLicitante(perfil);

		const licitantesMap = mesh.yjsAdapter.getMap("veeduria:licitantes");
		const registrado = licitantesMap.get("lic-1") as PerfilLicitante;

		expect(registrado.nombre).toBe("Juan Perez");
		expect(mesh.transmitir).toHaveBeenCalledWith(
			expect.objectContaining({
				tipo: "veeduria:licitante_vinculado",
			}),
		);
	});

	it("debe sincronizar licitaciones de ChileCompra", async () => {
		const licitaciones = [
			{
				codigo: "123-456",
				nombre: "Licitacion 1",
				descripcion: "Desc 1",
				monto: 1000,
				moneda: "CLP",
				estado: "Abierta",
				fechaCierre: Date.now() + 86400000,
			},
		];

		await bridge.syncChileCompra(licitaciones);

		const chileCompraMap = mesh.yjsAdapter.getMap("veeduria:chilecompra");
		expect(chileCompraMap.has("123-456")).toBe(true);
		expect(mesh.transmitir).toHaveBeenCalledWith(
			expect.objectContaining({
				tipo: "veeduria:chilecompra_sync",
			}),
		);
	});
});
