import { beforeEach, describe, expect, it, vi } from "vitest";
import { EvidentiaVeeduria } from "../../../src/adapters/maloca-veeduria/evidentia-veeduria.js";
import type { Contrato } from "../../../src/adapters/maloca-veeduria/types.js";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import type { NodoId } from "../../../src/types/index.js";

describe("EvidentiaVeeduria", () => {
	let mesh: EdgeMesh;
	let adapter: EvidentiaVeeduria;

	beforeEach(() => {
		mesh = new EdgeMesh({
			nodoId: "test-node" as NodoId,
			storageBackend: "mem",
		});
		adapter = new EvidentiaVeeduria(mesh);

		vi.spyOn(mesh, "transmitir").mockResolvedValue(undefined);
	});

	it("debe notarizar un contrato", async () => {
		const contrato: Contrato = {
			id: "1",
			hash: "abc",
			contenido: "Contrato de prueba",
			firmas: [],
			timestamp: Date.now(),
			estado: "registrado",
		};

		const contratosMap = mesh.yjsAdapter.getMap("veeduria:contratos");
		contratosMap.set("abc", contrato);

		const proof = await adapter.notarizeContract("abc");

		expect(proof).toContain("0x-proof-abc");

		const registrado = contratosMap.get("abc") as Contrato;
		expect(registrado.estado).toBe("notarizado");

		expect(adapter.getBlockchainProof("abc")).toBe(proof);
		expect(mesh.transmitir).toHaveBeenCalledWith(
			expect.objectContaining({
				tipo: "veeduria:contrato_notarizado",
				hash: "abc",
				proof,
			}),
		);
	});

	it("debe lanzar error si el contrato no existe", async () => {
		await expect(adapter.notarizeContract("non-existent")).rejects.toThrow();
	});

	it("debe retornar null si no hay prueba de notarizacion", () => {
		expect(adapter.getBlockchainProof("abc")).toBeNull();
	});
});
