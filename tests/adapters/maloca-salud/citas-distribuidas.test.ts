import { beforeEach, describe, expect, it } from "vitest";
import { CitaMeshAdapter } from "../../../src/adapters/maloca-salud/citas-distribuidas.js";
import type { CitaInfo } from "../../../src/adapters/maloca-salud/types.js";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import type { NodoId } from "../../../src/types/index.js";

describe("CitaMeshAdapter", () => {
	let mesh: EdgeMesh;
	let adapter: CitaMeshAdapter;

	beforeEach(() => {
		mesh = new EdgeMesh({
			nodoId: "nodo-test" as NodoId,
			storageBackend: "mem",
		});
		adapter = new CitaMeshAdapter(mesh);
	});

	it("debe crear una cita correctamente", async () => {
		const cita: CitaInfo = {
			id: "cita-1",
			pacienteId: "paciente-1",
			medicoId: "medico-1",
			fecha: "2023-12-01",
			hora: "10:00",
			motivo: "Consulta general",
			estado: "programada",
		};

		await adapter.createCita(cita);

		const citas = mesh.yjsAdapter.getArray("maloca-salud:citas");
		expect(citas.toArray()).toContainEqual(cita);
	});

	it("debe sincronizar citas de un paciente", async () => {
		const cita: CitaInfo = {
			id: "cita-1",
			pacienteId: "paciente-1",
			medicoId: "medico-1",
			fecha: "2023-12-01",
			hora: "10:00",
			motivo: "Consulta general",
			estado: "programada",
		};
		await adapter.createCita(cita);

		const citasPaciente = await adapter.syncCitas("paciente-1");
		expect(citasPaciente).toHaveLength(1);
		expect(citasPaciente[0].id).toBe("cita-1");
	});

	it("debe obtener disponibilidad de un médico", async () => {
		const cita: CitaInfo = {
			id: "cita-1",
			pacienteId: "paciente-1",
			medicoId: "medico-1",
			fecha: "2023-12-01",
			hora: "10:00",
			motivo: "Consulta general",
			estado: "programada",
		};
		await adapter.createCita(cita);

		const disponibilidad = await adapter.getAvailability(
			"medico-1",
			"2023-12-01",
		);
		expect(disponibilidad).not.toContain("10:00");
		expect(disponibilidad).toContain("09:00");
		expect(disponibilidad).toContain("11:00");
	});
});
