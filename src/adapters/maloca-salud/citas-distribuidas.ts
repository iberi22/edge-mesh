import * as Y from "yjs";
import type { EdgeMesh } from "../../edge-mesh.js";
import type { CitaInfo } from "./types.js";

export class CitaMeshAdapter {
	private readonly mesh: EdgeMesh;

	constructor(mesh: EdgeMesh) {
		this.mesh = mesh;
	}

	/**
	 * Crea una cita médica replicada en el mesh.
	 */
	async createCita(citaInfo: CitaInfo): Promise<void> {
		const citas = this.mesh.yjsAdapter.getArray("maloca-salud:citas");

		Y.transact(this.mesh.yjsAdapter.doc, () => {
			citas.push([citaInfo]);
		});
	}

	/**
	 * Sincroniza citas offline-first para un paciente.
	 */
	async syncCitas(patientId: string): Promise<CitaInfo[]> {
		const citas = this.mesh.yjsAdapter.getArray("maloca-salud:citas");
		const allCitas = citas.toArray() as CitaInfo[];
		return allCitas.filter((c) => c.pacienteId === patientId);
	}

	/**
	 * Consulta disponibilidad de un médico en una fecha específica vía mesh.
	 */
	async getAvailability(doctorId: string, fecha: string): Promise<string[]> {
		const citas = this.mesh.yjsAdapter.getArray("maloca-salud:citas");
		const allCitas = citas.toArray() as CitaInfo[];

		// Suponemos horario de 8:00 a 17:00 cada hora
		const horario = [
			"08:00",
			"09:00",
			"10:00",
			"11:00",
			"12:00",
			"13:00",
			"14:00",
			"15:00",
			"16:00",
			"17:00",
		];
		const ocupados = allCitas
			.filter(
				(c) =>
					c.medicoId === doctorId &&
					c.fecha === fecha &&
					c.estado !== "cancelada",
			)
			.map((c) => c.hora);

		return horario.filter((h) => !ocupados.includes(h));
	}
}
