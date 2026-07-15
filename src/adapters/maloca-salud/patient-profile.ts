import * as Y from "yjs";
import type { EdgeMesh } from "../../edge-mesh.js";
import type { PostQuantumIdentity } from "../../identity/index.js";
import type { PacientePerfil } from "./types.js";

export class PerfilPacienteAdapter {
	private readonly mesh: EdgeMesh;

	constructor(mesh: EdgeMesh) {
		this.mesh = mesh;
	}

	/**
	 * Registra un paciente como nodo mesh vinculando su perfil e identidad.
	 */
	async registerPatient(
		perfil: PacientePerfil,
		_identidad: PostQuantumIdentity,
	): Promise<void> {
		const pacientes = this.mesh.yjsAdapter.getMap("maloca-salud:pacientes");

		Y.transact(this.mesh.yjsAdapter.doc, () => {
			pacientes.set(perfil.id, perfil);
		});
	}

	/**
	 * Obtiene el historial médico de un paciente vía sync mesh.
	 */
	async getMedicalHistory(patientId: string): Promise<unknown[]> {
		const historiales = this.mesh.yjsAdapter.getArray(
			`maloca-salud:historial:${patientId}`,
		);
		return historiales.toArray();
	}

	/**
	 * Vincula paciente-médico en el mesh.
	 */
	async linkDoctor(patientId: string, doctorId: string): Promise<void> {
		const links = this.mesh.yjsAdapter.getMap(
			"maloca-salud:links-paciente-medico",
		);

		Y.transact(this.mesh.yjsAdapter.doc, () => {
			const existing = (links.get(patientId) as string[]) || [];
			if (!existing.includes(doctorId)) {
				links.set(patientId, [...existing, doctorId]);
			}
		});
	}
}
