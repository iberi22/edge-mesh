import * as Y from "yjs";
import type { EdgeMesh } from "../../edge-mesh.js";
import type { EPSData } from "./types.js";

export class EPSBridge {
	private readonly mesh: EdgeMesh;

	constructor(mesh: EdgeMesh) {
		this.mesh = mesh;
	}

	/**
	 * Sincroniza datos de la EPS al mesh.
	 */
	async syncEPSData(epsData: EPSData): Promise<void> {
		const epsMap = this.mesh.yjsAdapter.getMap("maloca-salud:eps-data");

		Y.transact(this.mesh.yjsAdapter.doc, () => {
			epsMap.set(epsData.id, epsData);
		});
	}

	/**
	 * Verifica afiliación EPS de un paciente vía mesh.
	 */
	async verifyEPS(patientId: string, epsId: string): Promise<boolean> {
		const epsMap = this.mesh.yjsAdapter.getMap("maloca-salud:eps-data");
		const epsData = epsMap.get(epsId) as EPSData | undefined;

		if (epsData === undefined) return false;

		return epsData.pacientesAfiliados.includes(patientId);
	}
}
