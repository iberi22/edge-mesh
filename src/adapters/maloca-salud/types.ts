import type { NodoId } from "../../types/index.js";

export interface PacientePerfil {
	readonly id: string;
	readonly nombre: string;
	readonly documento: string;
	readonly epsId: string;
	readonly fechaNacimiento: string;
	readonly historialIds: readonly string[];
}

export interface MedicoPerfil {
	readonly id: string;
	readonly nombre: string;
	readonly especialidad: string;
	readonly registroMedico: string;
	readonly pacientesVinculados: readonly NodoId[];
}

export interface CitaInfo {
	readonly id: string;
	readonly pacienteId: string;
	readonly medicoId: string;
	readonly fecha: string;
	readonly hora: string;
	readonly motivo: string;
	readonly estado: "programada" | "completada" | "cancelada";
}

export interface EPSData {
	readonly id: string;
	readonly nombre: string;
	readonly nit: string;
	readonly pacientesAfiliados: readonly string[];
}

export interface RegistroMedico {
	readonly id: string;
	readonly pacienteId: string;
	readonly fecha: string;
	readonly diagnostico: string;
	readonly tratamiento: string;
	readonly medicoId: string;
}
