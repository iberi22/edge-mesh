import type { NodoId } from "../../types/index.js";

export interface Contrato {
	id: string;
	hash: string;
	contenido: string;
	firmas: {
		nodoId: NodoId;
		firma: Uint8Array;
	}[];
	timestamp: number;
	estado: "pendiente" | "registrado" | "notarizado";
}

export interface PerfilLicitante {
	id: string;
	nodoId: NodoId;
	nombre: string;
	rut: string;
	karma: number;
	fechaRegistro: number;
}

export interface LicitacionChileCompra {
	codigo: string;
	nombre: string;
	descripcion: string;
	monto: number;
	moneda: string;
	estado: string;
	fechaCierre: number;
}
