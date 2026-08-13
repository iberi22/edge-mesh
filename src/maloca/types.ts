import type { NodoId, ParPublico } from "../types/index.js";

export interface PerfilHumano {
	readonly id: string;
	readonly identidad: ParPublico;
	readonly alias: string;
	readonly nodos: readonly NodoId[];
	readonly proyectos: readonly string[];
	readonly karma?: number | Karma;
	readonly metadatos: Readonly<Record<string, unknown>>;
}

export interface PerfilServicio {
	readonly id: string;
	readonly tipo: string;
	readonly version: string;
	readonly endpoint?: string;
	readonly capacidades: readonly string[];
	readonly capabilidades?: readonly string[];
}

export interface TransaccionKarma {
	readonly id: string;
	readonly tipo: string;
	readonly proyecto: string;
	readonly sujeto: NodoId;
	readonly delta: number;
	readonly razon: string;
	readonly emisor: NodoId;
	readonly emitidoPor?: NodoId;
	readonly timestamp: number;
	readonly firma: Uint8Array;
}

export interface Karma {
	readonly total: number;
	readonly historial: readonly TransaccionKarma[];
	readonly pesosPorProyecto: Readonly<Record<string, number>>;
	readonly pesos?: Readonly<Record<string, number>>;
	readonly ultimoDecay: number;
	readonly ultimaActualizacion?: number;
	readonly decay?: number;
}

export interface MetadatosCompartidos {
	readonly red: {
		readonly nombre: string;
		readonly version: string;
		readonly nodosActivos: number;
	};
	readonly perfiles: number; // contador o algo similar
	readonly repositorios: readonly string[];
	readonly plugins: readonly string[];
}
