import type { EdgeMesh } from "../../edge-mesh.js";
import { base64ToBytes, bytesToBase64 } from "../../identity/index.js";
import type { NodoId } from "../../types/index.js";
import type {
	Contrato,
	LicitacionChileCompra,
	PerfilLicitante,
} from "./types.js";

/**
 * Un Y.Map no puede contener un `Uint8Array`.
 *
 * `Y.Map.set` envuelve el valor en un `ContentAny`, y `ContentAny` le pasa
 * `deepFreeze`. `Object.freeze` —que es lo que hay bajo— lanza `TypeError:
 * Cannot freeze array buffer views with elements` en cuanto el typed array
 * tiene elementos. Medido con yjs 13.6.32 / lib0 0.2.117:
 *
 *     NODE_ENV=development
 *       Uint8Array([1,2,3])  -> THROWS  Cannot freeze array buffer views…
 *       [1,2,3]             -> OK
 *       "AQID"  (base64)     -> OK
 *
 * El fallo depende del entorno: con `NODE_ENV` sin definir o en `production` la
 * suite pasa en verde y el defecto queda invisible, mientras que en
 * `development` —como corre el gate documentado de este repo— revienta. Un
 * contrato con firma es el caso normal, no el borde.
 *
 * Se codifica en la frontera de la persistencia, no en el tipo de dominio:
 * `Contrato.firma` sigue siendo `Uint8Array` porque es lo que firman y
 * verifican; solo lo que se guarda va en base64, y `getContract` lo rehidrata.
 */
type ContratoEnMapa = Omit<Contrato, "firmas"> & {
	firmas: { nodoId: NodoId; firma: string }[];
};

export class ContractBridge {
	private readonly mesh: EdgeMesh;

	constructor(mesh: EdgeMesh) {
		this.mesh = mesh;
	}

	/**
	 * Firma un contrato con PQC y lo registra en la red mesh.
	 */
	async submitContract(contrato: Contrato): Promise<void> {
		const encoder = new TextEncoder();
		const datos = encoder.encode(contrato.contenido);
		const firma = await this.mesh.identity.firmar(datos);

		const contratoFirmado: Contrato = {
			...contrato,
			firmas: [
				...contrato.firmas,
				{
					nodoId: this.mesh.config.nodoId,
					firma,
				},
			],
			estado: "registrado",
			timestamp: Date.now(),
		};

		// Registrar en el mesh (usando YjsAdapter para sincronizar el estado).
		// La firma va en base64: un Y.Map no admite un Uint8Array (ver la nota
		// de `ContratoEnMapa`). Lo que viaja por la red sigue siendo el contrato
		// tipado, con sus bytes de firma intactos.
		const contratosMap = this.mesh.yjsAdapter.getMap("veeduria:contratos");
		const paraElMapa: ContratoEnMapa = {
			...contratoFirmado,
			firmas: contratoFirmado.firmas.map((f) => ({
				nodoId: f.nodoId,
				firma: bytesToBase64(f.firma),
			})),
		};
		contratosMap.set(contratoFirmado.hash, paraElMapa);

		// Transmitir a la red
		await this.mesh.transmitir({
			tipo: "veeduria:nuevo_contrato",
			contrato: contratoFirmado,
		});
	}

	/**
	 * Obtiene el estado de un contrato via mesh.
	 */
	getContractStatus(hash: string): string | null {
		const contratosMap = this.mesh.yjsAdapter.getMap("veeduria:contratos");
		const contrato = contratosMap.get(hash) as ContratoEnMapa | undefined;
		return contrato ? contrato.estado : null;
	}

	/**
	 * Lee un contrato del mapa rehidratando las firmas a `Uint8Array`.
	 *
	 * `getContractStatus` solo lee `estado`, asi que no necesita esta
	 * conversion; quien necesite las firmas —verificarlas, exportarlas— debe
	 * pasar por aqui en vez de leer el mapa a mano y olvidarse del base64.
	 */
	getContract(hash: string): Contrato | null {
		const contratosMap = this.mesh.yjsAdapter.getMap("veeduria:contratos");
		const guardada = contratosMap.get(hash) as ContratoEnMapa | undefined;
		if (!guardada) return null;
		return {
			...guardada,
			firmas: (guardada.firmas ?? []).map((f) => ({
				nodoId: f.nodoId,
				firma: base64ToBytes(f.firma),
			})),
		} as Contrato;
	}

	/**
	 * Vincula un perfil de licitante a un nodo Maloca.
	 */
	async linkLicitante(perfil: PerfilLicitante): Promise<void> {
		const licitantesMap = this.mesh.yjsAdapter.getMap("veeduria:licitantes");
		licitantesMap.set(perfil.id, {
			...perfil,
			nodoId: this.mesh.config.nodoId,
		});

		await this.mesh.transmitir({
			tipo: "veeduria:licitante_vinculado",
			perfilId: perfil.id,
			nodoId: this.mesh.config.nodoId,
		});
	}

	/**
	 * Sincroniza licitaciones de ChileCompra al mesh.
	 */
	async syncChileCompra(licitaciones: LicitacionChileCompra[]): Promise<void> {
		const chileCompraMap = this.mesh.yjsAdapter.getMap("veeduria:chilecompra");

		for (const licitacion of licitaciones) {
			chileCompraMap.set(licitacion.codigo, licitacion);
		}

		await this.mesh.transmitir({
			tipo: "veeduria:chilecompra_sync",
			cantidad: licitaciones.length,
			timestamp: Date.now(),
		});
	}
}
