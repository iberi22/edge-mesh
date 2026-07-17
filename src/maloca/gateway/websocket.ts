import type { EdgeMesh } from "../../edge-mesh.js";
import type { Envolvente } from "../../types/index.js";

/**
 * WebSocket Gateway para tiempo real en el mesh Maloca.
 * Simulación de manejador de WS.
 */

export class MalocaWSGateway {
	private activeSubscriptions: Map<string, Set<string>> = new Map();

	constructor(private readonly mesh: EdgeMesh) {}

	/**
	 * Conecta un cliente WS al mesh.
	 */
	async connectWS(profileId: string) {
		console.log(`WS Client connected: ${profileId}`);

		// Iniciar escucha de eventos del mesh para reenviar al WS
		this.mesh.on("mensajeRecibido", (ev) => {
			this.handleMeshMessage(profileId, ev.detail.envolvente);
		});

		return {
			connectionId: Math.random().toString(36).substring(7),
			profileId,
		};
	}

	/**
	 * Suscribe al cliente a tipos específicos de eventos.
	 */
	subscribeToEvents(profileId: string, tipos: string[]) {
		const subs = this.activeSubscriptions.get(profileId) ?? new Set();
		for (const t of tipos) {
			subs.add(t);
		}
		this.activeSubscriptions.set(profileId, subs);
	}

	/**
	 * Envía un evento desde el cliente externo al mesh.
	 */
	async emitMessage(evento: { type: string; payload: any }) {
		await this.mesh.transmitir({
			type: evento.type,
			payload: evento.payload,
			timestamp: Date.now(),
		});
	}

	/**
	 * Maneja mensajes recibidos del mesh y los filtra para el cliente.
	 */
	private handleMeshMessage(profileId: string, envolvente: Envolvente) {
		const subs = this.activeSubscriptions.get(profileId);
		if (subs && (subs.has("*") || subs.has(envolvente.tipo))) {
			// En un entorno real, aquí se enviaría por el socket:
			// socket.send(JSON.stringify(envolvente));
			console.log(`WS [${profileId}] forwarding event: ${envolvente.tipo}`);
		}
	}
}
