import { ChatChannel, EdgeMesh, TIPO_CANAL } from "../../src/index.js";
import type { NodoId } from "../../src/types/index.js";

async function main() {
	// 1. Initialize the EdgeMesh node
	const mesh = new EdgeMesh({
		nodoId: "peer-1" as NodoId,
		peerId: "peer-1-id",
	});

	await mesh.iniciar();

	// 2. Create or join a chat channel
	const chat = new ChatChannel(
		mesh.config.nodoId,
		"general",
		mesh.yjsAdapter,
		TIPO_CANAL.PUBLICO,
	);

	// 3. Listen for messages
	chat.addEventListener("mensaje", (ev: Event) => {
		const detail = (ev as CustomEvent).detail;
		console.log(`[${detail.mensaje.sender}]: ${detail.mensaje.text}`);
	});

	// 4. Join and send a message
	await chat.unirseAlCanal();
	await chat.enviarMensaje("Hello, Edge Mesh!");

	// 5. List connected users
	console.log("Users in channel:", chat.obtenerUsuariosConectados());
}

main().catch(console.error);
