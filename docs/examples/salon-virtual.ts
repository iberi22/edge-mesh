import { EdgeMesh, SalonesManager, TIPO_SALON } from "../../src/index.js";
import type { NodoId } from "../../src/types/index.js";

async function main() {
	const mesh = new EdgeMesh({
		nodoId: "admin-1" as NodoId,
		peerId: "admin-peer-id",
	});

	await mesh.iniciar();

	// 1. Initialize SalonesManager
	const salonesManager = new SalonesManager(mesh);

	// 2. Create a virtual salon for a meeting
	const salon = await salonesManager.crearSalon(
		"Weekly Sync",
		TIPO_SALON.REUNION,
		25, // Max participants
	);

	// 3. Listen for participants joining
	salon.addEventListener("participanteUnido", (ev: Event) => {
		const { participanteId } = (ev as CustomEvent).detail;
		console.log(`User ${participanteId} entered the room.`);
	});

	// 4. Share content in the room
	await salon.compartirContenido("agenda", {
		items: ["Progress update", "Budget review", "Planning"],
		version: 1,
	});

	// 5. Send a room broadcast message
	await salon.enviarMensaje("Welcome everyone! Please check the agenda.");

	console.log(
		`Salon "${salon.obtenerInfo().nombre}" is active with ID: ${salon.id}`,
	);
}

main().catch(console.error);
