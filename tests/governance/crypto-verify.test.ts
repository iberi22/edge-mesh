import { describe, expect, it } from "vitest";
import {
	createGovernanceManager,
	ESTADO_PROPUESTA,
	GovernanceManager,
	type VerificadorVotos,
} from "../../src/governance/index.js";
import {
	createPostQuantumIdentity,
	generateKeypair,
} from "../../src/identity/index.js";
import type { NodoId, ParPublico, PayloadVotacion } from "../../src/types/index.js";

describe("Governance Cryptographic Signature Verification", () => {
	const nodo1 = "nodo-1" as NodoId;
	const nodo2 = "nodo-2" as NodoId;
	const nodoDesconocido = "nodo-desconocido" as NodoId;

	const id1 = createPostQuantumIdentity(nodo1, generateKeypair("maestra"));
	const id2 = createPostQuantumIdentity(nodo2, generateKeypair("maestra"));

	const publicKeys = new Map<NodoId, ParPublico>([
		[nodo1, id1.exportarPublico()],
		[nodo2, id2.exportarPublico()],
	]);

	const verificador: VerificadorVotos = {
		obtenerClavePublica(nodoId: NodoId): ParPublico | undefined {
			return publicKeys.get(nodoId);
		},
		verificarFirma(
			mensaje: Uint8Array,
			firma: Uint8Array,
			clave: ParPublico | Uint8Array,
		): boolean {
			try {
				const { ml_dsa65 } = require("@noble/post-quantum/ml-dsa.js");
				return ml_dsa65.verify(firma, mensaje, clave);
			} catch {
				return false;
			}
		},
	};

	async function firmarVoto(
		propuestaId: string,
		voto: "a_favor" | "en_contra" | "abstencion",
		identity: typeof id1,
		timestamp = Date.now(),
	): Promise<PayloadVotacion> {
		const mensajeBytes = new TextEncoder().encode(
			JSON.stringify({
				propuestaId,
				nodoId: identity.nodoId,
				voto,
				timestamp,
			}),
		);
		const firma = await identity.firmar(mensajeBytes);

		return {
			propuesta: propuestaId,
			voto,
			nodoId: identity.nodoId,
			peso: 1,
			justificacion: "Voto criptográficamente firmado",
			firma,
			timestamp,
		};
	}

	it("accepts a vote with a valid ML-DSA-65 signature", async () => {
		const gov = createGovernanceManager(
			{ umbral: 0.5 },
			verificador,
		);

		const prop = gov.crearPropuesta("prop-1", "upgrade", nodo1, {});
		const votoValido = await firmarVoto("prop-1", "a_favor", id1);

		const resultado = gov.votar("prop-1", votoValido);
		expect(resultado).toBe(true);

		const propActual = gov.obtenerPropuesta("prop-1");
		expect(propActual?.votos.length).toBe(1);
		expect(propActual?.votos[0].nodoId).toBe(nodo1);
	});

	it("rejects a vote with an invalid or corrupted signature", async () => {
		const gov = createGovernanceManager(
			{ umbral: 0.5 },
			verificador,
		);

		gov.crearPropuesta("prop-2", "config", nodo1, {});
		const votoValido = await firmarVoto("prop-2", "a_favor", id1);

		// Corrupt signature bytes
		const firmaCorrupta = new Uint8Array(votoValido.firma as Uint8Array);
		firmaCorrupta[0] = (firmaCorrupta[0] ?? 0) ^ 0xff;

		const votoInvalido: PayloadVotacion = {
			...votoValido,
			firma: firmaCorrupta,
		};

		const resultado = gov.votar("prop-2", votoInvalido);
		expect(resultado).toBe(false);

		const propActual = gov.obtenerPropuesta("prop-2");
		expect(propActual?.votos.length).toBe(0);
	});

	it("accepts an unsigned vote when requireSignedVotes is false (backwards compatibility)", () => {
		const gov = createGovernanceManager(
			{ umbral: 0.5 },
			verificador,
			{ requireSignedVotes: false },
		);

		gov.crearPropuesta("prop-3", "action", nodo1, {});
		const votoSinFirma: PayloadVotacion = {
			propuesta: "prop-3",
			voto: "a_favor",
			nodoId: nodo1,
			peso: 1,
			justificacion: "Sin firma pero permitido en modo no estricto",
		};

		const resultado = gov.votar("prop-3", votoSinFirma);
		expect(resultado).toBe(true);
	});

	it("rejects an unsigned vote when requireSignedVotes is true (strict mode)", () => {
		const gov = createGovernanceManager(
			{ umbral: 0.5 },
			verificador,
			{ requireSignedVotes: true },
		);

		gov.crearPropuesta("prop-4", "action", nodo1, {});
		const votoSinFirma: PayloadVotacion = {
			propuesta: "prop-4",
			voto: "a_favor",
			nodoId: nodo1,
			peso: 1,
			justificacion: null,
		};

		const resultado = gov.votar("prop-4", votoSinFirma);
		expect(resultado).toBe(false);
	});

	it("rejects a vote from an unknown node without a registered public key", async () => {
		const idDesconocido = createPostQuantumIdentity(
			nodoDesconocido,
			generateKeypair("maestra"),
		);

		const gov = createGovernanceManager(
			{ umbral: 0.5 },
			verificador,
		);

		gov.crearPropuesta("prop-5", "action", nodo1, {});
		const votoDesconocido = await firmarVoto("prop-5", "a_favor", idDesconocido);

		const resultado = gov.votar("prop-5", votoDesconocido);
		expect(resultado).toBe(false);
	});

	it("rejects a replay attack where signature payload does not match vote parameters", async () => {
		const gov = createGovernanceManager(
			{ umbral: 0.5 },
			verificador,
		);

		gov.crearPropuesta("prop-6", "action", nodo1, {});
		// Firmado para prop-6 pero intentado usar en prop-7
		const votoProp6 = await firmarVoto("prop-6", "a_favor", id1);

		gov.crearPropuesta("prop-7", "action", nodo1, {});
		const votoReplay: PayloadVotacion = {
			...votoProp6,
			propuesta: "prop-7",
		};

		const resultado = gov.votar("prop-7", votoReplay);
		expect(resultado).toBe(false);
	});
});
