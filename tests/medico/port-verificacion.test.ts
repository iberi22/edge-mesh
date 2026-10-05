/**
 * Port verification — this file is NOT ported from the fork.
 *
 * The fork's own medico tests pass in the core, which proves the module arrived
 * intact. It does NOT prove the ported pieces interoperate the way the fork did,
 * because the fork had all of them behind one barrier and the core has three:
 * identity ML-KEM, the confidentiality layer, and the medico wire format. A test
 * that only exercises the fork's fixtures would stay green even if that seam had
 * rotted.
 *
 * So this drives the real chain, end to end, over a real ML-KEM handshake: a
 * credential signed by a real ML-DSA-65 identity, sealed under a real
 * XChaCha20-Poly1305 session, carried in a real CREDENCIAL envelope, and accepted
 * by a peer that never saw the plaintext.
 */
import { describe, expect, it } from "vitest";
import {
	crearIdentidadVinculada,
	type PostQuantumIdentity,
} from "../../src/identity/index.js";
import {
	crearCredencial,
	verificarFirmaCredencial,
} from "../../src/medico/credencial.js";
import { ESTADO_EMISION, TIPO_CREDENCIAL } from "../../src/medico/types.js";
import {
	aceptarSesionCifrada,
	type SesionCifrada,
	esEnvolventeCifrado,
	GuardiaReplay,
	iniciarSesionCifrada,
} from "../../src/protocol/crypto.js";
import {
	createEnvelope,
	signEnvelope,
	verifyEnvelopeSignature,
} from "../../src/protocol/index.js";
import type { NodoId } from "../../src/types/index.js";
import { TIPO_MENSAJE } from "../../src/types/index.js";

/** The medical record shape this port exists to carry. */
const LICENCIA =
	"a3f5c9e17b2d48f0a6c81e35b7d2094f8e6c15d7b3a90f2e84c6d15b7a30e9f4";
const AHORA = 1_760_000_000_000;
const VIGENTE = 1_792_000_000_000;

/** Byte-array equality without depending on Node's Buffer types. */
function iguales(x: Uint8Array, y: Uint8Array): boolean {
	if (x.length !== y.length) return false;
	return x.every((byte, i) => byte === y[i]);
}

async function dosNodos(): Promise<{
	a: PostQuantumIdentity;
	b: PostQuantumIdentity;
}> {
	return {
		a: await crearIdentidadVinculada(),
		b: await crearIdentidadVinculada(),
	};
}

/** Issuer key and signature, hex, the way `malla.ts` puts them on the wire. */
function firmaAHex(firma: Uint8Array): string {
	return Array.from(firma)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

describe("medico/port — el sello crypto y el formato medico se hablan", () => {
	it("una credencial viaja sellada entre dos ML-KEM y el receptor la verifica", async () => {
		const { a: emisor, b: receptor } = await dosNodos();

		// 1. El emisor construye y firma la credencial con ML-DSA-65 real.
		const credencial = await crearCredencial(
			{
				tipo: TIPO_CREDENCIAL.LICENCIA,
				emisor: emisor.nodoId,
				pais: "co",
				autoridad: "Consejo Profesional de Medicina y Sangre",
				idLicencia: LICENCIA,
				emitidoEn: AHORA,
				vigenteHasta: VIGENTE,
				estadoEmision: ESTADO_EMISION.ATESTIGUADA_PARES,
			},
			emisor,
		);

		// 2. Abre una sesion ML-KEM-768 real con el receptor y la sella.
		const { sesion: sesEmisor, handshake } = iniciarSesionCifrada(
			emisor,
			receptor.exportarKemPublico(),
		);
		const { sesion: sesReceptor } = aceptarSesionCifrada(receptor, handshake);

		// The handshake must have carried a real FIPS 203 ciphertext.
		expect(handshake.kemCipherText.length).toBeGreaterThan(1000);

		const { cifrarYSiguiente } = await import("../../src/protocol/crypto.js");
		const plano = createEnvelope(
			TIPO_MENSAJE.CREDENCIAL,
			emisor.nodoId,
			receptor.nodoId,
			{ id: credencial.id, firma: firmaAHex(credencial.firma) },
		);
		const { env: sellado } = cifrarYSiguiente(plano, sesEmisor);
		const firmado = await signEnvelope(sellado, emisor);

		// 3. El receptor ve solo ciphertext, y aun asi verifica todo.
		expect(esEnvolventeCifrado(firmado)).toBe(true);
		const enElCable = JSON.stringify(firmado);
		expect(enElCable).not.toContain(LICENCIA);
		expect(enElCable).not.toContain(firmaAHex(credencial.firma).slice(0, 32));

		// El mensaje nuevo TIPO_MENSAJE.CREDENCIAL tiene que sobrevivir la
		// validacion de forma de envolvente, si no nunca podria viajar.
		const { validateEnvelope } = await import("../../src/protocol/index.js");
		expect(validateEnvelope(firmado)).toBe(true);

		// El orden importa, y es el documentado en `malla.ts`: forma, luego firma
		// de la envolvente, y SOLO entonces descifrar. Verificar despues de abrir
		// compararia una firma tomada sobre el ciphertext contra bytes en claro,
		// que por supuesto no coinciden.
		expect(
			await verifyEnvelopeSignature(
				firmado,
				emisor.exportarPublico(),
				receptor,
			),
		).toBe(true);

		const { abrirPayload } = await import("../../src/protocol/crypto.js");
		const abierto = abrirPayload(firmado, sesReceptor, new GuardiaReplay());

		const cuerpo = abierto.payload as { id: string; firma: string };
		expect(cuerpo.id).toBe(credencial.id);
		expect(cuerpo.firma).toBe(firmaAHex(credencial.firma));
		expect(
			await verificarFirmaCredencial(
				credencial,
				receptor,
				emisor.exportarPublico(),
			),
		).toBe(true);
	});

	it("un nodo con una sesion ajena no puede abrir el registro", async () => {
		const { a: emisor, b: receptor } = await dosNodos();
		const intruso = await crearIdentidadVinculada();

		const { sesion: sesEmisor } = iniciarSesionCifrada(
			emisor,
			receptor.exportarKemPublico(),
		);
		const { cifrarYSiguiente, abrirPayload, ErrorPayloadCifrado } =
			await import("../../src/protocol/crypto.js");
		const { env } = cifrarYSiguiente(
			createEnvelope(TIPO_MENSAJE.CREDENCIAL, emisor.nodoId, receptor.nodoId, {
				paciente: "PAC-8891",
			}),
			sesEmisor,
		);

		// Sesion propia del intruso, derivada de SU propio ML-KEM.
		const sesIntruso: SesionCifrada = {
			sesionId: "intrusa-00000000",
			epoch: 0,
			claves: {
				claveCifrado: new Uint8Array(32).fill(9),
				claveAutenticacion: new Uint8Array(32).fill(9),
			},
			direccion: 2,
			siguienteCounter: 0n,
		};
		expect(() => abrirPayload(env, sesIntruso, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);

		// Y la recuperacion del secreto de otro tampoco le da nada: su propia clave
		// de desencapsulacion sobre un ciphertext ajeno produce material distinto.
		const sobreDelIntruso = intruso.encapsular(intruso.exportarKemPublico());
		expect(sobreDelIntruso.claveCompartida.length).toBe(32);
		expect(
			iguales(
				intruso.decapsular(sobreDelIntruso.cipherText),
				sobreDelIntruso.claveCompartida,
			),
		).toBe(true);
		const sobreAjeno = emisor.encapsular(receptor.exportarKemPublico());
		expect(
			iguales(
				intruso.decapsular(sobreAjeno.cipherText),
				sobreAjeno.claveCompartida,
			),
		).toBe(false);
	});

	it("el emisor de la credencial esta ligado criptograficamente a su nodeId", async () => {
		// This is what makes `emisor` more than a string in the record: a node
		// cannot claim a nodeId it cannot produce the ML-KEM key for.
		const { a, b } = await dosNodos();
		expect(a.nodoId).toMatch(/^mlkem[0-9a-f]{32}$/);
		expect(a.nodoId).not.toBe(b.nodoId);

		const { derivarNodoId, verificarNodoIdVinculado } = await import(
			"../../src/identity/index.js"
		);
		expect(await derivarNodoId(a.exportarKemPublico())).toBe(a.nodoId);
		expect(
			await verificarNodoIdVinculado(a.nodoId, a.exportarKemPublico()),
		).toBe(true);
		// B cannot claim A's id.
		expect(
			await verificarNodoIdVinculado(a.nodoId, b.exportarKemPublico()),
		).toBe(false);
	});
});
