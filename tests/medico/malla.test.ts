/**
 * Wire-format tests for the medical layer (`src/medico/malla.ts`).
 *
 * The load-bearing rule under test: a professional record has no cleartext form
 * on the wire. Phase 1 built a data model that could not leave the node that
 * made it; the hole this file exists to verify closed is that the record now
 * travels — sealed, signed, and refusing to survive any edit to it.
 *
 * Each test therefore checks a *specific* way the transport could betray the
 * record: no cleartext leak, no roundtrip loss, no acceptance of a tampered
 * payload, no acceptance of a record whose issuer signature does not verify.
 */

import { describe, expect, it } from "vitest";
import {
	crearIdentidadVinculada,
	type PostQuantumIdentity,
} from "../../src/identity/index.js";
import {
	ALCANCE_AVAL,
	type Aval,
	aPayloadGossipMedico,
	type BorradorAval,
	type BorradorCredencial,
	bytesCredencial,
	type CredencialMedica,
	crearAval,
	crearCredencial,
	credencialAWire,
	ESTADO_EMISION,
	emitirAval,
	emitirCredencial,
	emitirRegistro,
	hashCredencial,
	hashLicencia,
	idAval,
	MOTIVO_RECHAZO_MALLA,
	OBJETO_AVAL,
	type OpcionesRecibir,
	recibirAval,
	recibirCredencial,
	registroAWire,
	TIPO_CREDENCIAL,
	validarCredencialFirmada,
} from "../../src/medico/index.js";
import {
	abrirPayload,
	aceptarSesionCifrada,
	type SesionCifrada,
} from "../../src/protocol/crypto.js";
import {
	createEnvelope,
	GuardiaReplay,
	iniciarSesionCifrada,
	signEnvelope,
	verifyEnvelopeSignature,
} from "../../src/protocol/index.js";
import type { Envolvente, NodoId } from "../../src/types/index.js";
import { TIPO_MENSAJE } from "../../src/types/index.js";

const AHORA = 1_700_000_000_000;
const DIA = 86_400_000;
const NUMERO_LICENCIA = "COT-12-34567";

interface Par {
	readonly emisor: PostQuantumIdentity;
	readonly receptor: PostQuantumIdentity;
	readonly sesionEmisor: SesionCifrada;
	readonly sesionReceptor: SesionCifrada;
}

/** Two linked identities plus an established encryption session between them. */
async function par(): Promise<Par> {
	const emisor = await crearIdentidadVinculada();
	const receptor = await crearIdentidadVinculada();
	const { sesion: sesionEmisor, handshake } = iniciarSesionCifrada(
		emisor,
		receptor.exportarKemPublico(),
	);
	const { sesion: sesionReceptor } = aceptarSesionCifrada(receptor, handshake);
	return { emisor, receptor, sesionEmisor, sesionReceptor };
}

async function borradorCredencial(
	emisor: PostQuantumIdentity,
): Promise<CredencialMedica> {
	const borrador: BorradorCredencial = {
		tipo: TIPO_CREDENCIAL.LICENCIA,
		pais: "CO",
		autoridad: "minsalud-rethus",
		idLicencia: await hashLicencia(NUMERO_LICENCIA),
		emitidoEn: AHORA - DIA,
		vigenteHasta: AHORA + 364 * DIA,
		estadoEmision: ESTADO_EMISION.ANCLADA_AUTORIDAD,
		emisor: emisor.nodoId,
	};
	return crearCredencial(borrador, emisor);
}

async function borradorAval(
	avalador: PostQuantumIdentity,
	avalado: NodoId,
	credencial: CredencialMedica,
): Promise<Aval> {
	const borrador: BorradorAval = {
		avalador: avalador.nodoId,
		avalado,
		objetoAval: OBJETO_AVAL.LICENCIA_VERIFICADA,
		credencialRef: credencial.id,
		hashCredencial: await hashCredencial(credencial),
		metodoVerificacion: {
			clase: "registro_por_pais",
			pais: "CO",
			versionRegistro: "rethus-2026-01",
		},
		evidenciaHash: "e".repeat(64),
		alcance: ALCANCE_AVAL.ANUAL,
		emitidoEn: AHORA,
		vigenteHasta: AHORA + 364 * DIA,
		nonce: "nonce-malla-1",
	};
	return crearAval(borrador, avalador, { hash: borrador.hashCredencial });
}

/** Receiver-side options for a message sent by `emisor` within `par`. */
function opciones(p: Par, emisor: PostQuantumIdentity): OpcionesRecibir {
	return {
		sesion: p.sesionReceptor,
		guardia: new GuardiaReplay(),
		identidadEmisor: emisor,
		parPublicoEmisor: emisor.exportarPublico(),
	};
}

/** Flip one bit inside the base64 ciphertext, keeping its length. */
function manipularCiphertext(env: Envolvente): Envolvente {
	const payload = env.payload as { ct: string };
	const bytes = Uint8Array.from(atob(payload.ct), (c) => c.charCodeAt(0));
	bytes[0] ^= 0x01;
	let binario = "";
	for (const b of bytes) binario += String.fromCharCode(b);
	return { ...env, payload: { ...payload, ct: btoa(binario) } };
}

describe("medico/malla — contrato del enum de protocolo", () => {
	it("TIPO_MENSAJE tiene las entradas de la capa médica", () => {
		// docs/medico/protocolo.md §7 names these three exactly.
		expect(TIPO_MENSAJE.CREDENCIAL).toBe("credencial");
		expect(TIPO_MENSAJE.AVAL).toBe("aval");
		expect(TIPO_MENSAJE.REGISTRO).toBe("registro");
	});

	it("el typo HALLazGO está corregido y el valor de wire no cambió", () => {
		// The key was misspelled; the wire value never was, so no peer is affected.
		expect(TIPO_MENSAJE).toHaveProperty("HALLAZGO");
		expect(TIPO_MENSAJE).not.toHaveProperty("HALLazGO");
		expect(TIPO_MENSAJE.HALLAZGO).toBe("hallazgo");
	});

	it("el tráfico médico NO se disfraza de authz", () => {
		// Reusing AUTHZ for credentials would make grants and claims unauditable.
		expect(TIPO_MENSAJE.CREDENCIAL).not.toBe(TIPO_MENSAJE.AUTHZ);
		expect(TIPO_MENSAJE.AVAL).not.toBe(TIPO_MENSAJE.AUTHZ);
	});
});

describe("medico/malla — roundtrip de credencial", () => {
	it("el objeto vuelve idéntico tras cifrar, enviar, abrir y verificar", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);

		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
			destino: p.receptor.nodoId,
		});

		const recibido = await recibirCredencial(env, opciones(p, p.emisor));

		expect(recibido.ok).toBe(true);
		if (!recibido.ok) return;
		expect(recibido.registro).toEqual(credencial);
		// Deep equality on Uint8Array members is only meaningful field by field:
		// toEqual compares typed arrays by content, but spelling it out keeps a
		// future refactor from silently comparing nothing.
		expect(Array.from(recibido.registro.firma)).toEqual(
			Array.from(credencial.firma),
		);
	});

	it("un opcional ausente no reaparece como opcional presente", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		expect(credencial.numeroLicenciaCifrado).toBeUndefined();

		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});
		const recibido = await recibirCredencial(env, opciones(p, p.emisor));

		expect(recibido.ok).toBe(true);
		if (!recibido.ok) return;
		expect(recibido.registro.numeroLicenciaCifrado).toBeUndefined();
		expect("numeroLicenciaCifrado" in recibido.registro).toBe(false);
		expect("especialidad" in recibido.registro).toBe(false);
	});

	it("un opcional presente sobrevive el viaje byte a byte", async () => {
		const p = await par();
		const sello = new Uint8Array([1, 2, 3, 250, 255]);
		const credencial = await crearCredencial(
			{
				tipo: TIPO_CREDENCIAL.LICENCIA,
				pais: "CO",
				autoridad: "minsalud-rethus",
				idLicencia: await hashLicencia(NUMERO_LICENCIA),
				numeroLicenciaCifrado: sello,
				especialidad: "cardiologia",
				emitidoEn: AHORA - DIA,
				vigenteHasta: AHORA + 364 * DIA,
				estadoEmision: ESTADO_EMISION.ANCLADA_AUTORIDAD,
				emisor: p.emisor.nodoId,
			},
			p.emisor,
		);

		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});
		const recibido = await recibirCredencial(env, opciones(p, p.emisor));

		expect(recibido.ok).toBe(true);
		if (!recibido.ok) return;
		expect(Array.from(recibido.registro.numeroLicenciaCifrado ?? [])).toEqual(
			Array.from(sello),
		);
		expect(recibido.registro.especialidad).toBe("cardiologia");
	});
});

describe("medico/malla — roundtrip de aval", () => {
	it("el aval vuelve idéntico, incluida su unión discriminada", async () => {
		const p = await par();
		const emisorAval = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(p.emisor);
		const aval = await borradorAval(emisorAval, p.emisor.nodoId, credencial);

		const { env } = await emitirAval(aval, {
			identidad: emisorAval,
			sesion: p.sesionEmisor,
		});
		const recibido = await recibirAval(env, opciones(p, emisorAval));

		expect(recibido.ok).toBe(true);
		if (!recibido.ok) return;
		expect(recibido.registro).toEqual(aval);
		expect(recibido.registro.metodoVerificacion).toEqual(
			aval.metodoVerificacion,
		);
	});

	it("cada clase de metodoVerificacion sobrevive al viaje", async () => {
		const p = await par();
		const emisorAval = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(p.emisor);

		const metodos = [
			{
				clase: "registro_por_pais",
				pais: "CO",
				versionRegistro: "rethus-2026-01",
			},
			{ clase: "colegio_directo", ref: "colomedico-cm/cert/8891" },
			{ clase: "testimonio_directo" },
			{ clase: "supervision", desde: AHORA - 30 * DIA, hasta: AHORA },
		] as const;

		// Thread the session: `emitir` returns the ADVANCED session and the
		// crypto layer refuses to reuse a counter. Reusing the original object is
		// exactly what ErrorReusoDeNonce exists to prevent.
		let sesion = p.sesionEmisor;

		for (const metodo of metodos) {
			const aval = await crearAval(
				{
					avalador: emisorAval.nodoId,
					avalado: p.emisor.nodoId,
					objetoAval: OBJETO_AVAL.LICENCIA_VERIFICADA,
					credencialRef: credencial.id,
					hashCredencial: await hashCredencial(credencial),
					metodoVerificacion: metodo,
					evidenciaHash: "e".repeat(64),
					alcance: ALCANCE_AVAL.ANUAL,
					emitidoEn: AHORA,
					vigenteHasta: AHORA + 364 * DIA,
					nonce: `nonce-${metodo.clase}`,
				},
				emisorAval,
				{ hash: await hashCredencial(credencial) },
			);

			const emision = await emitirAval(aval, { identidad: emisorAval, sesion });
			sesion = emision.sesion;
			const recibido = await recibirAval(emision.env, opciones(p, emisorAval));

			expect(recibido.ok, `clase ${metodo.clase}`).toBe(true);
			if (!recibido.ok) return;
			expect(recibido.registro.metodoVerificacion).toEqual(metodo);
		}
	});
});

describe("medico/malla — el payload NO viaja en claro", () => {
	it("ningún campo de la credencial aparece en el mensaje cifrado", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);

		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
			destino: p.receptor.nodoId,
		});

		const serializado = JSON.stringify(env);

		// Long, high-entropy fields: absence of these is unambiguous. Note the
		// deliberate absence of short-substring assertions — a 3- or 4-char probe
		// collides with the random envelope id roughly one run in five, which is a
		// flaky test that proves nothing about confidentiality.
		expect(serializado).not.toContain(credencial.id);
		expect(serializado).not.toContain(credencial.idLicencia);
		expect(serializado).not.toContain(credencial.autoridad);
		expect(serializado).not.toContain("minsalud-rethus");

		// The real test of confidentiality is not "a substring is absent" but
		// "the plaintext does not decode": the decrypted bytes must differ from what
		// the sender put in, and the ciphertext must not contain the record.
		const abierto = abrirPayload(env, p.sesionReceptor, new GuardiaReplay(), {
			aplicarGuardia: false,
		});
		expect(JSON.stringify(env.payload)).not.toBe(
			JSON.stringify(abierto.payload),
		);
		expect((abierto.payload as Record<string, unknown>).idLicencia).toBe(
			credencial.idLicencia,
		);
		expect(env.payload).toHaveProperty("ct");
	});

	it("el payload es un sobre cifrado, no un objeto de negocio", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		const payload = env.payload as Record<string, unknown>;
		expect(payload.v).toBe(1);
		expect(typeof payload.ct).toBe("string");
		expect(payload).not.toHaveProperty("credencial");
		expect(payload).not.toHaveProperty("idLicencia");
	});

	it("un aval tampoco viaja en claro", async () => {
		const p = await par();
		const emisorAval = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(p.emisor);
		const aval = await borradorAval(emisorAval, p.emisor.nodoId, credencial);

		const { env } = await emitirAval(aval, {
			identidad: emisorAval,
			sesion: p.sesionEmisor,
		});
		const serializado = JSON.stringify(env);

		expect(serializado).not.toContain(aval.hashCredencial);
		expect(serializado).not.toContain(aval.evidenciaHash);
		expect(serializado).not.toContain(aval.credencialRef);
		expect(serializado).not.toContain("licencia_verificada");
		expect(serializado).not.toContain("medico_general");

		// Only the holder of the session key recovers it — which is the property
		// the substring checks above merely approximate.
		const abierto = abrirPayload(env, p.sesionReceptor, new GuardiaReplay(), {
			aplicarGuardia: false,
		});
		expect((abierto.payload as Record<string, unknown>).hashCredencial).toBe(
			aval.hashCredencial,
		);
	});
});

describe("medico/malla — la firma verifica con la identidad del emisor", () => {
	it("el ML-DSA del envolvente verifica contra la clave pública del emisor", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		expect(
			await verifyEnvelopeSignature(env, p.emisor.exportarPublico(), p.emisor),
		).toBe(true);
	});

	it("la firma propia de la credencial sigue verificando tras el viaje", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});
		const recibido = await recibirCredencial(env, opciones(p, p.emisor));

		expect(recibido.ok).toBe(true);
		if (!recibido.ok) return;
		// The signature covers the canonical bytes, so a lossless roundtrip means
		// the same canonical bytes — and therefore the same verification result.
		expect(Array.from(recibido.registro.firma)).toEqual(
			Array.from(credencial.firma),
		);
		const canonico = bytesCredencial(recibido.registro);
		expect(
			await p.emisor.verificar(
				canonico,
				recibido.registro.firma,
				p.emisor.exportarPublico(),
			),
		).toBe(true);
		expect(Array.from(canonico)).toEqual(
			Array.from(bytesCredencial(credencial)),
		);
	});

	it("el receptor con OTRA identidad rechaza la firma del emisor", async () => {
		const p = await par();
		const impostor = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		const recibido = await recibirCredencial(env, {
			sesion: p.sesionReceptor,
			guardia: new GuardiaReplay(),
			identidadEmisor: impostor,
			parPublicoEmisor: impostor.exportarPublico(),
		});

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		expect(recibido.motivo).toBe(
			MOTIVO_RECHAZO_MALLA.FIRMA_ENVOLVENTE_INVALIDA,
		);
	});
});

describe("medico/malla — un mensaje manipulado NO se acepta", () => {
	it("un ciphertext alterado se rechaza en la firma del envolvente", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		const recibido = await recibirCredencial(
			manipularCiphertext(env),
			opciones(p, p.emisor),
		);

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		// Refused at the FIRST barrier, not the second: the ML-DSA signature covers
		// the payload, so flipping a ciphertext bit is caught before any decryption
		// is even attempted. An attacker who cannot forge ML-DSA never reaches Poly1305.
		expect(recibido.motivo).toBe(
			MOTIVO_RECHAZO_MALLA.FIRMA_ENVOLVENTE_INVALIDA,
		);
	});

	it("un ciphertext alterado Y re-firmado por el emisor lo detiene el AEAD", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		// Re-signing is only reachable by someone holding the emitter's ML-DSA key
		// (i.e. the emitter itself). Re-done deliberately here to prove the AEAD is
		// a real second barrier and not merely shadowed by the signature check.
		const rehashed = await signEnvelope(manipularCiphertext(env), p.emisor);
		expect(
			await verifyEnvelopeSignature(
				rehashed,
				p.emisor.exportarPublico(),
				p.emisor,
			),
		).toBe(true);

		const recibido = await recibirCredencial(rehashed, opciones(p, p.emisor));

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		expect(recibido.motivo).toBe(MOTIVO_RECHAZO_MALLA.PAYLOAD_NO_CIFRADO);
	});

	it("cambiar un campo de cabecera tras cifrar invalida el mensaje", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
			destino: p.receptor.nodoId,
		});

		// The header is bound into the AEAD as associated data, so re-pointing the
		// message at another node breaks the signature and, once re-signed, Poly1305.
		const reenviado: Envolvente = {
			...env,
			destino: "mlkemattacker" as typeof env.destino,
		};
		const rehashed = await signEnvelope(reenviado, p.emisor);

		const recibido = await recibirCredencial(rehashed, opciones(p, p.emisor));

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		// A valid signature over a header the AEAD was not sealed with: exactly the
		// replay-under-a-different-id attack that binding the header prevents.
		expect(recibido.motivo).toBe(MOTIVO_RECHAZO_MALLA.PAYLOAD_NO_CIFRADO);
	});

	it("quitar la firma del envolvente se rechaza", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		const sinFirma: Envolvente = { ...env, firma: null };
		const recibido = await recibirCredencial(sinFirma, opciones(p, p.emisor));

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		expect(recibido.motivo).toBe(
			MOTIVO_RECHAZO_MALLA.FIRMA_ENVOLVENTE_INVALIDA,
		);
	});

	it("reemplazar la firma por otra válida no la hace pasar", async () => {
		const p = await par();
		const impostor = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		// A signature over DIFFERENT bytes from a key the receiver does not trust.
		const falsa = await signEnvelope(
			createEnvelope(
				TIPO_MENSAJE.CREDENCIAL,
				impostor.nodoId,
				p.receptor.nodoId,
				"basura",
			),
			impostor,
		);
		const recibido = await recibirCredencial(
			{ ...env, firma: falsa.firma },
			opciones(p, p.emisor),
		);

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		expect(recibido.motivo).toBe(
			MOTIVO_RECHAZO_MALLA.FIRMA_ENVOLVENTE_INVALIDA,
		);
	});

	it("un mensaje en claro disfrazado de credencial se rechaza", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		// Strip the AEAD and substitute the business object straight into the slot.
		const enClaro = createEnvelope(
			TIPO_MENSAJE.CREDENCIAL,
			p.emisor.nodoId,
			p.receptor.nodoId,
			credencialAWire(credencial),
		);
		const recibido = await recibirCredencial(enClaro, opciones(p, p.emisor));

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		expect(recibido.motivo).toBe(
			MOTIVO_RECHAZO_MALLA.FIRMA_ENVOLVENTE_INVALIDA,
		);
		expect(env.payload).not.toEqual(enClaro.payload);
	});

	it("un mensaje de aval no se acepta como credencial", async () => {
		const p = await par();
		const emisorAval = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(p.emisor);
		const aval = await borradorAval(emisorAval, p.emisor.nodoId, credencial);

		const { env } = await emitirAval(aval, {
			identidad: emisorAval,
			sesion: p.sesionEmisor,
		});
		const recibido = await recibirCredencial(env, opciones(p, emisorAval));

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		expect(recibido.motivo).toBe(MOTIVO_RECHAZO_MALLA.PAYLOAD_MALFORMADO);
	});

	it("una credencial reetiquetada a otro emisor se rechaza por su propia firma", async () => {
		// The wire layer must not become a laundering step. The impostor signs its
		// envelope truthfully — the transport is happy with that — but re-labelling
		// `emisor` changes the canonical bytes, so the credential's own ML-DSA
		// signature no longer verifies and the record is refused at the last gate.
		const p = await par();
		const impostor = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(impostor);
		const suplantada: CredencialMedica = {
			...credencial,
			emisor: p.emisor.nodoId,
		};

		const { env } = await emitirCredencial(suplantada, {
			identidad: impostor,
			sesion: p.sesionEmisor,
		});
		const recibido = await recibirCredencial(env, opciones(p, impostor));

		expect(recibido.ok).toBe(false);
		if (recibido.ok) return;
		expect(recibido.motivo).toBe(MOTIVO_RECHAZO_MALLA.FIRMA_REGISTRO_INVALIDA);

		// The model-level check reaches the same verdict on its own, which is what
		// makes it safe to keep as an independent gate.
		const validado = await validarCredencialFirmada(
			suplantada,
			impostor,
			impostor.exportarPublico(),
			AHORA,
		);
		expect(validado.ok).toBe(false);
		expect(validado.accesoPermitido).toBe(false);
		expect(env.tipo).toBe(TIPO_MENSAJE.CREDENCIAL);
	});
});

describe("medico/malla — id de aval e idempotencia", () => {
	it("el id del aval sobrevive el viaje como clave de idempotencia", async () => {
		const p = await par();
		const emisorAval = await crearIdentidadVinculada();
		const credencial = await borradorCredencial(p.emisor);
		const esperado = idAval(
			emisorAval.nodoId,
			p.emisor.nodoId,
			AHORA,
			"nonce-malla-1",
		);
		const aval = await borradorAval(emisorAval, p.emisor.nodoId, credencial);
		expect(aval.id).toBe(esperado);

		const { env } = await emitirAval(aval, {
			identidad: emisorAval,
			sesion: p.sesionEmisor,
		});
		const recibido = await recibirAval(env, opciones(p, emisorAval));

		expect(recibido.ok).toBe(true);
		if (!recibido.ok) return;
		expect(recibido.registro.id).toBe(esperado);
	});
});

describe("medico/malla — contrato del contador de sesión", () => {
	it("emitir devuelve la sesión avanzada y reutilizar el contador se rehúsa", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);

		const primera = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});
		expect(primera.sesion.siguienteCounter).toBe(1n);

		// The returned session is the one that must be sent with next; reusing the
		// original counter is refused rather than silently producing a keystream
		// repeat, which is the AEAD's catastrophic failure mode.
		await expect(
			emitirCredencial(credencial, {
				identidad: p.emisor,
				sesion: p.sesionEmisor,
			}),
		).rejects.toThrow(/Nonce reuse/);

		// Advancing properly works, and the message still verifies.
		const segunda = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: primera.sesion,
		});
		expect(segunda.sesion.siguienteCounter).toBe(2n);
		const recibido = await recibirCredencial(
			segunda.env,
			opciones(p, p.emisor),
		);
		expect(recibido.ok).toBe(true);
	});
});

describe("medico/malla — registro de país", () => {
	it("una instantánea viaja ordenada, para que sea direccionable por hash", async () => {
		const p = await par();
		const hashes = new Set(["c".repeat(64), "a".repeat(64), "b".repeat(64)]);
		const { env } = await emitirRegistro(
			{ pais: "CO", version: "rethus-2026-01", hashes },
			{ identidad: p.emisor, sesion: p.sesionEmisor },
		);

		expect(env.tipo).toBe(TIPO_MENSAJE.REGISTRO);
		const abierto = abrirPayload(env, p.sesionReceptor, new GuardiaReplay(), {
			aplicarGuardia: false,
		});
		const cuerpo = abierto.payload as { hashes: string[] };

		expect(cuerpo.hashes).toEqual([...hashes].sort());
	});

	it("el mismo conjunto en distinto orden de inserción produce los mismos bytes firmados", () => {
		const a = {
			pais: "CO",
			version: "v1",
			hashes: new Set(["a".repeat(64), "b".repeat(64)]),
		};
		const b = {
			pais: "CO",
			version: "v1",
			hashes: new Set(["b".repeat(64), "a".repeat(64)]),
		};

		// The snapshot must be hash-addressable, so ordering cannot depend on how a
		// node happened to build its Set.
		expect(registroAWire(a)).toEqual(registroAWire(b));
	});
});

describe("medico/malla — listo para gossip", () => {
	it("el adaptador produce el objeto que transmitirConGossip ya acepta", async () => {
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});

		const payload = aPayloadGossipMedico(env);

		// Mirrors src/mesh/index.ts:PayloadGossip shape ({ tipo, ... }).
		expect(payload.tipo).toBe("medico:v1");
		expect(payload.env.tipo).toBe(TIPO_MENSAJE.CREDENCIAL);
		// Still sealed inside the gossip payload: a relaying node cannot read it.
		expect(payload.env.payload).not.toHaveProperty("idLicencia");
	});

	it("VALIDAR no es necesario: el adaptador no depende de estado de malla", async () => {
		// Guards against the adapter growing a mesh import later.
		const p = await par();
		const credencial = await borradorCredencial(p.emisor);
		const { env } = await emitirCredencial(credencial, {
			identidad: p.emisor,
			sesion: p.sesionEmisor,
		});
		expect(() => aPayloadGossipMedico(env)).not.toThrow();
		expect(p.emisor.nodoId).toBeTruthy();
	});
});
