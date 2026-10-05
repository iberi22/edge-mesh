/**
 * Wire format for the medical layer — the seam Phase 1 left open.
 *
 * ─── THE HOLE THIS FILE CLOSES ─────────────────────────────────────────────
 *
 * `src/medico/` defined the data model and its pure validation, but a
 * `CredencialMedica` could not leave the node that made it: `TIPO_MENSAJE` had
 * no member for it, and nothing could put one inside an `Envolvente`. The model
 * existed; the road out of it did not. This file builds the road, and only the
 * road — it invents no transport and edits no mesh file.
 *
 * ─── WHY THE BYTES ARE RE-ENCODED AND NOT JSON-SUMMONED ─────────────────────
 *
 * `cifrarPayload` seals `JSON.stringify(env.payload)`. `JSON.stringify` turns a
 * `Uint8Array` into `{"0":12,"1":34,…}` — an object of indices, not bytes. A
 * signature sealed that way could not be reconstructed on the far side, so every
 * byte field (two ML-DSA signatures and the sealed licence number) is hex-encoded
 * through `canonica.ts` before it enters the payload and decoded on the way out.
 * `bytesAHex`/`hexABytes` are the same primitives `canonica.ts` already signs
 * with, so "the bytes the signature covers" and "the bytes that travel" come out
 * of one implementation instead of two that must agree.
 *
 * ─── ORDER OF OPERATIONS IS NOT A STYLE CHOICE ──────────────────────────────
 *
 * Serialise → SEAL → SIGN. `cifrarPayload` binds the envelope header into the
 * AEAD, and `signEnvelope` signs `canonicalEnvelopeBytes`, which covers
 * `payload`. Signing first would leave the ciphertext outside the signature and
 * let anyone re-seal a payload under the same signature; so the seal happens
 * first and the returned envelope is the one that gets signed. On the receiving
 * side the order inverts: shape, then envelope signature, then decrypt, then the
 * record's own signature.
 *
 * ─── WHAT IS DELIBERATELY NOT HERE ─────────────────────────────────────────
 *
 * There is no `transmitirCredencial` on the mesh, because writing one means
 * editing `src/mesh/index.ts` next to `transmitirKarma`, which another owner
 * owns. {@link aPayloadGossipMedico} produces exactly the object
 * `MeshManager.transmitirConGossip(namespace, payload)` takes, so wiring it up is
 * a one-line method on the mesh rather than a redesign.
 *
 * Pure and testable: the clock and the randomness live inside `createEnvelope`,
 * and everything else is injected, so the whole roundtrip runs on fixtures with
 * no network and no filesystem.
 */

import type { ParPublico, PostQuantumIdentity } from "../identity/index.js";
import {
	abrirPayload,
	cifrarYSiguiente,
	GuardiaReplay,
	type SesionCifrada,
} from "../protocol/crypto.js";
import {
	createEnvelope,
	signEnvelope,
	validateEnvelope,
	verifyEnvelopeSignature,
} from "../protocol/index.js";
import type { Envolvente, NodoId } from "../types/index.js";
import { TIPO_MENSAJE } from "../types/index.js";
import { verificarFirmaAval } from "./aval.js";
import { bytesAHex, hexABytes } from "./canonica.js";
import { verificarFirmaCredencial } from "./credencial.js";
import type { InstantaneaRegistroPais } from "./registro.js";
import type { Aval, CredencialMedica, MetodoVerificacion } from "./types.js";

// ─── REJECTION REASONS ──────────────────────────────────────────────────────

/**
 * Why a medical message was refused. Every value means the record was NOT
 * applied. There is no third state — the same fail-closed rule as
 * `validarCredencial`: a peer must never be able to tell "malformed" from
 * "unknown" and act differently on the two.
 */
export const MOTIVO_RECHAZO_MALLA = {
	/** The envelope shape itself is invalid (`validateEnvelope` failed). */
	ENVOLVENTE_INVALIDA: "envolvente_invalida",
	/** The envelope's ML-DSA signature does not verify against the sender's key. */
	FIRMA_ENVOLVENTE_INVALIDA: "firma_envolvente_invalida",
	/** The envelope is not a sealed payload, or the AEAD rejected it. */
	PAYLOAD_NO_CIFRADO: "payload_no_cifrado",
	/** The plaintext payload is not the record type this message type declares. */
	PAYLOAD_MALFORMADO: "payload_malformado",
	/** The record's own signature does not verify against its claimed issuer. */
	FIRMA_REGISTRO_INVALIDA: "firma_registro_invalida",
} as const;
export type MotivoRechazoMalla =
	(typeof MOTIVO_RECHAZO_MALLA)[keyof typeof MOTIVO_RECHAZO_MALLA];

/** Fail-closed outcome. `ok: true` is the only way a record reaches a caller. */
export type ResultadoRecepcion<T> =
	| { readonly ok: true; readonly registro: T }
	| {
			readonly ok: false;
			readonly motivo: MotivoRechazoMalla;
			readonly detalle: string;
	  };

function fallo(
	motivo: MotivoRechazoMalla,
	detalle: string,
): ResultadoRecepcion<never> {
	return { ok: false, motivo, detalle };
}

// ─── WIRE SHAPES (byte fields hex-encoded) ──────────────────────────────────

/**
 * `CredencialMedica` with `Uint8Array` fields as hex. An optional field that was
 * absent stays absent: `hexABytes(undefined)` throws, and an absent optional must
 * not come back as a present zero-length one.
 */
export interface CredencialMedicaWire {
	readonly id: string;
	readonly tipo: string;
	readonly pais: string;
	readonly autoridad: string;
	readonly idLicencia: string;
	readonly numeroLicenciaCifrado?: string;
	readonly especialidad?: string;
	readonly emitidoEn: number;
	readonly vigenteHasta: number;
	readonly estadoEmision: string;
	readonly firma: string;
	readonly emisor: NodoId;
}

export interface MetodoVerificacionWire {
	readonly clase: string;
	readonly pais?: string;
	readonly versionRegistro?: string;
	readonly ref?: string;
	readonly desde?: number;
	readonly hasta?: number;
}

export interface AvalWire {
	readonly id: string;
	readonly version: number;
	readonly avalador: NodoId;
	readonly avalado: NodoId;
	readonly objetoAval: string;
	readonly credencialRef: string;
	readonly hashCredencial: string;
	readonly metodoVerificacion: MetodoVerificacionWire;
	readonly evidenciaHash: string;
	readonly alcance: string;
	readonly emitidoEn: number;
	readonly vigenteHasta: number;
	readonly revocable: true;
	readonly firma: string;
}

/**
 * A registry snapshot travels as a **sorted array of hashes**, never a `Set`.
 *
 * A `Set` is not JSON-serialisable, and its iteration order is insertion order —
 * two nodes holding the same snapshot in a different insertion order would sign
 * different bytes for identical content. Sorting is what makes the snapshot
 * hash-addressable at all.
 */
export interface RegistroPaisWire {
	readonly pais: string;
	readonly version: string;
	readonly hashes: readonly string[];
}

export function credencialAWire(
	credencial: CredencialMedica,
): CredencialMedicaWire {
	return {
		id: credencial.id,
		tipo: credencial.tipo,
		pais: credencial.pais,
		autoridad: credencial.autoridad,
		idLicencia: credencial.idLicencia,
		...(credencial.numeroLicenciaCifrado
			? { numeroLicenciaCifrado: bytesAHex(credencial.numeroLicenciaCifrado) }
			: {}),
		...(credencial.especialidad === undefined
			? {}
			: { especialidad: credencial.especialidad }),
		emitidoEn: credencial.emitidoEn,
		vigenteHasta: credencial.vigenteHasta,
		estadoEmision: credencial.estadoEmision,
		firma: bytesAHex(credencial.firma),
		emisor: credencial.emisor,
	};
}

export function avalAWire(aval: Aval): AvalWire {
	return {
		id: aval.id,
		version: aval.version,
		avalador: aval.avalador,
		avalado: aval.avalado,
		objetoAval: aval.objetoAval,
		credencialRef: aval.credencialRef,
		hashCredencial: aval.hashCredencial,
		metodoVerificacion: metodoAWire(aval.metodoVerificacion),
		evidenciaHash: aval.evidenciaHash,
		alcance: aval.alcance,
		emitidoEn: aval.emitidoEn,
		vigenteHasta: aval.vigenteHasta,
		revocable: true,
		firma: bytesAHex(aval.firma),
	};
}

export function registroAWire(
	instantanea: InstantaneaRegistroPais,
): RegistroPaisWire {
	return {
		pais: instantanea.pais,
		version: instantanea.version,
		hashes: Array.from(instantanea.hashes).sort(),
	};
}

/**
 * Rebuild the discriminated union from its wire form.
 *
 * An explicit switch over `clase`, not a generic key copy, so an unknown class
 * fails loudly instead of silently becoming an object that still type-checks as
 * `MetodoVerificacion`. A copy-through is exactly where
 * `metodoVerificacion.clase: 'inventada'` would slip into a validated record.
 */
function wireAMetodo(wire: MetodoVerificacionWire): MetodoVerificacion {
	switch (wire.clase) {
		case "registro_por_pais":
			return {
				clase: "registro_por_pais",
				pais: wire.pais ?? "",
				versionRegistro: wire.versionRegistro ?? "",
			};
		case "colegio_directo":
			return { clase: "colegio_directo", ref: wire.ref ?? "" };
		case "testimonio_directo":
			return { clase: "testimonio_directo" };
		case "supervision":
			return {
				clase: "supervision",
				desde: wire.desde ?? 0,
				hasta: wire.hasta ?? 0,
			};
		default:
			throw new TypeError(
				`wireAMetodo: clase de verificación desconocida: ${String(wire.clase)}`,
			);
	}
}

function metodoAWire(metodo: MetodoVerificacion): MetodoVerificacionWire {
	switch (metodo.clase) {
		case "registro_por_pais":
			return {
				clase: metodo.clase,
				pais: metodo.pais,
				versionRegistro: metodo.versionRegistro,
			};
		case "colegio_directo":
			return { clase: metodo.clase, ref: metodo.ref };
		case "testimonio_directo":
			return { clase: metodo.clase };
		case "supervision":
			return { clase: metodo.clase, desde: metodo.desde, hasta: metodo.hasta };
	}
}

function hexObligatorio(valor: unknown, campo: string): Uint8Array {
	if (typeof valor !== "string" || valor.length === 0) {
		throw new TypeError(
			`${campo}: se esperaba un string hex, recibido ${typeof valor}`,
		);
	}
	return hexABytes(valor);
}

/**
 * Inverse of {@link credencialAWire}.
 *
 * Takes `unknown` on purpose. The value arrives from a decrypted payload, so it
 * is attacker-influenced data: narrowing it by assertion here would push the
 * check to the caller, and a caller that forgets becomes the hole. The shape
 * assertion is cheap, and `validarCredencial` still runs before the record counts
 * as anything.
 *
 * @throws TypeError on a malformed wire payload.
 */
export function wireACredencial(wire: unknown): CredencialMedica {
	if (wire === null || typeof wire !== "object")
		throw new TypeError("wireACredencial: payload no es un objeto");
	const w = wire as CredencialMedicaWire;
	return {
		id: w.id,
		tipo: w.tipo as CredencialMedica["tipo"],
		pais: w.pais,
		autoridad: w.autoridad,
		idLicencia: w.idLicencia,
		...(w.numeroLicenciaCifrado
			? { numeroLicenciaCifrado: hexABytes(w.numeroLicenciaCifrado) }
			: {}),
		...(w.especialidad === undefined ? {} : { especialidad: w.especialidad }),
		emitidoEn: w.emitidoEn,
		vigenteHasta: w.vigenteHasta,
		estadoEmision: w.estadoEmision as CredencialMedica["estadoEmision"],
		firma: hexObligatorio(w.firma, "credencial.firma"),
		emisor: w.emisor,
	};
}

/**
 * Inverse of {@link avalAWire}. Takes `unknown` for the same trust-boundary
 * reason as {@link wireACredencial}.
 *
 * @throws TypeError on a malformed wire payload.
 */
export function wireAAval(wire: unknown): Aval {
	if (wire === null || typeof wire !== "object")
		throw new TypeError("wireAAval: payload no es un objeto");
	const w = wire as AvalWire;
	return {
		id: w.id,
		version: w.version as Aval["version"],
		avalador: w.avalador,
		avalado: w.avalado,
		objetoAval: w.objetoAval as Aval["objetoAval"],
		credencialRef: w.credencialRef,
		hashCredencial: w.hashCredencial,
		metodoVerificacion: wireAMetodo(w.metodoVerificacion),
		evidenciaHash: w.evidenciaHash,
		alcance: w.alcance as Aval["alcance"],
		emitidoEn: w.emitidoEn,
		vigenteHasta: w.vigenteHasta,
		revocable: true,
		firma: hexObligatorio(w.firma, "aval.firma"),
	};
}

// ─── EMIT ───────────────────────────────────────────────────────────────────

/**
 * What a sender needs: an identity to sign with and the encryption session the
 * payload is sealed under. Injected rather than imported so this module never
 * reaches into the mesh for a session it does not own.
 */
export interface OpcionesEmitir {
	/** Signs the sealed envelope. */
	readonly identidad: PostQuantumIdentity;
	/** Session whose AEAD key the payload is sealed under. */
	readonly sesion: SesionCifrada;
	/** Addressed recipient. Defaults to `'*'` (gossip: anyone may relay). */
	readonly destino?: NodoId;
}

/** A sealed, signed envelope plus the session advanced past it. */
export interface EmisionMedica {
	readonly env: Envolvente;
	readonly sesion: SesionCifrada;
}

/**
 * Seal then sign. Shared by all three record types because the ordering
 * constraint is identical for each; only the message type and the wire body
 * vary.
 */
async function emitir(
	tipo: (typeof TIPO_MENSAJE)[keyof typeof TIPO_MENSAJE],
	cuerpo: unknown,
	opciones: OpcionesEmitir,
): Promise<EmisionMedica> {
	// `cifrarYSiguiente` rather than `cifrarPayload` + a manual increment: it is
	// the same two lines, but it also runs `assertContadorLibre` FIRST, so a
	// reused counter is refused before anything is sealed instead of after.
	const { env, sesion } = cifrarYSiguiente(
		createEnvelope(
			tipo,
			opciones.identidad.nodoId,
			opciones.destino ?? ("*" as NodoId),
			cuerpo,
		),
		opciones.sesion,
	);
	// Sign AFTER sealing: the ML-DSA signature must cover the ciphertext, not the
	// plaintext that was just replaced by it.
	return { env: await signEnvelope(env, opciones.identidad), sesion };
}

export function emitirCredencial(
	credencial: CredencialMedica,
	opciones: OpcionesEmitir,
): Promise<EmisionMedica> {
	return emitir(TIPO_MENSAJE.CREDENCIAL, credencialAWire(credencial), opciones);
}

export function emitirAval(
	aval: Aval,
	opciones: OpcionesEmitir,
): Promise<EmisionMedica> {
	return emitir(TIPO_MENSAJE.AVAL, avalAWire(aval), opciones);
}

export function emitirRegistro(
	instantanea: InstantaneaRegistroPais,
	opciones: OpcionesEmitir,
): Promise<EmisionMedica> {
	return emitir(TIPO_MENSAJE.REGISTRO, registroAWire(instantanea), opciones);
}

// ─── RECEIVE ────────────────────────────────────────────────────────────────

/** What a receiver needs to check a message it did not create. */
export interface OpcionesRecibir {
	readonly sesion: SesionCifrada;
	/** Replay protection. Supply one to share a window across messages. */
	readonly guardia?: GuardiaReplay;
	/** The sender's identity, to verify the envelope signature. */
	readonly identidadEmisor: PostQuantumIdentity;
	readonly parPublicoEmisor: ParPublico;
}

/**
 * The shared receive prologue: shape → envelope signature → decrypt → rehydrate.
 *
 * `aplicarGuardia: false` is deliberate. The record's own ML-DSA signature is
 * checked immediately afterwards, and a record that fails that check has not been
 * accepted in any sense worth burning a replay counter over — the counter is
 * one-shot per direction, so spending it on an unauthenticated record is how a
 * peer gets its session wedged by junk. `abrirPayload` still refuses an
 * out-of-window counter when `aplicarGuardia` is left on; idempotency of the
 * record itself is carried by `Aval.id`, the key `canonica.ts#idAval` exists to
 * provide.
 */
async function recibir<T>(
	env: Envolvente,
	tipoEsperado: string,
	opciones: OpcionesRecibir,
	aRegistro: (cuerpo: unknown) => T,
): Promise<ResultadoRecepcion<T>> {
	// 1. Shape. Cheapest, and it refuses before any PQC work.
	if (!validateEnvelope(env))
		return fallo(
			MOTIVO_RECHAZO_MALLA.ENVOLVENTE_INVALIDA,
			"validateEnvelope rechazó la forma",
		);
	if (env.tipo !== tipoEsperado) {
		return fallo(
			MOTIVO_RECHAZO_MALLA.PAYLOAD_MALFORMADO,
			`tipo ${env.tipo} donde se esperaba ${tipoEsperado}`,
		);
	}

	// 2. Envelope signature, BEFORE decryption: an unsigned or forged envelope
	//    must not cost a Poly1305 open, let alone reach the record.
	const firmaOk = await verifyEnvelopeSignature(
		env,
		opciones.parPublicoEmisor,
		opciones.identidadEmisor,
	);
	if (!firmaOk) {
		return fallo(
			MOTIVO_RECHAZO_MALLA.FIRMA_ENVOLVENTE_INVALIDA,
			"la firma del envolvente no verifica contra la clave del emisor",
		);
	}

	// 3. Open the AEAD.
	let abierto: Envolvente;
	try {
		abierto = abrirPayload(
			env,
			opciones.sesion,
			opciones.guardia ?? new GuardiaReplay(),
			{ aplicarGuardia: false },
		);
	} catch (error) {
		return fallo(
			MOTIVO_RECHAZO_MALLA.PAYLOAD_NO_CIFRADO,
			error instanceof Error ? error.message : String(error),
		);
	}

	// 4. Rehydrate. A malformed body is a refusal, never a partial object.
	try {
		return { ok: true, registro: aRegistro(abierto.payload) };
	} catch (error) {
		return fallo(
			MOTIVO_RECHAZO_MALLA.PAYLOAD_MALFORMADO,
			error instanceof Error ? error.message : String(error),
		);
	}
}

/**
 * Receive and fully verify a credential.
 *
 * @param verificarFirma pass `false` only when the caller has already established
 *   the issuer's key by another route; the default re-checks the record's own
 *   signature, which is what binds the claim to `emisor`.
 */
export async function recibirCredencial(
	env: Envolvente,
	opciones: OpcionesRecibir,
	verificarFirma = true,
): Promise<ResultadoRecepcion<CredencialMedica>> {
	const base = await recibir(
		env,
		TIPO_MENSAJE.CREDENCIAL,
		opciones,
		wireACredencial,
	);
	if (!base.ok) return base;
	if (!verificarFirma) return base;
	const firmaOk = await verificarFirmaCredencial(
		base.registro,
		opciones.identidadEmisor,
		opciones.parPublicoEmisor,
	);
	if (!firmaOk) {
		return fallo(
			MOTIVO_RECHAZO_MALLA.FIRMA_REGISTRO_INVALIDA,
			`la firma de la credencial no verifica contra la clave de ${base.registro.emisor}`,
		);
	}
	return base;
}

/** Receive and fully verify an endorsement. Mirrors {@link recibirCredencial}. */
export async function recibirAval(
	env: Envolvente,
	opciones: OpcionesRecibir,
	verificarFirma = true,
): Promise<ResultadoRecepcion<Aval>> {
	const base = await recibir(env, TIPO_MENSAJE.AVAL, opciones, wireAAval);
	if (!base.ok) return base;
	if (!verificarFirma) return base;
	const firmaOk = await verificarFirmaAval(
		base.registro,
		opciones.identidadEmisor,
		opciones.parPublicoEmisor,
	);
	if (!firmaOk) {
		return fallo(
			MOTIVO_RECHAZO_MALLA.FIRMA_REGISTRO_INVALIDA,
			`la firma del aval no verifica contra la clave de ${base.registro.avalador}`,
		);
	}
	return base;
}

// ─── GOSSIP ADAPTER (no mesh file is edited) ────────────────────────────────

/**
 * Discriminator for the gossip payload, mirroring `PAYLOAD_KARMA_TIPO` in
 * `src/mesh/index.ts`. Namespaced so a medical message is never mistaken for
 * another gossip payload kind by a listener that dispatches on `tipo`.
 */
export const PAYLOAD_MEDICO_TIPO = "medico:v1" as const;

/**
 * Exactly the object `MeshManager.transmitirConGossip(namespace, payload)` already
 * accepts, so wiring the medical layer into gossip is one method next to
 * `transmitirKarma` — not a transport change, and not this file's job.
 *
 * The envelope travels **whole**, sealed and signed, because a gossip `payload`
 * slot is opaque and the node that finally reads a relayed message is not
 * necessarily the one the session was established with: it cannot open the
 * ciphertext. Confidentiality therefore holds for the direct leg only, and a
 * relayed credential arrives still sealed — which is why routing a relayed record
 * needs per-hop re-sealing, not just a `transmitir` call.
 */
export function aPayloadGossipMedico(env: Envolvente): {
	readonly tipo: typeof PAYLOAD_MEDICO_TIPO;
	readonly env: Envolvente;
} {
	return { tipo: PAYLOAD_MEDICO_TIPO, env };
}
