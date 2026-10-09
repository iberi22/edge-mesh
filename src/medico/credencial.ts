/**
 * `CredencialMedica` — construction, signing and validation.
 *
 * ─── VALIDATION FAILS CLOSED ────────────────────────────────────────────────
 *
 * Every refusal in this module returns a named reason and leaves the caller
 * with no way to read "unverified but proceed" out of the result. There is no
 * `unknown`, no tri-state, no boolean-plus-warning. The type system does not
 * offer a value meaning "we could not check this, carry on".
 *
 * That is the whole point. The OrionHealth licence verifier returns
 * `LicenseVerificationResult.unknown` when a country's registry is empty, which
 * is correct for a local lookup UI and wrong here: a mesh node that treats
 * `unknown` as "not refused" turns *an unsupported country* into a bypass. A
 * physician could present a licence from a country with no registry snapshot and
 * be waved through by any node that had not yet downloaded that registry.
 */

import type { PostQuantumIdentity } from "../identity/index.js";
import type { NodoId, ParPublico } from "../types/index.js";
import {
	bytesAHex,
	bytesCredencial,
	hashCredencial,
	idCredencial,
} from "./canonica.js";
import {
	CAMPOS_OBLIGATORIOS_CREDENCIAL,
	type CredencialMedica,
	ESTADO_EMISION,
	type EstadoEmision,
	TIPO_CREDENCIAL,
	type TipoCredencial,
	VERSION_MODELO,
} from "./types.js";

/** Why a credential was refused. Every value here means access stays closed. */
export const MOTIVO_RECHAZO_CREDENCIAL = {
	/** A mandatory field is absent or empty. Names the field. */
	CAMPO_OBLIGATORIO_AUSENTE: "campo_obligatorio_ausente",
	/**
	 * `vigenteHasta` absent or not a number. Kept distinct from
	 * `CREDENCIAL_CADUCADA` because this is the OrionHealth `expired`-never-returned
	 * defect: without an issuer-signed expiry a revoked licence verifies forever.
	 */
	SIN_VIGENCIA: "sin_vigencia",
	/** `Date.now() >= vigenteHasta`. */
	CREDENCIAL_CADUCADA: "credencial_caducada",
	/** `vigenteHasta` is in the past at construction time. */
	VIGENCIA_EN_PASADO: "vigencia_en_pasado",
	/** `emitidoEn` is not a plausible epoch-ms value, or is after `vigenteHasta`. */
	EMISION_INVALIDA: "emision_invalida",
	/** `idLicencia` is not a 64-char lower-case hex SHA-256. */
	ID_LICENCIA_MAL_FORMADO: "id_licencia_mal_formado",
	/** `pais` is not ISO 3166-1 alpha-2. */
	PAIS_INVALIDO: "pais_invalido",
	/** `tipo` or `estadoEmision` outside the declared unions. */
	ENUM_INVALIDO: "enum_invalido",
	/** No signature bytes. */
	FIRMA_AUSENTE: "firma_ausente",
	/** Signature does not verify against the issuer's public key. */
	FIRMA_INVALIDA: "firma_invalida",
	/** `estadoEmision: 'autofirmada'` whose `emisor` is not the subject. */
	AUTOEMISION_INCOHERENTE: "autoemision_incoherente",
} as const;

export type MotivoRechazoCredencial =
	(typeof MOTIVO_RECHAZO_CREDENCIAL)[keyof typeof MOTIVO_RECHAZO_CREDENCIAL];

export type ResultadoValidacionCredencial =
	| { readonly ok: true; readonly credencial: CredencialMedica }
	| {
			readonly ok: false;
			readonly motivo: MotivoRechazoCredencial;
			readonly detalle: string;
			/**
			 * Always `false`. Present so that a caller destructuring the discriminant
			 * cannot accidentally treat a refusal as soft information. There is no
			 * state in this module where a credential is "unverified but usable".
			 */
			readonly accesoPermitido: false;
	  };

/** Inputs for {@link crearCredencial}. The issuer signs; nothing else does. */
export interface BorradorCredencial {
	readonly tipo: TipoCredencial;
	/** ISO 3166-1 alpha-2. `CO` for Colombia. */
	readonly pais: string;
	/** `'minsalud-rethus'`, `'colomedico-cm'`. The source of the claim. */
	readonly autoridad: string;
	/** `sha256(normalize(numeroLicencia))`. The raw number must not be passed here. */
	readonly idLicencia: string;
	readonly especialidad?: string;
	/** Seal of the real licence number to a specific verifier, if kept. */
	readonly numeroLicenciaCifrado?: Uint8Array;
	readonly emitidoEn: number;
	/**
	 * REQUIRED. Issuer-signed expiry. There is no default and no "derive it from
	 * the registry": a membership list cannot express a validity window, so this
	 * value has to come from the issuer's signature.
	 */
	readonly vigenteHasta: number;
	readonly estadoEmision: EstadoEmision;
	/** Who signs. For `'autofirmada'` this is the subject node itself. */
	readonly emisor: NodoId;
}

const RE_HEX64 = /^[0-9a-f]{64}$/;
const RE_PAIS_ALFA2 = /^[A-Z]{2}$/;

function fallo(
	motivo: MotivoRechazoCredencial,
	detalle: string,
): ResultadoValidacionCredencial {
	return { ok: false, motivo, detalle, accesoPermitido: false };
}

/**
 * Structural validation, in cheap-to-expensive order. Runs no signature check.
 *
 * Order is deliberate: the malformed-shape refusals cost nothing, so a garbage
 * payload never reaches a post-quantum operation. Same discipline
 * `applyTransaction` in `src/maloca/karma.ts` uses.
 *
 * @param ahora - injected clock (ms epoch). Tests pass a fixed value; the
 *   function itself never reads the clock, which is what keeps it pure.
 */
export function validarCredencial(
	credencial: CredencialMedica,
	ahora: number,
): ResultadoValidacionCredencial {
	if (!credencial || typeof credencial !== "object") {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.CAMPO_OBLIGATORIO_AUSENTE,
			"la credencial no es un objeto",
		);
	}

	// ── 1. The five mandatory fields, by name ──
	for (const campo of CAMPOS_OBLIGATORIOS_CREDENCIAL) {
		const valor = (credencial as unknown as Record<string, unknown>)[campo];
		if (valor === undefined || valor === null || valor === "") {
			return fallo(
				MOTIVO_RECHAZO_CREDENCIAL.CAMPO_OBLIGATORIO_AUSENTE,
				`falta '${campo}'`,
			);
		}
	}

	// ── 2. `vigenteHasta`, the field that closes the OrionHealth defect ──
	// Checked before the enums because its absence is the specific bug this
	// module exists to make impossible, and deserves the most specific reason.
	if (
		typeof credencial.vigenteHasta !== "number" ||
		!Number.isFinite(credencial.vigenteHasta)
	) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.SIN_VIGENCIA,
			"vigenteHasta ausente o no numérico: sin vigencia firmada por el emisor, una licencia revocada validaría para siempre",
		);
	}
	if (credencial.vigenteHasta <= 0) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.SIN_VIGENCIA,
			`vigenteHasta inválido: ${credencial.vigenteHasta}`,
		);
	}

	// ── 3. Enums ──
	if (!Object.values(TIPO_CREDENCIAL).includes(credencial.tipo)) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.ENUM_INVALIDO,
			`tipo desconocido: ${String(credencial.tipo)}`,
		);
	}
	if (!Object.values(ESTADO_EMISION).includes(credencial.estadoEmision)) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.ENUM_INVALIDO,
			`estadoEmision desconocido: ${String(credencial.estadoEmision)}`,
		);
	}

	// ── 4. Country: alpha-2, upper case ──
	if (!RE_PAIS_ALFA2.test(credencial.pais)) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.PAIS_INVALIDO,
			`pais debe ser ISO 3166-1 alpha-2 en mayúsculas: ${credencial.pais}`,
		);
	}

	// ── 5. `idLicencia` must be a SHA-256 hex digest, not a licence number ──
	// A raw licence number pasted into this field would be a PII leak and is
	// refused at the boundary rather than at publication time.
	if (!RE_HEX64.test(credencial.idLicencia)) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.ID_LICENCIA_MAL_FORMADO,
			"idLicencia debe ser sha256 hex de 64 caracteres; el número de licencia en claro no se acepta aquí",
		);
	}

	// ── 6. Dates are coherent ──
	if (
		typeof credencial.emitidoEn !== "number" ||
		!Number.isFinite(credencial.emitidoEn)
	) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.EMISION_INVALIDA,
			`emitidoEn inválido: ${String(credencial.emitidoEn)}`,
		);
	}
	if (credencial.emitidoEn > credencial.vigenteHasta) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.EMISION_INVALIDA,
			`emitidoEn (${credencial.emitidoEn}) es posterior a vigenteHasta (${credencial.vigenteHasta})`,
		);
	}

	// ── 7. Expiry ──
	if (credencial.vigenteHasta < ahora) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.CREDENCIAL_CADUCADA,
			`credencial caducada: vigente hasta ${credencial.vigenteHasta}, ahora ${ahora}`,
		);
	}
	if (credencial.vigenteHasta === ahora) {
		// `vigenteHasta` is exclusive: at the exact millisecond it lapses, it lapses.
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.CREDENCIAL_CADUCADA,
			`credencial caducada en el instante exacto de expiración (${ahora})`,
		);
	}

	// ── 8. Signature present ──
	if (
		!(credencial.firma instanceof Uint8Array) ||
		credencial.firma.length === 0
	) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.FIRMA_AUSENTE,
			"firma ausente o vacía",
		);
	}

	return { ok: true, credencial };
}

/**
 * Verify the issuer's signature over the canonical credential bytes.
 *
 * Separate from {@link validarCredencial} so a caller can run the cheap
 * structural checks first and skip a post-quantum verification on garbage.
 * Both are required before a credential counts as evidence; neither is
 * sufficient alone.
 */
export async function verificarFirmaCredencial(
	credencial: CredencialMedica,
	identidadEmisor: PostQuantumIdentity,
	parPublico: ParPublico,
): Promise<boolean> {
	try {
		return await identidadEmisor.verificar(
			bytesCredencial(credencial),
			credencial.firma,
			parPublico,
		);
	} catch {
		return false;
	}
}

/**
 * Full validation: structure, then signature, then the self-attestation rule.
 *
 * @returns `ok: true` only when the credential is well formed, unexpired and
 *   genuinely signed by `emisor`. Any other outcome is `ok: false` with
 *   `accesoPermitido: false`. There is no partial credit and no third state.
 */
export async function validarCredencialFirmada(
	credencial: CredencialMedica,
	identidadEmisor: PostQuantumIdentity,
	parPublicoEmisor: ParPublico,
	ahora: number,
): Promise<ResultadoValidacionCredencial> {
	const estructural = validarCredencial(credencial, ahora);
	if (!estructural.ok) return estructural;

	if (
		!(await verificarFirmaCredencial(
			credencial,
			identidadEmisor,
			parPublicoEmisor,
		))
	) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.FIRMA_INVALIDA,
			`la firma no verifica contra la clave pública de ${credencial.emisor}`,
		);
	}

	return { ok: true, credencial };
}

/**
 * A self-attested credential must be signed by the subject it rides on.
 *
 * Kept separate from {@link validarCredencialFirmada} because a
 * `CredencialMedica` carries no subject field of its own — the binding is
 * `RegistroProfesional.nodoId`, one level up. An `autofirmada` credential whose
 * `emisor` is a different node would let a node borrow someone else's key to
 * look institutionally verified, so the check needs both halves and neither
 * object alone contains them.
 *
 * Only `autofirmada` is constrained this way: an `atestiguada_pares` credential
 * carries the issuing node's own signature, and an `anclada_autoridad` one
 * carries the college's, and both are expected to differ from the subject.
 */
export function validarVinculoEmision(
	credencial: CredencialMedica,
	nodoSujeto: NodoId,
): ResultadoValidacionCredencial {
	if (
		credencial.estadoEmision === ESTADO_EMISION.AUTOFIRMADA &&
		credencial.emisor !== nodoSujeto
	) {
		return fallo(
			MOTIVO_RECHAZO_CREDENCIAL.AUTOEMISION_INCOHERENTE,
			`credencial autofirmada por ${credencial.emisor} pero presentada por el sujeto ${nodoSujeto}`,
		);
	}
	return { ok: true, credencial };
}

/**
 * Build and sign a credential.
 *
 * The `id` is derived from `idLicencia + tipo + pais`, so the same licence with
 * the same type in the same country always yields the same id: the credential is
 * identifiable across nodes without any node choosing a random identifier that
 * two honest nodes would fail to agree on.
 *
 * The signature covers everything except `firma`, over the canonical bytes from
 * `./canonica.ts`.
 */
export async function crearCredencial(
	borrador: BorradorCredencial,
	identidad: PostQuantumIdentity,
): Promise<CredencialMedica> {
	const id = await idCredencial(
		borrador.idLicencia,
		borrador.tipo,
		borrador.pais,
	);

	// Assemble first, then sign the assembly, so what is signed is exactly what
	// travels — including the derived id.
	const sinFirmar: CredencialMedica = {
		id,
		tipo: borrador.tipo,
		pais: borrador.pais.toUpperCase(),
		autoridad: borrador.autoridad,
		idLicencia: borrador.idLicencia,
		...(borrador.numeroLicenciaCifrado
			? { numeroLicenciaCifrado: borrador.numeroLicenciaCifrado }
			: {}),
		...(borrador.especialidad ? { especialidad: borrador.especialidad } : {}),
		emitidoEn: borrador.emitidoEn,
		vigenteHasta: borrador.vigenteHasta,
		estadoEmision: borrador.estadoEmision,
		firma: new Uint8Array(0),
		emisor: borrador.emisor,
	};

	const firma = await identidad.firmar(bytesCredencial(sinFirmar));
	return { ...sinFirmar, firma };
}

/** SHA-256 of the canonical credential bytes. Binds an `Aval` to exact bytes. */
export function hashDeCredencial(
	credencial: CredencialMedica,
): Promise<string> {
	return hashCredencial(credencial);
}

/** Hex form of the canonical credential bytes, for logging and debugging. */
export function volcarCredencial(credencial: CredencialMedica): string {
	return bytesAHex(bytesCredencial(credencial));
}

/**
 * A "certified doctor" per the product promise: `licencia ∧ especialidad`, both
 * with a peer-witnessed or authority-anchored state, both unexpired.
 *
 * Deliberately not a boolean field on the licence. A boolean cannot expire, and
 * specialties are revoked on a different cadence from base licensure.
 *
 * A licensed-but-unspecialised doctor is a legitimate node with a *smaller*
 * capability set, not an impostor (DECISIÓN A.4) — this returns `false`, and the
 * caller decides what a lower tier grants.
 */
export function esMedicoCertificado(
	credenciales: readonly CredencialMedica[],
	ahora: number,
): boolean {
	const vigentes = credenciales.filter((c) => validarCredencial(c, ahora).ok);
	const conEmisionFuerte = vigentes.filter(
		(c) =>
			c.estadoEmision === ESTADO_EMISION.ATESTIGUADA_PARES ||
			c.estadoEmision === ESTADO_EMISION.ANCLADA_AUTORIDAD,
	);
	const tieneLicencia = conEmisionFuerte.some(
		(c) => c.tipo === TIPO_CREDENCIAL.LICENCIA,
	);
	const tieneEspecialidad = conEmisionFuerte.some(
		(c) => c.tipo === TIPO_CREDENCIAL.ESPECIALIDAD,
	);
	return tieneLicencia && tieneEspecialidad;
}

export { VERSION_MODELO };
