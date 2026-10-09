/**
 * `Aval` — the peer endorsement, and the line it cannot cross.
 *
 * ─── WHY AN AVAL IS STRUCTURALLY NOT A CITA ─────────────────────────────────
 *
 * An `Aval` is a peer assertion *about a claim*: `avalador → avalado`, subject =
 * a credential hash, carrying `metodoVerificacion` (how the checker checked) and
 * no patient, no date of encounter, no diagnosis, no content. A `Cita` is a
 * patient assertion *about an encounter*, and needs none of those fields.
 *
 * Conflating them destroys the anti-Sybil property, so the separation is
 * enforced three ways here: the type carries a closed `objetoAval` union, the
 * endorsement counter in {@link resumirAvales} only counts the two objects that
 * are about licensure, and {@link OBJETO_QUE_CUENTA} is the single place that
 * decision lives.
 *
 * ─── THE LOAD-BEARING RULE ───────────────────────────────────────────────────
 *
 * Only `licencia_verificada` and `especialidad_verificada` promote a credential
 * to `atestiguada_pares`. An `Aval` of `interaccion_clinica` proves the claimer
 * *treated patients*, not that they are *licensed*. Allowing clinical `Aval`s to
 * count is precisely the hole that lets a well-liked non-doctor buy their way
 * into a network of doctors — money can buy encounters, and it cannot buy a
 * government record.
 */

import type { PostQuantumIdentity } from "../identity/index.js";
import type { TransaccionKarma } from "../maloca/types.js";
import type { NodoId, ParPublico } from "../types/index.js";
import { bytesAval, hashCredencial, hashLicencia, idAval } from "./canonica.js";
import {
	ALCANCE_AVAL,
	type AlcanceAval,
	type Aval,
	CLASE_VERIFICACION,
	type MetodoVerificacion,
	OBJETO_AVAL,
	type ObjetoAval,
	type ResumenAvales,
	VERSION_MODELO,
} from "./types.js";

/** Why an `Aval` was refused. Every value means it does not count. */
export const MOTIVO_RECHAZO_AVAL = {
	/** `avalador === avalado`. The `auto_emision` rule, copied. */
	AUTO_ENDORSEMENT: "auto_endorsement",
	/** No signature bytes. */
	FIRMA_AUSENTE: "firma_ausente",
	/** Signature does not verify against the avalador's public key. */
	FIRMA_INVALIDA: "firma_invalida",
	/** `objetoAval`, `alcance`, `revocable` or `metodoVerificacion.clase` invalid. */
	CAMPO_INVALIDO: "campo_invalido",
	/** `emitidoEn` / `vigenteHasta` incoherent. */
	VIGENCIA_INVALIDA: "vigencia_invalida",
	/** The `Aval` has lapsed. */
	AVAL_CADUCADO: "aval_caducado",
	/** `metodoVerificacion: 'registro_por_pais'` without `versionRegistro`. */
	VERSION_REGISTRO_AUSENTE: "version_registro_ausente",
} as const;

export type MotivoRechazoAval =
	(typeof MOTIVO_RECHAZO_AVAL)[keyof typeof MOTIVO_RECHAZO_AVAL];

export type ResultadoValidacionAval =
	| { readonly ok: true; readonly aval: Aval }
	| {
			readonly ok: false;
			readonly motivo: MotivoRechazoAval;
			readonly detalle: string;
			/** Always `false` — an `Aval` that does not validate never counts. */
			readonly cuentaParaPromocion: false;
	  };

function fallo(
	motivo: MotivoRechazoAval,
	detalle: string,
): ResultadoValidacionAval {
	return { ok: false, motivo, detalle, cuentaParaPromocion: false };
}

/**
 * The only `objetoAval` values that may promote a credential to
 * `atestiguada_pares`.
 *
 * Exported as data so that the rule has exactly one definition in the codebase.
 * If a test, a counter or a threshold function disagreed with this set, a
 * clinical `Aval` would end up counting toward licensure somewhere.
 */
export const OBJETO_QUE_CUENTA = [
	OBJETO_AVAL.LICENCIA_VERIFICADA,
	OBJETO_AVAL.ESPECIALIDAD_VERIFICADA,
] as const;

export function avalCuentaParaPromocion(objeto: ObjetoAval): boolean {
	return (OBJETO_QUE_CUENTA as readonly ObjetoAval[]).includes(objeto);
}

/** Inputs for {@link crearAval}. */
export interface BorradorAval {
	readonly avalador: NodoId;
	readonly avalado: NodoId;
	readonly objetoAval: ObjetoAval;
	/** `id` of the credential being endorsed. */
	readonly credencialRef: string;
	/** The exact credential bytes the avalador checked. Hashed internally. */
	readonly hashCredencial: string;
	readonly metodoVerificacion: MetodoVerificacion;
	/** Hash of the artefact relied upon, if any. */
	readonly evidenciaHash: string;
	readonly alcance: AlcanceAval;
	readonly emitidoEn: number;
	readonly vigenteHasta: number;
	/** Uniqueness component of the id, so replaying does not collide. */
	readonly nonce: string;
}

/**
 * Structural validation of an `Aval`, no signature check. Cheap first, PQC last,
 * same ordering as the credential path.
 *
 * @param ahora - injected clock (ms epoch). The function never reads the clock
 *   itself, which is what keeps it pure.
 */
export function validarAval(
	aval: Aval,
	ahora: number,
): ResultadoValidacionAval {
	if (!aval || typeof aval !== "object") {
		return fallo(MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO, "el aval no es un objeto");
	}

	// ── Self-endorsement, refused first and unconditionally ──
	// `KarmaManager.applyTransaction` refuses `emisor === sujeto` with
	// `auto_emision`; the same rule, copied, because the failure mode is identical
	// (one node manufacturing its own evidence).
	if (aval.avalador === aval.avalado) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.AUTO_ENDORSEMENT,
			`${aval.avalador} no puede avalarse a sí mismo (equivale a auto_emision en karma.ts)`,
		);
	}

	if (aval.version !== VERSION_MODELO) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
			`version no soportada: ${String(aval.version)}`,
		);
	}

	if (!Object.values(OBJETO_AVAL).includes(aval.objetoAval)) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
			`objetoAval desconocido: ${String(aval.objetoAval)}`,
		);
	}
	if (!Object.values(ALCANCE_AVAL).includes(aval.alcance)) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
			`alcance desconocido: ${String(aval.alcance)}`,
		);
	}
	if (aval.revocable !== true) {
		// An `Aval` that is not revocable is a permanent fact, and the design says
		// endorsements must be revocable (`docs/medico/protocolo.md` §5).
		return fallo(
			MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
			"revocable debe ser true: todo aval es revocable",
		);
	}

	if (!aval.credencialRef || !aval.hashCredencial) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
			"un aval debe referirse a una credencial concreta (credencialRef + hashCredencial)",
		);
	}

	// ── `metodoVerificacion` must be complete for its class ──
	const metodo = aval.metodoVerificacion;
	if (!metodo || !Object.values(CLASE_VERIFICACION).includes(metodo.clase)) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
			"metodoVerificacion.clase desconocida",
		);
	}
	if (metodo.clase === CLASE_VERIFICACION.REGISTRO_POR_PAIS) {
		// Mandatory so a stale snapshot is visible on the face of the record. A
		// registry check with no version cannot be reasoned about later.
		if (!metodo.versionRegistro) {
			return fallo(
				MOTIVO_RECHAZO_AVAL.VERSION_REGISTRO_AUSENTE,
				"registro_por_pais exige versionRegistro: sin ella un snapshot obsoleto es indistinguible de uno fresco",
			);
		}
		if (!metodo.pais) {
			return fallo(
				MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
				"registro_por_pais exige pais",
			);
		}
	}
	if (metodo.clase === CLASE_VERIFICACION.COLEGIO_DIRECTO && !metodo.ref) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
			"colegio_directo exige ref",
		);
	}
	if (metodo.clase === CLASE_VERIFICACION.SUPERVISION) {
		if (typeof metodo.desde !== "number" || typeof metodo.hasta !== "number") {
			return fallo(
				MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO,
				"supervision exige desde y hasta",
			);
		}
		if (metodo.desde > metodo.hasta) {
			return fallo(
				MOTIVO_RECHAZO_AVAL.VIGENCIA_INVALIDA,
				`supervision desde (${metodo.desde}) > hasta (${metodo.hasta})`,
			);
		}
	}

	// ── Dates ──
	if (typeof aval.emitidoEn !== "number" || !Number.isFinite(aval.emitidoEn)) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.VIGENCIA_INVALIDA,
			`emitidoEn inválido: ${String(aval.emitidoEn)}`,
		);
	}
	if (
		typeof aval.vigenteHasta !== "number" ||
		!Number.isFinite(aval.vigenteHasta)
	) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.VIGENCIA_INVALIDA,
			"vigenteHasta ausente o no numérico",
		);
	}
	if (aval.emitidoEn > aval.vigenteHasta) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.VIGENCIA_INVALIDA,
			`emitidoEn (${aval.emitidoEn}) es posterior a vigenteHasta (${aval.vigenteHasta})`,
		);
	}
	if (aval.vigenteHasta <= ahora) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.AVAL_CADUCADO,
			`aval caducado: vigente hasta ${aval.vigenteHasta}, ahora ${ahora}`,
		);
	}

	if (!(aval.firma instanceof Uint8Array) || aval.firma.length === 0) {
		return fallo(MOTIVO_RECHAZO_AVAL.FIRMA_AUSENTE, "firma ausente o vacía");
	}

	return { ok: true, aval };
}

/**
 * Verify the avalador's signature over the canonical `Aval` bytes.
 *
 * Note the key must be the *avalador's*, never the avalado's: the whole content
 * of an endorsement is that a second party looked and agreed.
 */
export async function verificarFirmaAval(
	aval: Aval,
	identidad: PostQuantumIdentity,
	parPublicoAvalador: ParPublico,
): Promise<boolean> {
	try {
		return await identidad.verificar(
			bytesAval(aval),
			aval.firma,
			parPublicoAvalador,
		);
	} catch {
		return false;
	}
}

/** Full validation: structure, then signature. */
export async function validarAvalFirmado(
	aval: Aval,
	identidad: PostQuantumIdentity,
	parPublicoAvalador: ParPublico,
	ahora: number,
): Promise<ResultadoValidacionAval> {
	const estructural = validarAval(aval, ahora);
	if (!estructural.ok) return estructural;

	if (!(await verificarFirmaAval(aval, identidad, parPublicoAvalador))) {
		return fallo(
			MOTIVO_RECHAZO_AVAL.FIRMA_INVALIDA,
			`la firma no verifica contra la clave pública de ${aval.avalador}`,
		);
	}
	return { ok: true, aval };
}

/**
 * Build and sign an `Aval`.
 *
 * `hashCredencial` is computed from the credential object rather than taken on
 * trust, so an `Aval` cannot be minted against a hash that does not match the
 * bytes it claims to have checked.
 */
export async function crearAval(
	borrador: BorradorAval,
	identidadAvalador: PostQuantumIdentity,
	credencialVerificada: { readonly hash: string },
): Promise<Aval> {
	const id = idAval(
		borrador.avalador,
		borrador.avalado,
		borrador.emitidoEn,
		borrador.nonce,
	);

	if (credencialVerificada.hash !== borrador.hashCredencial) {
		throw new Error(
			`crearAval: hashCredencial (${borrador.hashCredencial}) no corresponde a la credencial verificada (${credencialVerificada.hash})`,
		);
	}

	const sinFirmar: Aval = {
		id,
		version: VERSION_MODELO,
		avalador: borrador.avalador,
		avalado: borrador.avalado,
		objetoAval: borrador.objetoAval,
		credencialRef: borrador.credencialRef,
		hashCredencial: borrador.hashCredencial,
		metodoVerificacion: borrador.metodoVerificacion,
		evidenciaHash: borrador.evidenciaHash,
		alcance: borrador.alcance,
		emitidoEn: borrador.emitidoEn,
		vigenteHasta: borrador.vigenteHasta,
		revocable: true,
		firma: new Uint8Array(0),
	};

	const firma = await identidadAvalador.firmar(bytesAval(sinFirmar));
	return { ...sinFirmar, firma };
}

/** Convenience: hash a credential's canonical bytes for use in `crearAval`. */
export function prepararCredencialParaAval(
	credencial: Parameters<typeof hashCredencial>[0],
): Promise<string> {
	return hashCredencial(credencial);
}

/** Convenience: `sha256(normalize(numeroLicencia))`. Never pass the number itself. */
export function idLicenciaDesdeNumero(numeroLicencia: string): Promise<string> {
	return hashLicencia(numeroLicencia);
}

/**
 * Fold live `Aval`s into a {@link ResumenAvales}.
 *
 * This fold, not a stored fact, is what makes `atestiguada_pares` revocable:
 * drop a revocation and the count falls on the next recomputation.
 *
 * Only unexpired, self-consistent `Aval`s are counted, and only the two
 * licensure objects feed {@link ResumenAvales.verificacionesLicencia}.
 * `avaladoresUnicos` counts distinct signers, not `Aval`s, so one peer endorsing
 * fifty times cannot move the threshold.
 *
 * @param ahora - injected clock. Pure: the function never reads time itself.
 */
export function resumirAvales(
	avales: readonly Aval[],
	ahora: number,
): ResumenAvales {
	const porObjeto = {
		[OBJETO_AVAL.LICENCIA_VERIFICADA]: 0,
		[OBJETO_AVAL.ESPECIALIDAD_VERIFICADA]: 0,
		[OBJETO_AVAL.INTERACCION_CLINICA]: 0,
		[OBJETO_AVAL.DOCENCIA]: 0,
	} as Record<ObjetoAval, number>;

	const avaladoresUnicos = new Set<NodoId>();
	const avaladoresDeLicencia = new Set<NodoId>();
	let ultimoAval: number | undefined;
	let total = 0;

	for (const aval of avales) {
		// Signature verification needs a public key and is async, so it is the
		// caller's job (Phase 3) to hand over already-verified `Aval`s. Structural
		// validity plus expiry is what this pure fold can check on its own.
		if (!validarAval(aval, ahora).ok) continue;

		porObjeto[aval.objetoAval] = (porObjeto[aval.objetoAval] ?? 0) + 1;
		avaladoresUnicos.add(aval.avalador);
		if (avalCuentaParaPromocion(aval.objetoAval))
			avaladoresDeLicencia.add(aval.avalador);
		if (ultimoAval === undefined || aval.emitidoEn > ultimoAval)
			ultimoAval = aval.emitidoEn;
		total++;
	}

	return {
		total,
		porObjeto,
		avaladoresUnicos: avaladoresUnicos.size,
		verificacionesLicencia: avaladoresDeLicencia.size,
		...(ultimoAval === undefined ? {} : { ultimoAval }),
	};
}

/**
 * Adapt an `Aval` to the existing {@link TransaccionKarma} shape.
 *
 * The signature envelope of an endorsement — `id`, `emisor`, `timestamp`,
 * `firma` — is karma's, reused rather than reinvented, so an `Aval` can ride
 * the OpLog and the replay/idempotency path that already exist.
 *
 * `razon` states *what was verified and how*, so the karma ledger is auditable
 * without a join back to the `Aval`. The subject is the **endorsed** node, which
 * is the node earning standing — matching karma's `sujeto` semantics.
 *
 * `delta` is deliberately left to the caller as `deltaPorAvalacion`: the weight
 * of an `Aval` is a policy decision (DECISIÓN B.3), and this module must not
 * quietly pick one. Note that karma is a *signal* and never grants access
 * (`docs/medico/reglas-red.md` §1).
 */
export function aTransaccionKarma(
	aval: Aval,
	deltaPorAvalacion: number,
): TransaccionKarma {
	return {
		id: aval.id,
		tipo: "aval",
		proyecto: aval.objetoAval,
		sujeto: aval.avalado,
		delta: deltaPorAvalacion,
		razon: `${aval.objetoAval} via ${aval.metodoVerificacion.clase}`,
		emisor: aval.avalador,
		timestamp: aval.emitidoEn,
		firma: aval.firma,
	};
}
