/**
 * `RegistroProfesional` — the professional half of a node's public record, and
 * the rules that keep a node from being mistaken for a person.
 *
 * ─── WHAT THIS TYPE DELIBERATELY CANNOT HOLD ────────────────────────────────
 *
 * There is no field here capable of holding a patient record. Not "we won't
 * populate it" — the shape does not admit it. Health data is a special category
 * under GDPR Art. 9 and sensitive under Ley 1581/2012 Art. 5, whose
 * household/personal exemption of Art. 2(a) is lost the moment a peer node
 * holds a copy. A mesh is a replication substrate (`src/op-log/index.ts`,
 * `src/snapshot/index.ts`): anything written is designed to be copied and kept,
 * so a patient's record inside an OpLog is a breach waiting for a payload bug,
 * and no amount of per-envelope encryption helps once five nodes hold the
 * cleartext. Any future feature needing patient-adjacent data needs a different
 * transport, not a field added here.
 *
 * ─── ONE HUMAN, SEVERAL NODES ───────────────────────────────────────────────
 *
 * We never assert `nodoId → person`. A physician may legitimately run a private
 * clinical node and a public teaching node — different trust surfaces. The
 * per-human fact we store is `idLicencia`, and the anti-Sybil rules in
 * `docs/medico/reglas-red.md` are built on that, not on `nodoId`. Note the
 * consequence: because `nodoId` is derived from the KEM key, key rotation
 * changes it, so a `nodoId` change on a known physician is a *new node*
 * requiring re-validation of layer 1 — never a continuity.
 */

import { resumirAvales } from "./aval.js";
import {
	esMedicoCertificado,
	MOTIVO_RECHAZO_CREDENCIAL,
	validarCredencial,
} from "./credencial.js";
import {
	type CredencialMedica,
	type RegistroProfesional,
	TIPO_CREDENCIAL,
} from "./types.js";

/** Why a `RegistroProfesional` was refused. */
export const MOTIVO_RECHAZO_REGISTRO = {
	/** Not an object, or `version` unsupported. */
	ESTRUCTURA_INVALIDA: "estructura_invalida",
	/** A credential inside failed `validarCredencial`. */
	CREDENCIAL_INVALIDA: "credencial_invalida",
	/** Two credentials in the same record share an `id`. */
	CREDENCIAL_DUPLICADA: "credencial_duplicada",
	/** `declaracion.jurisdiccion` missing or not ISO alpha-2. */
	JURISDICCION_INVALIDA: "jurisdiccion_invalida",
	/** `especialidades` claims a specialty with no matching credential. */
	ESPECIALIDAD_SIN_CREDENCIAL: "especialidad_sin_credencial",
	/** A specialty credential with `tipo: 'especialidad'` and no `especialidad`. */
	ESPECIALIDAD_SIN_NOMBRE: "especialidad_sin_nombre",
} as const;

export type MotivoRechazoRegistro =
	(typeof MOTIVO_RECHAZO_REGISTRO)[keyof typeof MOTIVO_RECHAZO_REGISTRO];

export type ResultadoValidacionRegistro =
	| {
			readonly ok: true;
			readonly registro: RegistroProfesional;
			readonly esCertificado: boolean;
	  }
	| {
			readonly ok: false;
			readonly motivo: MotivoRechazoRegistro;
			readonly detalle: string;
			readonly accesoPermitido: false;
	  };

const RE_PAIS_ALFA2 = /^[A-Z]{2}$/;

function fallo(
	motivo: MotivoRechazoRegistro,
	detalle: string,
): ResultadoValidacionRegistro {
	return { ok: false, motivo, detalle, accesoPermitido: false };
}

/**
 * Structural validation of a whole `RegistroProfesional`.
 *
 * Runs every contained credential through {@link validarCredencial} — a record
 * carrying one lapsed credential is a record with a lapsed credential, and the
 * aggregate being valid must not launder its parts.
 *
 * @param ahora - injected clock (ms epoch). The function never reads it itself.
 * @returns `ok: true` plus whether the node qualifies as a *certified doctor*
 *   (`licencia ∧ especialidad`, both strongly emitted and unexpired). A record
 *   that validates but is not certified is a legitimate node with a smaller
 *   capability set, not a failure (DECISIÓN A.4).
 */
export function validarRegistroProfesional(
	registro: RegistroProfesional,
	ahora: number,
): ResultadoValidacionRegistro {
	if (!registro || typeof registro !== "object") {
		return fallo(
			MOTIVO_RECHAZO_REGISTRO.ESTRUCTURA_INVALIDA,
			"el registro no es un objeto",
		);
	}
	if (registro.version !== 1) {
		return fallo(
			MOTIVO_RECHAZO_REGISTRO.ESTRUCTURA_INVALIDA,
			`version no soportada: ${String(registro.version)}`,
		);
	}
	if (!registro.nodoId) {
		return fallo(MOTIVO_RECHAZO_REGISTRO.ESTRUCTURA_INVALIDA, "falta nodoId");
	}
	if (!Array.isArray(registro.credenciales)) {
		return fallo(
			MOTIVO_RECHAZO_REGISTRO.ESTRUCTURA_INVALIDA,
			"credenciales debe ser un array",
		);
	}

	// ── Jurisdiction ──
	const juris = registro.declaracion?.jurisdiccion;
	if (!juris || !RE_PAIS_ALFA2.test(juris)) {
		return fallo(
			MOTIVO_RECHAZO_REGISTRO.JURISDICCION_INVALIDA,
			`jurisdiccion debe ser ISO 3166-1 alpha-2 en mayúsculas: ${String(juris)}`,
		);
	}

	// ── Every credential, individually ──
	const vistos = new Set<string>();
	for (const credencial of registro.credenciales) {
		const resultado = validarCredencial(credencial, ahora);
		if (!resultado.ok) {
			// The credential's own reason is preserved in `detalle`: a caller
			// debugging an expired record needs to know *which* field expired, not
			// just that "a credential is invalid".
			return fallo(
				MOTIVO_RECHAZO_REGISTRO.CREDENCIAL_INVALIDA,
				`credencial ${credencial?.id ?? "(sin id)"}: ${resultado.motivo} — ${resultado.detalle}`,
			);
		}
		if (vistos.has(credencial.id)) {
			return fallo(
				MOTIVO_RECHAZO_REGISTRO.CREDENCIAL_DUPLICADA,
				`id de credencial repetido: ${credencial.id}`,
			);
		}
		vistos.add(credencial.id);

		if (
			credencial.tipo === TIPO_CREDENCIAL.ESPECIALIDAD &&
			!credencial.especialidad
		) {
			return fallo(
				MOTIVO_RECHAZO_REGISTRO.ESPECIALIDAD_SIN_NOMBRE,
				`credencial de especialidad ${credencial.id} sin campo 'especialidad'`,
			);
		}
	}

	// ── `especialidades` must not over-claim ──
	// The summary array is what a directory renders. If it can list a specialty
	// the credential set does not prove, it is an unauthenticated claim about a
	// person's qualifications, which is the one thing this network must never
	// publish.
	const specialtiesConCredencial = new Set(
		registro.credenciales
			.filter((c) => c.tipo === TIPO_CREDENCIAL.ESPECIALIDAD)
			.map((c) => c.especialidad),
	);
	for (const esp of registro.especialidades) {
		if (!specialtiesConCredencial.has(esp)) {
			return fallo(
				MOTIVO_RECHAZO_REGISTRO.ESPECIALIDAD_SIN_CREDENCIAL,
				`especialidad '${esp}' listada sin credencial de tipo 'especialidad' que la respalde`,
			);
		}
	}

	const credencialesValidas =
		registro.credenciales as readonly CredencialMedica[];
	return {
		ok: true,
		registro,
		esCertificado: esMedicoCertificado(credencialesValidas, ahora),
	};
}

/**
 * Recompute a record's `avalRecibido` from its live `Aval`s.
 *
 * The stored summary is a cache, never the truth. Revocation works only because
 * this fold can be re-run: an `Aval` withdrawn by its author simply stops
 * appearing in the input and the count falls. A design that stored "verified" as
 * a flag would have no path back.
 *
 * @param ahora - injected clock; lapsed `Aval`s are dropped from the fold.
 */
export function recalcularAvalRecibido(
	registro: RegistroProfesional,
	avalesVivos: Parameters<typeof resumirAvales>[0],
	ahora: number,
): RegistroProfesional {
	return { ...registro, avalRecibido: resumirAvales(avalesVivos, ahora) };
}

/** Reasons a credential can be refused, re-exported for callers of this module. */
export { MOTIVO_RECHAZO_CREDENCIAL };
