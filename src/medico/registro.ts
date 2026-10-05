/**
 * The extension point for Phase 3, and the reason this layer fails closed.
 *
 * ─── THE ORIONHEALTH PATTERN AND ITS TWO DEFECTS ────────────────────────────
 *
 * `apps/OrionHealth/lib/features/doctor_verification/domain/services/license_verifier.dart`
 * gets "is this licence number real" right with the right primitive:
 *
 * ```dart
 * final normalized = licenseNumber.replaceAll(RegExp(r'\s+'), '').toUpperCase();
 * final hash = sha256.convert(utf8.encode(normalized)).toString();
 * final countryHashes = await _registry.getHashesForCountry(countryCode);
 * if (countryHashes.isEmpty) return LicenseVerificationResult.unknown;
 * if (countryHashes.contains(hash)) return LicenseVerificationResult.valid;
 * return LicenseVerificationResult.invalid;
 * ```
 *
 * Three properties worth keeping: only the hash travels (the number is PII under
 * Ley 1581/2012), registries are country-scoped (ReTHUS and the Spanish
 * colleges are different datasets with different cadences), and the result is
 * three-valued.
 *
 * Two properties that are defects *for our use case*:
 *
 * 1. **`unknown` is not `valid`.** An empty country registry yields `unknown`.
 *    Fine for a UI that says "we don't know yet". Fatal here: a node that treats
 *    `unknown` as "not refused" turns *an unsupported country* into a bypass. A
 *    physician presents a licence from a country nobody has downloaded a
 *    snapshot for, and every node that has not yet fetched that registry waves
 *    them through. So {@link EstadoVerificacionRegistro} has exactly two members.
 *    There is no third state, so the bug is not representable.
 *
 * 2. **`expired` is declared but never returned.** A hash-set membership carries
 *    no validity window, so a licence cancelled in 2027 verifies forever. The
 *    fix is not in this file: it is the issuer-signed `vigenteHasta` on
 *    {@link CredencialMedica}, checked by `validarCredencial`.
 *
 * ─── WHAT THIS FILE DELIBERATELY DOES NOT DO ────────────────────────────────
 *
 * It does no I/O. No fetch, no registry file, no snapshot download. The
 * interface below is the seam; Phase 3 implements it against a replicated,
 * append-only, hash-compared country snapshot. Because the seam is pure data in
 * and pure data out, this module is fully testable with a fixture and no network.
 */

import { hashLicencia } from "./canonica.js";
import type { CredencialMedica } from "./types.js";

/**
 * The result of consulting a country registry.
 *
 * Two states, not three. `no_verificado` covers both "the licence is not in the
 * registry" and "we have no registry for this country" — the caller does not get
 * to tell them apart, because acting differently on them is exactly the bug.
 * Access stays closed in both cases.
 */
export const ESTADO_VERIFICACION_REGISTRO = {
	VERIFICADO: "verificado",
	NO_VERIFICADO: "no_verificado",
} as const;

export type EstadoVerificacionRegistro =
	(typeof ESTADO_VERIFICACION_REGISTRO)[keyof typeof ESTADO_VERIFICACION_REGISTRO];

/** A per-country snapshot of licence hashes, plus the version that dated it. */
export interface InstantaneaRegistroPais {
	/** ISO 3166-1 alpha-2. */
	readonly pais: string;
	/**
	 * Version of the snapshot. Mandatory on the wire too, not just here: an `Aval`
	 * with `metodoVerificacion.clase: 'registro_por_pais'` is refused without it,
	 * because a stale snapshot that cannot be named cannot be reasoned about.
	 */
	readonly version: string;
	/** Hex SHA-256 of normalised licence numbers. Membership only, never a number. */
	readonly hashes: ReadonlySet<string>;
}

/**
 * The Phase 3 seam. One method, no I/O in this module.
 *
 * An implementation is *injected* rather than imported so this file stays free
 * of any dependency on where snapshots come from — a local file today, a gossiped
 * replica later — and so a test can supply a fixture.
 */
export interface VerificadorRegistroPais {
	/**
	 * @returns the snapshot for `pais`, or `undefined` when none is available.
	 *   `undefined` means *unsupported country* and is handled fail-closed.
	 */
	instantanea(pais: string): InstantaneaRegistroPais | undefined;

	/** Version of the snapshot this verifier would consult, for audit logs. */
	versionInstantanea(pais: string): string | undefined;
}

/** An in-memory verifier. Pure: a fixture map, no I/O. Useful in tests. */
export class VerificadorRegistroEnMemoria implements VerificadorRegistroPais {
	private readonly porPais = new Map<string, InstantaneaRegistroPais>();

	constructor(instantaneas: readonly InstantaneaRegistroPais[] = []) {
		for (const inst of instantaneas) {
			this.porPais.set(inst.pais.toUpperCase(), {
				...inst,
				pais: inst.pais.toUpperCase(),
			});
		}
	}

	instantanea(pais: string): InstantaneaRegistroPais | undefined {
		return this.porPais.get(pais.toUpperCase());
	}

	versionInstantanea(pais: string): string | undefined {
		return this.porPais.get(pais.toUpperCase())?.version;
	}

	/** Add or replace a snapshot. The append-only, hash-compared path is Phase 3. */
	publicar(instantanea: InstantaneaRegistroPais): void {
		this.porPais.set(instantanea.pais.toUpperCase(), {
			...instantanea,
			pais: instantanea.pais.toUpperCase(),
		});
	}
}

export type ResultadoVerificacionRegistro =
	| {
			readonly estado: "verificado";
			readonly idLicencia: string;
			readonly versionRegistro: string;
	  }
	| {
			/**
			 * Fail-closed. Covers both "not in the registry" and "no registry for this
			 * country". `causa` is for operators and logs only — it must never widen
			 * what a caller may do.
			 */
			readonly estado: "no_verificado";
			readonly causa:
				| "pais_sin_registro"
				| "licencia_no_encontrada"
				| "licencia_caducada";
			readonly accesoPermitido: false;
	  };

/**
 * The OrionHealth primitive, fail-closed.
 *
 * The whole behavioural difference from OrionHealth is the empty-registry branch:
 * it returns `no_verificado` / `pais_sin_registro`, not `unknown`. Same
 * normalisation, same hash, same membership test.
 *
 * @param numeroLicencia - the raw number, hashed here and nowhere else.
 * @param pais - ISO 3166-1 alpha-2.
 */
export async function verificarLicenciaContraRegistro(
	numeroLicencia: string,
	pais: string,
	verificador: VerificadorRegistroPais,
): Promise<ResultadoVerificacionRegistro> {
	return consultarInstantanea(
		await hashLicencia(numeroLicencia),
		pais,
		verificador,
	);
}

/**
 * Membership test over an **already-hashed** `idLicencia`.
 *
 * Separate from {@link verificarLicenciaContraRegistro} because hashing is not
 * idempotent: feeding a stored `idLicencia` (which is already
 * `sha256(normalize(numero))`) back through `hashLicencia` hashes the digest a
 * second time and can never match the set. A credential on the wire carries the
 * hash, never the number, so the credential path must consult the set directly.
 *
 * @param idLicencia - a `sha256` hex digest. NOT a licence number.
 */
export async function verificarHashContraRegistro(
	idLicencia: string,
	pais: string,
	verificador: VerificadorRegistroPais,
): Promise<ResultadoVerificacionRegistro> {
	return consultarInstantanea(idLicencia, pais, verificador);
}

/** Shared fail-closed membership test. */
async function consultarInstantanea(
	idLicencia: string,
	pais: string,
	verificador: VerificadorRegistroPais,
): Promise<ResultadoVerificacionRegistro> {
	const instantanea = verificador.instantanea(pais);

	// ── FAIL CLOSED ──
	// This is the branch OrionHealth returns `unknown` from. An empty registry and
	// a missing country are the same thing operationally: we cannot verify, so we
	// do not verify. Treating this as "not refused" makes an unsupported country
	// a universal bypass, and the owner has decided the launch market is Colombia
	// only — `CO` is supported, everything else fails closed until a real
	// snapshot exists for it.
	if (!instantanea || instantanea.hashes.size === 0) {
		return {
			estado: "no_verificado",
			causa: "pais_sin_registro",
			accesoPermitido: false,
		};
	}

	if (!instantanea.hashes.has(idLicencia)) {
		return {
			estado: "no_verificado",
			causa: "licencia_no_encontrada",
			accesoPermitido: false,
		};
	}

	return {
		estado: "verificado",
		idLicencia,
		versionRegistro: instantanea.version,
	};
}

/**
 * Registry membership is necessary but not sufficient.
 *
 * OrionHealth's `expired` defect lives here: set membership carries no validity
 * window, so a licence cancelled in 2027 stays in the snapshot and keeps
 * matching. The window must come from the credential's issuer-signed
 * `vigenteHasta`, which is why this check cannot be folded into the membership
 * test.
 *
 * @param ahora - injected clock. Pure: no `Date.now()` here.
 * @returns `true` only when the credential is in the registry *and* unexpired.
 */
export async function verificarCredencialContraRegistro(
	credencial: CredencialMedica,
	verificador: VerificadorRegistroPais,
	ahora: number,
): Promise<ResultadoVerificacionRegistro> {
	const porPais = await verificarHashContraRegistro(
		credencial.idLicencia,
		credencial.pais,
		verificador,
	);
	if (porPais.estado === "no_verificado") return porPais;

	if (credencial.vigenteHasta <= ahora) {
		// Membership holds and the credential is still within its own window only
		// when both are true. Without this, "in the set" means "forever".
		return {
			estado: "no_verificado",
			causa: "licencia_caducada",
			accesoPermitido: false,
		};
	}

	return {
		estado: "verificado",
		idLicencia: credencial.idLicencia,
		versionRegistro:
			verificador.versionInstantanea(credencial.pais) ?? "desconocida",
	};
}

/** Countries with a real snapshot behind them. Colombia only at launch (DECISIÓN C.1). */
export const PAISES_SOPORTADOS = ["CO"] as const;
