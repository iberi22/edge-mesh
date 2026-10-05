/**
 * Data model for the medical layer — types only.
 *
 * This file is the code transcription of
 * `packages/edge-mesh/docs/medico/modelo-datos.md`. Field names here are the
 * document's names, deliberately: `autoridad`, `emitidoEn`, `vigenteHasta`,
 * `idLicencia`, `tipo`, `objetoAval`. Do not rename them to something more
 * descriptive; the design doc is the specification and the wire format must
 * match it byte for byte once signatures exist.
 *
 * ─── WHY THIS IS NOT A "user" OBJECT ────────────────────────────────────────
 *
 * The most common design error in this kind of system is collapsing four layers
 * into one. They are kept apart here because they prove different things:
 *
 *   layer 0  `NodoId`            I control a key          mathematics
 *   layer 1  `CredencialMedica`  this human holds a license   the state
 *   layer 2  `Aval`              I checked layer 1 and stand behind it  a peer
 *   layer 3  `Karma`             peers repeatedly endorsed me  the sum
 *
 * Access is granted by layer 1 + layer 2, never by layer 0 (worthless as merit)
 * and never by layer 3 (mintable by anyone willing to spend a few signatures).
 * See `docs/medico/reglas-red.md` §1.
 *
 * ─── THE TWO DEFECTS THIS SHAPE EXISTS TO CLOSE ─────────────────────────────
 *
 * 1. `unknown` IS NOT `valid`. The OrionHealth pattern
 *    (`apps/OrionHealth/lib/features/doctor_verification/domain/services/license_verifier.dart`)
 *    returns `LicenseVerificationResult.unknown` when a country's registry is
 *    empty. In a mesh that lets a node self-attest, "unverified but proceed"
 *    makes an *unsupported country* a bypass. So `EstadoVerificacionRegistro`
 *    in `./verificador.ts` has no third state at all: `verificado` and
 *    `no_verificado` only. The ambiguity is not representable.
 *
 * 2. A HASH SET CANNOT EXPRESS EXPIRY. OrionHealth declares `expired` in its
 *    enum and never returns it, because list membership carries no validity
 *    window. In a mesh that runs for years, immutable hash-set membership means
 *    a licence cancelled in 2027 still verifies forever. So `vigenteHasta` is a
 *    required field, signed by the issuer, not inferred from list membership.
 *
 * Nothing in this file performs I/O. Verification against a real registry
 * snapshot is Phase 3; the extension point is `VerificadorRegistroPais`.
 */

import type { NodoId } from "../types/index.js";

/** Wire version of the credential / record shape. Bumped only on a breaking change. */
export const VERSION_MODELO = 1 as const;

/**
 * The five fields every credential must carry, named as the design doc names
 * them. Mapped to the plain-language description they satisfy:
 *
 *   - source            → `autoridad`    ("who issued this")
 *   - published         → `emitidoEn`    ("when it was issued")
 *   - reviewed          → `vigenteHasta` ("when it stops being current")
 *   - licence           → `idLicencia`   ("which licence, as a hash")
 *   - claim backed      → `tipo`         ("what kind of claim this is")
 *
 * Exported as data so a validation error can name the field that was missing
 * instead of returning a bare boolean.
 */
export const CAMPOS_OBLIGATORIOS_CREDENCIAL = [
	"autoridad",
	"emitidoEn",
	"vigenteHasta",
	"idLicencia",
	"tipo",
] as const;

/** What kind of claim a credential makes. Specialties are separate credentials. */
export const TIPO_CREDENCIAL = {
	LICENCIA: "licencia",
	ESPECIALIDAD: "especialidad",
	COLEGIACION: "colegiacion",
	REGISTRO_RETHUS: "registro_rethus",
} as const;
export type TipoCredencial =
	(typeof TIPO_CREDENCIAL)[keyof typeof TIPO_CREDENCIAL];

/**
 * How honestly the credential was obtained. This is the label peers read; it is
 * not decoration:
 *
 *   - `autofirmada`       the node signed its own claim. A format-valid
 *                         assertion by an anonymous party, **zero** evidential
 *                         weight. Useful only so a peer knows what to go check.
 *   - `atestiguada_pares` N peers each verified it independently and signed an
 *                         `Aval`. This is the state that opens access.
 *   - `anclada_autoridad` the state's or the college's own key signed it.
 *                         Strongest, and the only state that survives peers
 *                         going offline.
 */
export const ESTADO_EMISION = {
	AUTOFIRMADA: "autofirmada",
	ANCLADA_AUTORIDAD: "anclada_autoridad",
	ATESTIGUADA_PARES: "atestiguada_pares",
} as const;
export type EstadoEmision =
	(typeof ESTADO_EMISION)[keyof typeof ESTADO_EMISION];

/**
 * A verified professional credential: "this human holds licence L in country C,
 * valid until D".
 *
 * This layer is **forgeable by anyone**: a signature proves authorship, never
 * truth. `estadoEmision` is the honest label of how much that forgery is worth,
 * and `Aval` is what actually promotes it.
 */
export interface CredencialMedica {
	/** Stable id: `hash(idLicencia + tipo + pais)`. See `./credencial.ts`. */
	readonly id: string;
	readonly tipo: TipoCredencial;
	/** ISO 3166-1 alpha-2. `CO` for Colombia — the only market at launch. */
	readonly pais: string;
	/** Issuing authority: `'minsalud-rethus'`, `'colomedico-cm'`. */
	readonly autoridad: string;
	/**
	 * `sha256(normalize(licenceNumber))` — public-safe, never the number itself.
	 *
	 * Only the hash travels. The number is PII under Ley 1581/2012 and peers do
	 * not need it. Publishing it unsalted is also the anti-Sybil primitive: ten
	 * nodes presenting the same `idLicencia` are provably one human.
	 */
	readonly idLicencia: string;
	/**
	 * Real-world PII, sealed to the specific verifier with ML-KEM-768. Optional
	 * (DECISIÓN A.3). Travels sealed, never cleartext.
	 */
	readonly numeroLicenciaCifrado?: Uint8Array;
	/** `'medicina_general'`, `'cardiologia'`. Separate credential, own expiry. */
	readonly especialidad?: string;
	/** Issue date, ms epoch. */
	readonly emitidoEn: number;
	/**
	 * Expiry, ms epoch. REQUIRED and signed by the issuer — a hash set cannot
	 * express "this lapsed", so without this field a revoked licence verifies
	 * forever. Omitting it is a validation failure, not a default.
	 */
	readonly vigenteHasta: number;
	readonly estadoEmision: EstadoEmision;
	/** ML-DSA-65 over the canonical bytes of every field above, except `firma`. */
	readonly firma: Uint8Array;
	/** Signer. `estadoEmision: 'autofirmada'` ⇒ `emisor` is the subject itself. */
	readonly emisor: NodoId;
}

/** Specialty slug. `'medicina_general'`, `'cardiologia'`, … */
export type Especialidad = string;

/**
 * What an `Aval` is about. The load-bearing distinction is that only the first
 * two can promote a credential to `atestiguada_pares`.
 *
 * `interaccion_clinica` asserts *"a real encounter occurred"* — nothing more.
 * No date, no diagnosis, no content. It is a boolean with a signer, and
 * letting it count toward credential verification is exactly the hole that
 * admits a well-liked non-doctor into a network of doctors.
 */
export const OBJETO_AVAL = {
	LICENCIA_VERIFICADA: "licencia_verificada",
	ESPECIALIDAD_VERIFICADA: "especialidad_verificada",
	INTERACCION_CLINICA: "interaccion_clinica",
	DOCENCIA: "docencia",
} as const;
export type ObjetoAval = (typeof OBJETO_AVAL)[keyof typeof OBJETO_AVAL];

/**
 * How the avalador actually checked it. Not decoration: two `Aval`s about the
 * same subject with different methods deserve different weight, and a peer must
 * be able to see *why* it is trusting someone.
 *
 *   - `registro_por_pais`  cheap, reproducible offline, but only as fresh as the
 *                          snapshot. `versionRegistro` is mandatory so a stale
 *                          snapshot is visible on the face of the record.
 *   - `colegio_directo`    expensive, rare, out-of-band with the college, and
 *                          the only method that survives the registry being
 *                          wrong. What a founding cohort should hold.
 *   - `testimonio_directo` cheap and unfalsifiable. Good signal of collegiality,
 *                          **weak** signal of licensure.
 *   - `supervision`        time-bounded, non-symmetric (A supervises B ⇒ B's
 *                          aval of A is not symmetric evidence), and the
 *                          strongest peer signal because it implies sustained
 *                          observation.
 */
export const CLASE_VERIFICACION = {
	REGISTRO_POR_PAIS: "registro_por_pais",
	COLEGIO_DIRECTO: "colegio_directo",
	TESTIMONIO_DIRECTO: "testimonio_directo",
	SUPERVISION: "supervision",
} as const;
export type ClaseVerificacion =
	(typeof CLASE_VERIFICACION)[keyof typeof CLASE_VERIFICACION];

export type MetodoVerificacion =
	| {
			readonly clase: "registro_por_pais";
			readonly pais: string;
			readonly versionRegistro: string;
	  }
	| { readonly clase: "colegio_directo"; readonly ref: string }
	| { readonly clase: "testimonio_directo" }
	| {
			readonly clase: "supervision";
			readonly desde: number;
			readonly hasta: number;
	  };

/** `'anual'` must be renewed and feeds decay. */
export const ALCANCE_AVAL = {
	PERMANENTE: "permanente",
	ANUAL: "anual",
} as const;
export type AlcanceAval = (typeof ALCANCE_AVAL)[keyof typeof ALCANCE_AVAL];

/**
 * A peer endorsement: *"I checked this claim and stand behind it."*
 *
 * Structurally incapable of being confused with anything else. It is about a
 * **claim** (peer → node, subject = a credential hash), never about an
 * **encounter** (patient → node, subject = a fact of a real world event).
 *
 * The signature shape — `id`, `emisor`, `timestamp`, `firma` — is
 * {@link TransaccionKarma}'s, reused verbatim rather than reinvented. See
 * `./aval.ts#aTransaccionKarma` for the adapter that feeds an `Aval` into the
 * existing karma path.
 */
export interface Aval {
	/** `${avalador}:${avalado}:${timestamp}:${nonce}`. Idempotency key. */
	readonly id: string;
	readonly version: typeof VERSION_MODELO;

	// ── WHO ──
	readonly avalador: NodoId;
	readonly avalado: NodoId;

	// ── WHAT IS BEING ENDORSED ──
	readonly objetoAval: ObjetoAval;
	/** `id` of the `CredencialMedica` being endorsed. */
	readonly credencialRef: string;
	/** Binds the `Aval` to the exact credential bytes the avalador checked. */
	readonly hashCredencial: string;

	// ── HOW THE AVALADOR CHECKED IT ──
	readonly metodoVerificacion: MetodoVerificacion;
	/** Hash of the artefact relied upon, if any. */
	readonly evidenciaHash: string;
	readonly alcance: AlcanceAval;
	readonly emitidoEn: number;
	/** Revocable endorsements only count while current. */
	readonly vigenteHasta: number;
	/** Always `true`. See `docs/medico/protocolo.md` §5. */
	readonly revocable: true;

	/** ML-DSA-65 by `avalador` over the canonical bytes of everything above. */
	readonly firma: Uint8Array;
}

/**
 * Fold over live endorsements. This, not a stored fact, is what makes
 * `atestiguada_pares` revocable.
 */
export interface ResumenAvales {
	readonly total: number;
	readonly porObjeto: Readonly<Record<ObjetoAval, number>>;
	/** Distinct `avalador`s — the only counter that matters for the threshold. */
	readonly avaladoresUnicos: number;
	/**
	 * Endorsements that legally count toward credential promotion: distinct
	 * avaladores over `licencia_verificada` + `especialidad_verificada`.
	 */
	readonly verificacionesLicencia: number;
	readonly ultimoAval?: number;
}

/** Who operates the node and under which jurisdiction. */
export interface DeclaracionNodo {
	/** ISO 3166-1 alpha-2 of the operator's jurisdiction. */
	readonly jurisdiccion: string;
	/**
	 * Public display name, opt-in (DECISIÓN A.5 — touches the Lex Artis
	 * professional-secret rule, not just privacy). Absent ⇒ the node is unnamed
	 * in the directory.
	 */
	readonly nombreMostrado?: string;
	/** Directory-level PII (contact, clinic address), sealed, opt-in. */
	readonly contactoCifrado?: Uint8Array;
}

/**
 * The professional half of a node's public record.
 *
 * ─── DELIBERATELY SHAPED SO IT CANNOT HOLD PATIENT DATA ────────────────────
 *
 * There is no field here capable of holding a patient record, not "we won't
 * populate it" — the shape does not admit it. Health data is a special category
 * under GDPR Art. 9 and sensitive under Ley 1581/2012 Art. 5, whose
 * household/personal exemption of Art. 2(a) is lost the moment a peer node holds
 * it. A mesh is a replication substrate: anything written is designed to be
 * copied and kept by several nodes, so a patient's record inside an OpLog is a
 * breach waiting for a payload bug. Any future feature needing
 * patient-adjacent data needs a different transport, not a field added here.
 *
 * Note what this type does NOT claim: `nodoId → person`. One human may
 * legitimately run several nodes, so the per-human fact we store is
 * `idLicencia`, and the anti-Sybil rules are built on that, not on `nodoId`.
 */
export interface RegistroProfesional {
	readonly version: typeof VERSION_MODELO;
	/** Binding: which key this claim rides on. */
	readonly nodoId: NodoId;
	readonly credenciales: readonly CredencialMedica[];
	readonly especialidades: readonly Especialidad[];
	readonly avalRecibido: ResumenAvales;
	readonly declaracion: DeclaracionNodo;
}
