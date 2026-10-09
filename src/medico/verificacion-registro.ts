/**
 * Foundation verification: from "well-formed credential" to "accredited".
 *
 * ─── WHAT THE PREVIOUS PHASE ALREADY SOLVED, AND WHAT IT DID NOT ─────────────
 *
 * `./credencial.ts` verifies FORM: ISO country, `idLicencia` is a SHA-256 hex,
 * `vigenteHasta` present and not lapsed, signature over the canonical bytes. A
 * credential can pass all of that and still be a forgery — a well-formed object
 * that no authority ever issued. Nothing before this file asked the substrate
 * question: *does this licence exist?*
 *
 * `./registro.ts` answers part of it, with the right fail-closed primitive
 * (normalize → SHA-256 → country-scoped membership). What it cannot answer, by
 * construction, is state: its `InstantaneaRegistroPais` is a `Set<string>` of
 * hashes, and a set has one relation — *present* or *absent*. A `Set` cannot say
 * "present, suspended", so a licence the Ministry suspended in March keeps
 * matching a snapshot taken in January, forever.
 *
 * ─── THE THIRD DEFECT, WHICH IS THE ONE THAT ADDS NOVEL VALUE ───────────────
 *
 * `InstantaneaRegistroPais` also carries no expiry and no version per entry, so
 * `{ estado: 'activa' }` would be enough — and that is exactly the
 * OrionHealth `expired`-never-returned defect wearing a different hat. A state
 * that is only ever `ACTIVA` because nothing can express anything else is not a
 * state machine, it is a comment.
 *
 * So the registry here is an array of {@link EntradaRegistroLicencia}: country,
 * licence hash, issuer-signed `vigenteHasta`, and an explicit
 * {@link EstadoLicenciaRegistro}. All three states are reachable and two of them
 * refuse. That is the whole point of this file.
 *
 * ─── WHY THE LOOKUP IS AN INJECTED FUNCTION ────────────────────────────────
 *
 * {@link FuenteAcreditacion.consultar} takes a `{ pais, hashLicencia }` and
 * returns an entry or `undefined`. No fetch, no filesystem, no `Date.now()`:
 * the transport is Phase 3's decision (a gossiped, hash-compared snapshot), and
 * until then a fixture *is* the network. Because the seam is data in / data
 * out, every state below is reachable from a test with no I/O at all.
 *
 * ─── WHY A MISSING COUNTRY REFUSES ────────────────────────────────────────
 *
 * OrionHealth returns `LicenseVerificationResult.unknown` when a country's
 * registry is empty and treats it as "not refused". Here an unlisted country is
 * `pais_no_soportado` and a supported country with an empty registry is
 * `licencia_no_encontrada` — both `accesoPermitido: false`, and the type has no
 * member meaning "we could not check this, carry on". An accreditation whose
 * failure mode is a bypass is not a verification scheme.
 *
 * Pure: no clock read, no randomness, no I/O. `ahora` is always injected, which
 * is what makes the refusal reasons reproducible — same inputs, same `motivo`,
 * byte for byte, forever.
 */

import {
	MOTIVO_RECHAZO_CREDENCIAL,
	type MotivoRechazoCredencial,
	validarCredencial,
} from "./credencial.js";
import {
	MOTIVO_RECHAZO_REGISTRO,
	type MotivoRechazoRegistro,
} from "./registro-profesional.js";
import type { CredencialMedica, MetodoVerificacion } from "./types.js";

/**
 * The life cycle of a licence *as the registry sees it*.
 *
 * Declared as a closed three-member union so the intermediate and terminal
 * states are first-class. OrionHealth has the same two non-active states in its
 * enum and returns neither one, because list membership cannot express them;
 * here `suspendida` and `revocada` are not decoration — each one is a distinct,
 * named refusal returned by {@link acreditarContraRegistro}.
 *
 * A value outside this union is refused as {@link MOTIVO_RECHAZO_CONSULTA_REGISTRO.ESTADO_REGISTRO_INVALIDO}.
 * Unknown is never treated as active.
 */
export const ESTADO_LICENCIA = {
	ACTIVA: "activa",
	SUSPENDIDA: "suspendida",
	REVOCADA: "revocada",
} as const;

export type EstadoLicencia =
	(typeof ESTADO_LICENCIA)[keyof typeof ESTADO_LICENCIA];

/**
 * One licence, as held by one country registry snapshot.
 *
 * Membership is no longer a bare hash: the entry states *what* the registry says
 * about the licence and *until when*, so a suspended or lapsed licence cannot be
 * represented as a good one. `pais` is mandatory so a transport bug that answers
 * a `CO` query with an `ES` entry is detectable
 * ({@link MOTIVO_RECHAZO_CONSULTA_REGISTRO.ENTRADA_DE_OTRO_PAIS}).
 */
export interface EntradaRegistroLicencia {
	/** ISO 3166-1 alpha-2, upper case. Must equal the credential's `pais`. */
	readonly pais: string;
	/** `sha256(normalize(numeroLicencia))`. Never the number: that is PII (Ley 1581/2012). */
	readonly hashLicencia: string;
	/**
	 * Registry-stated validity window, ms epoch. Independent of the credential's
	 * own `vigenteHasta`: both must hold, so a credential claiming a longer
	 * licence than the registry grants is refused rather than believed.
	 */
	readonly vigenteHasta: number;
	readonly estado: EstadoLicencia;
	/** Issuing authority, when the snapshot carries it. Checked when both sides do. */
	readonly autoridad?: string;
	/** Specialty slug, when the entry describes a specialty licence. */
	readonly especialidad?: string;
}

/** Sync or async, so a Phase 3 transport may fetch without changing the contract. */
type Awaitable<T> = T | Promise<T>;

/** The query a transport receives. Hash only — the licence number never travels. */
export interface ConsultaRegistroLicencia {
	readonly pais: string;
	readonly hashLicencia: string;
}

/**
 * The injected lookup: given a country and a licence hash, produce the registry's
 * entry, or `undefined` when the registry does not hold it.
 *
 * Returning `undefined` is "not in the registry". Throwing is not interpreted as
 * absence: it becomes {@link MOTIVO_RECHAZO_CONSULTA_REGISTRO.CONSULTA_FALLIDA},
 * still fail-closed, because a transport error must never be laundered into a
 * plain miss that some future caller might treat as benign.
 */
export type ConsultarEntradaRegistro = (
	consulta: ConsultaRegistroLicencia,
) => Awaitable<EntradaRegistroLicencia | undefined>;

/**
 * The Phase 3 extension point.
 *
 * Everything the verification needs from the outside world arrives through this
 * interface, so swapping an in-memory fixture for a replicated snapshot is a
 * constructor change in a later phase and not a change to any rule in this file.
 */
export interface FuenteAcreditacion {
	/**
	 * Countries this source can speak for. Empty ⇒ nothing is verifiable, and
	 * every credential is refused as `pais_no_soportado`.
	 *
	 * Separate from the registry's own contents on purpose: "we do not carry
	 * Colombia" is a different operational fact from "your licence is not in
	 * Colombia's registry", and conflating them is how an unsupported country
	 * becomes a silent bypass.
	 */
	readonly paisesSoportados: readonly string[];

	/** Version of the snapshot backing `pais`, for the audit trail. */
	versionRegistro(pais: string): string | undefined;

	/** The lookup itself. Injected; this module performs no I/O. */
	consultar(
		consulta: ConsultaRegistroLicencia,
	): Awaitable<EntradaRegistroLicencia | undefined>;
}

/**
 * Refusals specific to consulting a registry.
 *
 * Additive to the two existing reason sets rather than a parallel system:
 * {@link MotivoRechazoAcreditacion} is the union of this, `MOTIVO_RECHAZO_CREDENCIAL`
 * and `MOTIVO_RECHAZO_REGISTRO`, and a credential that fails form is reported
 * with the *credential's own* reason, so a caller reading
 * `motivo === MOTIVO_RECHAZO_CREDENCIAL.SIN_VIGENCIA` keeps working unchanged.
 */
export const MOTIVO_RECHAZO_CONSULTA_REGISTRO = {
	/** The credential itself failed `validarCredencial`; see `detalle` for its reason. */
	CREDENCIAL_MAL_FORMADA: "credencial_mal_formada",
	/** No source speaks for this country. Fail closed, never "unknown". */
	PAIS_NO_SOPORTADO: "pais_no_soportado",
	/** The source supports the country but holds no snapshot for it. */
	PAIS_SIN_REGISTRO: "pais_sin_registro",
	/** Country supported, snapshot present, licence absent. */
	LICENCIA_NO_ENCONTRADA: "licencia_no_encontrada",
	/** The registry says the licence is suspended. */
	LICENCIA_SUSPENDIDA: "licencia_suspendida",
	/** The registry says the licence is revoked. Terminal. */
	LICENCIA_REVOCADA: "licencia_revocada",
	/** `vigenteHasta <= ahora` on the registry entry, or on the credential, or the
	 *  credential claims a longer window than the registry grants. */
	LICENCIA_CADUCADA: "licencia_caducada",
	/** The entry answered a query for another country. Transport or source bug. */
	ENTRADA_DE_OTRO_PAIS: "entrada_de_otro_pais",
	/** `estado` outside {@link ESTADO_LICENCIA}. Unknown is never active. */
	ESTADO_REGISTRO_INVALIDO: "estado_registro_invalido",
	/** `vigenteHasta` absent or not a finite number on the entry. */
	VIGENCIA_REGISTRO_INVALIDA: "vigencia_registro_invalida",
	/** The specialty the credential claims is not the specialty the registry holds. */
	ESPECIALIDAD_NO_REGISTRADA: "especialidad_no_registada",
	/** The issuing authority disagrees with the registry's. */
	AUTORIDAD_NO_REGISTRADA: "autoridad_no_registada",
	/** `consultar` threw. Fail closed, and distinguishable from a plain miss. */
	CONSULTA_FALLIDA: "consulta_fallida",
	/** A verification class this phase does not implement. See the strategies below. */
	METODO_NO_IMPLEMENTADO: "metodo_no_implementado",
} as const;

export type MotivoRechazoConsultaRegistro =
	(typeof MOTIVO_RECHAZO_CONSULTA_REGISTRO)[keyof typeof MOTIVO_RECHAZO_CONSULTA_REGISTRO];

/**
 * Every reason a foundation verification can fail.
 *
 * The union, not a new vocabulary: shape failures surface as
 * `MOTIVO_RECHAZO_CREDENCIAL.*`, whole-record problems as
 * `MOTIVO_RECHAZO_REGISTRO.*`, and registry findings as
 * `MOTIVO_RECHAZO_CONSULTA_REGISTRO.*`.
 */
export type MotivoRechazoAcreditacion =
	| MotivoRechazoConsultaRegistro
	| MotivoRechazoCredencial
	| MotivoRechazoRegistro;

/** The audit record of a successful verification. */
export interface MetodoVerificacionAplicado {
	readonly clase: "registro_por_pais";
	readonly pais: string;
	readonly versionRegistro: string;
}

export type ResultadoAcreditacion =
	| {
			readonly ok: true;
			readonly credencial: CredencialMedica;
			/** The registry entry the verification stood on. */
			readonly entrada: EntradaRegistroLicencia;
			/**
			 * How it was checked, on the face of the result. An accreditation without
			 * proof of method is a claim, not a verification (`docs/medico/modelo-datos.md` §4.2).
			 */
			readonly metodoVerificacion: MetodoVerificacionAplicado;
			/** Injected clock value, so the trail carries no hidden `Date.now()`. */
			readonly verificadoEn: number;
	  }
	| {
			readonly ok: false;
			readonly motivo: MotivoRechazoAcreditacion;
			readonly detalle: string;
			/** Always `false`. There is no state here meaning "unverified but proceed". */
			readonly accesoPermitido: false;
	  };

function fallo(
	motivo: MotivoRechazoAcreditacion,
	detalle: string,
): ResultadoAcreditacion {
	return { ok: false, motivo, detalle, accesoPermitido: false };
}

/**
 * Build the `metodoVerificacion` that records "I checked this against the
 * country registry".
 *
 * One construction site: the success path below stamps its audit trail with
 * this, so the shape a verification returns and the shape an `Aval` must carry
 * cannot drift apart.
 *
 * `versionRegistro` is mandatory on the wire (`docs/medico/modelo-datos.md` §4.2):
 * a stale snapshot that cannot be named cannot be reasoned about, and an
 * unnameable one is refused by `validarAval` in `./aval.ts`.
 */
export function metodoRegistroPorPais(
	pais: string,
	versionRegistro: string,
): MetodoVerificacionAplicado {
	return {
		clase: "registro_por_pais",
		pais: pais.toUpperCase(),
		versionRegistro,
	};
}

const RE_PAIS_ALFA2 = /^[A-Z]{2}$/;
const RE_HEX64 = /^[0-9a-f]{64}$/;

/**
 * Verify a credential against a real registry entry.
 *
 * Checks run cheap-to-expensive and in a fixed order, so the same inputs always
 * produce the same `motivo`: form, then country support, then snapshot presence,
 * then lookup, then the entry's own state and window, then the claims the
 * credential makes about that entry. No branch is random, no branch reads a
 * clock that was not injected, and no branch can widen access.
 *
 * @param credencial - a credential already built. Its shape is re-checked here so
 *   the foundation path cannot be entered with a hand-rolled object.
 * @param fuente - the injected registry. Phase 3 supplies the real transport.
 * @param ahora - injected clock (ms epoch), used against both `vigenteHasta` fields.
 */
export async function acreditarContraRegistro(
	credencial: CredencialMedica,
	fuente: FuenteAcreditacion,
	ahora: number,
): Promise<ResultadoAcreditacion> {
	// ── 1. Form, first: never spend a lookup on a malformed object ──
	const forma = validarCredencial(credencial, ahora);
	if (!forma.ok) {
		// The credential's own reason is preserved so callers of `validarCredencial`
		// keep working; `motivo` stays inside the one vocabulary.
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.CREDENCIAL_MAL_FORMADA,
			`forma inválida (${forma.motivo}): ${forma.detalle}`,
		);
	}

	const pais = credencial.pais.toUpperCase();

	// ── 2. Country support: fail closed, the OrionHealth `unknown` branch ──
	if (
		!Array.isArray(fuente.paisesSoportados) ||
		!fuente.paisesSoportados.some((p) => p.toUpperCase() === pais)
	) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.PAIS_NO_SOPORTADO,
			`ninguna fuente sostiene '${pais}': no hay registro contra el cual verificar, y no verificar no es perdonar`,
		);
	}

	// ── 3. The country is supported: there must still be a snapshot behind it ──
	const version = fuente.versionRegistro(pais);
	if (!version) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.PAIS_SIN_REGISTRO,
			`'${pais}' está soportado pero no hay instantánea cargada`,
		);
	}

	// ── 4. The lookup. A throwing transport is a failure, not a miss ──
	let entrada: EntradaRegistroLicencia | undefined;
	try {
		entrada = await fuente.consultar({
			pais,
			hashLicencia: credencial.idLicencia,
		});
	} catch (error) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.CONSULTA_FALLIDA,
			`la consulta al registro falló: ${error instanceof Error ? error.message : String(error)}`,
		);
	}

	if (!entrada) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_NO_ENCONTRADA,
			`hash de licencia no presente en el registro '${pais}' (versión ${version})`,
		);
	}

	// ── 5. The entry must be well formed itself ──
	if (typeof entrada.pais !== "string" || !RE_PAIS_ALFA2.test(entrada.pais)) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.ENTRADA_DE_OTRO_PAIS,
			`la entrada declara un país inválido: ${String(entrada.pais)}`,
		);
	}
	if (entrada.pais.toUpperCase() !== pais) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.ENTRADA_DE_OTRO_PAIS,
			`la entrada responde a una consulta de '${pais}' con una de '${entrada.pais}'`,
		);
	}
	if (
		typeof entrada.hashLicencia !== "string" ||
		!RE_HEX64.test(entrada.hashLicencia)
	) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.VIGENCIA_REGISTRO_INVALIDA,
			"la entrada no declara un hash de licencia válido",
		);
	}
	if (
		typeof entrada.vigenteHasta !== "number" ||
		!Number.isFinite(entrada.vigenteHasta) ||
		entrada.vigenteHasta <= 0
	) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.VIGENCIA_REGISTRO_INVALIDA,
			`la entrada no declara una vigencia válida: ${String(entrada.vigenteHasta)}`,
		);
	}
	if (!Object.values(ESTADO_LICENCIA).includes(entrada.estado)) {
		// An unrecognised state is refused, never optimistically read as `activa`.
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.ESTADO_REGISTRO_INVALIDO,
			`estado de licencia desconocido: ${String(entrada.estado)}`,
		);
	}

	// ── 6. State. Both non-active states refuse — no "valid with warnings" ──
	if (entrada.estado === ESTADO_LICENCIA.REVOCADA) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_REVOCADA,
			`el registro de '${pais}' declara la licencia revocada: no admite avisos`,
		);
	}
	if (entrada.estado === ESTADO_LICENCIA.SUSPENDIDA) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_SUSPENDIDA,
			`el registro de '${pais}' declara la licencia suspendida: no admite avisos`,
		);
	}

	// ── 7. Windows. Two independent ones, and the credential may not exceed the registry ──
	// `vigenteHasta` is exclusive in both places, matching `validarCredencial`.
	if (credencial.vigenteHasta <= ahora) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_CADUCADA,
			`la credencial caducó antes de ${ahora} (vigente hasta ${credencial.vigenteHasta})`,
		);
	}
	if (entrada.vigenteHasta <= ahora) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_CADUCADA,
			`el registro da la licencia por vencida (vigente hasta ${entrada.vigenteHasta}, ahora ${ahora})`,
		);
	}
	if (credencial.vigenteHasta > entrada.vigenteHasta) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_CADUCADA,
			`la credencial reclama vigencia hasta ${credencial.vigenteHasta} pero el registro solo hasta ${entrada.vigenteHasta}`,
		);
	}

	// ── 8. The claims the credential makes about that entry ──
	if (
		entrada.especialidad !== undefined &&
		credencial.especialidad !== entrada.especialidad
	) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.ESPECIALIDAD_NO_REGISTRADA,
			`la entrada registra '${entrada.especialidad}' y la credencial reclama '${String(credencial.especialidad)}'`,
		);
	}
	if (
		entrada.autoridad !== undefined &&
		credencial.autoridad !== entrada.autoridad
	) {
		return fallo(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.AUTORIDAD_NO_REGISTRADA,
			`la entrada registra '${entrada.autoridad}' y la credencial declara '${credencial.autoridad}'`,
		);
	}

	return {
		ok: true,
		credencial,
		entrada,
		metodoVerificacion: metodoRegistroPorPais(pais, version),
		verificadoEn: ahora,
	};
}

/**
 * A verification strategy — the seam Phase 3 fills with peer attestation and
 * quorum revocation.
 *
 * Declared here, implemented by exactly one member today. The point of the
 * interface is that adding `avalado_por_pares` or `revocacion_por_quorum` is a
 * new implementation of *this* type, never a new branch inside
 * {@link acreditarContraRegistro}.
 */
export interface EstrategiaAcreditacion {
	/** The `MetodoVerificacion` class this strategy produces. */
	readonly clase: MetodoVerificacion["clase"];
	acreditar(
		credencial: CredencialMedica,
		fuente: FuenteAcreditacion,
		ahora: number,
	): Promise<ResultadoAcreditacion>;
}

/** The only implemented strategy: verification of foundation, by country registry. */
export const ESTRATEGIA_REGISTRO_POR_PAIS: EstrategiaAcreditacion = {
	clase: "registro_por_pais",
	acreditar: acreditarContraRegistro,
};

/**
 * Classes declared by `docs/medico/modelo-datos.md` §4.2 that this phase does
 * not implement. Listed so the gap is explicit rather than inferred from a
 * missing export.
 */
export const CLASES_NO_IMPLEMENTADAS = [
	"colegio_directo",
	"testimonio_directo",
	"supervision",
] as const;

/**
 * Dispatch to a strategy by its verification class.
 *
 * Fails closed with {@link MOTIVO_RECHAZO_CONSULTA_REGISTRO.METODO_NO_IMPLEMENTADO}
 * for a class with no strategy today, so "not built yet" can never be read as
 * "nothing to check". Peer attestation and quorum revocation arrive here, as
 * implementations of {@link EstrategiaAcreditacion}, in Phase 3.
 */
export async function acreditarCon(
	clase: MetodoVerificacion["clase"],
	credencial: CredencialMedica,
	fuente: FuenteAcreditacion,
	ahora: number,
): Promise<ResultadoAcreditacion> {
	if (clase === ESTRATEGIA_REGISTRO_POR_PAIS.clase) {
		return ESTRATEGIA_REGISTRO_POR_PAIS.acreditar(credencial, fuente, ahora);
	}
	return fallo(
		MOTIVO_RECHAZO_CONSULTA_REGISTRO.METODO_NO_IMPLEMENTADO,
		`la clase de verificación '${clase}' todavía no tiene estrategia en esta fase`,
	);
}

/**
 * An in-memory registry. Pure data, no I/O — the fixture a test supplies and the
 * stand-in Phase 3 replaces with a replicated, append-only snapshot.
 */
export class RegistroLicenciasEnMemoria implements FuenteAcreditacion {
	private readonly entradasPorPais = new Map<
		string,
		EntradaRegistroLicencia[]
	>();
	private readonly versiones = new Map<string, string>();
	private readonly soportados: ReadonlySet<string>;

	/**
	 * @param entradas - the registry contents. Anything whose `estado` is not in
	 *   {@link ESTADO_LICENCIA} is kept verbatim, so a test can prove such an
	 *   entry is refused rather than normalised away by the fixture.
	 * @param opciones.versionRegistro - snapshot version, per country or shared.
	 * @param opciones.paisesSoportados - countries this source speaks for. Defaults
	 *   to the countries actually present in `entradas`.
	 */
	constructor(
		entradas: readonly EntradaRegistroLicencia[] = [],
		opciones: {
			readonly versionRegistro?: string | Readonly<Record<string, string>>;
			readonly paisesSoportados?: readonly string[];
		} = {},
	) {
		for (const entrada of entradas) {
			const clave = entrada?.pais?.toUpperCase?.() ?? "";
			if (clave === "") continue;
			const lista = this.entradasPorPais.get(clave);
			if (lista) lista.push(entrada);
			else this.entradasPorPais.set(clave, [entrada]);
		}

		const version = opciones.versionRegistro;
		for (const pais of this.entradasPorPais.keys()) {
			const propia = typeof version === "string" ? version : version?.[pais];
			// An empty registry still has a version, so "supported but no snapshot" is
			// distinguishable from "empty snapshot" — both refuse, for different reasons.
			this.versiones.set(pais, propia ?? `${pais}-v0`);
		}

		const declarados = opciones.paisesSoportados?.map((p) => p.toUpperCase());
		this.soportados = new Set(declarados ?? [...this.entradasPorPais.keys()]);
	}

	get paisesSoportados(): readonly string[] {
		return [...this.soportados];
	}

	versionRegistro(pais: string): string | undefined {
		return this.versiones.get(pais.toUpperCase());
	}

	consultar({
		pais,
		hashLicencia,
	}: ConsultaRegistroLicencia): EntradaRegistroLicencia | undefined {
		const lista = this.entradasPorPais.get(pais.toUpperCase());
		if (!lista) return undefined;
		return lista.find((e) => e.hashLicencia === hashLicencia);
	}
}

/** Reasons this module can produce, re-exported so callers need one import. */
export { MOTIVO_RECHAZO_CREDENCIAL, MOTIVO_RECHAZO_REGISTRO };
