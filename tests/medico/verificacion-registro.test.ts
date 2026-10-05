/**
 * Foundation verification — the point where a credential stops being a
 * well-formed object and starts being accredited.
 *
 * ─── WHAT IS BEING PINNED ───────────────────────────────────────────────────
 *
 * `src/medico/credencial.ts` already proves FORM: ISO country, SHA-256 licence
 * hash, a signed `vigenteHasta` that has not lapsed, a signature over the
 * canonical bytes. Everything a well-formed forgery would also pass. The
 * question these tests answer is the substrate one — *does this licence exist,
 * and does the registry say it is good?*
 *
 * Three defects from OrionHealth's `license_verifier.dart` are closed here, and
 * each has a test:
 *
 *   1. `unknown` on an empty registry → an unsupportable country refuses
 *      (`PAIS_NO_SOPORTADO`, `PAIS_SIN_REGISTRO`). No state means "proceed".
 *   2. `expired` declared and never returned → `vigenteHasta` exists on BOTH
 *      the credential and the registry entry, and the credential may not claim
 *      a longer window than the registry grants.
 *   3. A hash `Set` cannot express state → the registry is an array of entries
 *      carrying `estado`, so `suspendida` and `revocada` are reachable and both
 *      refuse. This is the new value over `./registro.ts`, whose `Set<string>`
 *      can only say present or absent.
 *
 * The lookup is a single injected function. There is no fetch, no file, no clock
 * read: `ahora` is a constant in this file, and the fixture below *is* the
 * network. That is what makes the determinism test meaningful — no I/O, no
 * randomness, so the same inputs must yield byte-identical results forever.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { createPostQuantumIdentity } from "../../src/identity/index.js";
import { hashLicencia } from "../../src/medico/canonica.js";
import { crearCredencial } from "../../src/medico/credencial.js";
import {
	type CredencialMedica,
	ESTADO_EMISION,
	TIPO_CREDENCIAL,
} from "../../src/medico/index.js";
import {
	acreditarCon,
	acreditarContraRegistro,
	CLASES_NO_IMPLEMENTADAS,
	type EntradaRegistroLicencia,
	ESTADO_LICENCIA,
	ESTRATEGIA_REGISTRO_POR_PAIS,
	type FuenteAcreditacion,
	MOTIVO_RECHAZO_CONSULTA_REGISTRO,
	metodoRegistroPorPais,
	RegistroLicenciasEnMemoria,
} from "../../src/medico/verificacion-registro.js";
import type { NodoId } from "../../src/types/index.js";

const AHORA = 1_700_000_000_000;
const DIA = 86_400_000;

const NUMERO_CO = "12-345 678";
const VERSION = "rethus-2026-01";

// ── fixtures ────────────────────────────────────────────────────────────────

let hashCO = "";
let hashAUSENTE = "";

async function cargarHashes(): Promise<void> {
	hashCO = await hashLicencia(NUMERO_CO);
	hashAUSENTE = await hashLicencia("99-999-999");
}

function entrada(
	over: Partial<EntradaRegistroLicencia> = {},
): EntradaRegistroLicencia {
	return {
		pais: "CO",
		hashLicencia: hashCO,
		vigenteHasta: AHORA + 365 * DIA,
		estado: ESTADO_LICENCIA.ACTIVA,
		...over,
	};
}

function fuente(
	entradas: readonly EntradaRegistroLicencia[],
	opciones: {
		versionRegistro?: string;
		paisesSoportados?: readonly string[];
	} = {},
): RegistroLicenciasEnMemoria {
	return new RegistroLicenciasEnMemoria(entradas, {
		versionRegistro: opciones.versionRegistro ?? VERSION,
		...(opciones.paisesSoportados
			? { paisesSoportados: opciones.paisesSoportados }
			: {}),
	});
}

async function credencial(
	over: Partial<Parameters<typeof crearCredencial>[0]> = {},
): Promise<CredencialMedica> {
	const ident = await createPostQuantumIdentity(
		`mlkem${"e".repeat(32)}` as NodoId,
	);
	return crearCredencial(
		{
			tipo: TIPO_CREDENCIAL.LICENCIA,
			pais: "CO",
			autoridad: "minsalud-rethus",
			idLicencia: hashCO,
			emitidoEn: AHORA - DIA,
			vigenteHasta: AHORA + 200 * DIA,
			estadoEmision: ESTADO_EMISION.ATESTIGUADA_PARES,
			emisor: ident.nodoId,
			...over,
		},
		ident,
	);
}

beforeAll(cargarHashes);

// ── the accreditation path ──────────────────────────────────────────────────

describe("acreditarContraRegistro — a licence that exists and is in good standing", () => {
	it("accredits a credential whose licence is in the registry and current", async () => {
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([entrada()]),
			AHORA,
		);

		expect(r.ok).toBe(true);
		if (!r.ok) return;
		expect(r.entrada.hashLicencia).toBe(hashCO);
		expect(r.accesoPermitido).toBeUndefined();
	});

	// ── REQUIREMENT 4: the record of HOW, not just that it passed ──
	it("stamps metodoVerificacion with the country and the snapshot version", async () => {
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([entrada()]),
			AHORA,
		);

		expect(r.ok).toBe(true);
		if (!r.ok) return;
		expect(r.metodoVerificacion).toEqual({
			clase: "registro_por_pais",
			pais: "CO",
			versionRegistro: VERSION,
		});
		// The trail carries the injected clock, never a hidden `Date.now()`.
		expect(r.verificadoEn).toBe(AHORA);
	});

	it("distinguishes snapshots: the same licence, two versions, two trails", async () => {
		const cred = await credencial();
		const viejo = await acreditarContraRegistro(
			cred,
			fuente([entrada()], { versionRegistro: "rethus-2025-06" }),
			AHORA,
		);
		const nuevo = await acreditarContraRegistro(
			cred,
			fuente([entrada()], { versionRegistro: VERSION }),
			AHORA,
		);

		expect(nuevo.ok).toBe(true);
		if (!viejo.ok || !nuevo.ok) return;
		expect(viejo.metodoVerificacion.versionRegistro).toBe("rethus-2025-06");
		expect(nuevo.metodoVerificacion.versionRegistro).toBe(VERSION);
	});

	it("never puts the licence number in the result", async () => {
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([entrada()]),
			AHORA,
		);
		expect(JSON.stringify(r)).not.toContain("12-345");
	});

	it("keeps the registry as the binding side: a credential cannot outlive the entry", async () => {
		// The credential claims 200 days; the registry grants 10.
		const cred = await credencial({ vigenteHasta: AHORA + 200 * DIA });
		const r = await acreditarContraRegistro(
			cred,
			fuente([entrada({ vigenteHasta: AHORA + 10 * DIA })]),
			AHORA,
		);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_CADUCADA);
	});

	it("accepts a credential whose window is shorter than the registry grants", async () => {
		const cred = await credencial({ vigenteHasta: AHORA + 10 * DIA });
		const r = await acreditarContraRegistro(
			cred,
			fuente([entrada({ vigenteHasta: AHORA + 365 * DIA })]),
			AHORA,
		);
		expect(r.ok).toBe(true);
	});
});

// ── the four required refusals ──────────────────────────────────────────────

describe("acreditarContraRegistro — refusals carry a reason, never a boolean", () => {
	it("refuses a licence that is simply not in the registry", async () => {
		// Registry is populated but holds a different doctor.
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([entrada({ hashLicencia: hashAUSENTE })]),
			AHORA,
		);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_NO_ENCONTRADA,
		);
		expect(r.accesoPermitido).toBe(false);
	});

	// ── REQUIREMENT: fail closed, NEVER "unknown" ──
	it("fails closed on a country no source speaks for", async () => {
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([entrada()], { paisesSoportados: ["CO"] }),
			AHORA,
		);
		const es = await credencial({ pais: "ES" });

		const rEs = await acreditarContraRegistro(
			es,
			fuente([entrada()], { paisesSoportados: ["CO"] }),
			AHORA,
		);
		expect(rEs.ok).toBe(false);
		if (rEs.ok) return;
		expect(rEs.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.PAIS_NO_SOPORTADO);
		expect(rEs.accesoPermitido).toBe(false);
		// The word must not be reachable in either outcome.
		expect(JSON.stringify(rEs)).not.toContain("unknown");
		expect(JSON.stringify(r)).not.toContain("unknown");
	});

	it("fails closed when a supported country has no snapshot loaded", async () => {
		// Declared supported, but nothing to consult — different from "licence absent".
		const vacia = new RegistroLicenciasEnMemoria([], {
			paisesSoportados: ["CO"],
		});
		expect(vacia.versionRegistro("CO")).toBeUndefined();

		const r = await acreditarContraRegistro(await credencial(), vacia, AHORA);
		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.PAIS_SIN_REGISTRO);
		expect(r.accesoPermitido).toBe(false);
	});

	it('refuses a suspended licence — no "valid with warnings"', async () => {
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([entrada({ estado: ESTADO_LICENCIA.SUSPENDIDA })]),
			AHORA,
		);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_SUSPENDIDA);
		expect(r.accesoPermitido).toBe(false);
		expect(JSON.stringify(r)).not.toContain('ok":true');
	});

	it("refuses a revoked licence, and revocation is terminal", async () => {
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([entrada({ estado: ESTADO_LICENCIA.REVOCADA })]),
			AHORA,
		);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_REVOCADA);
		expect(r.accesoPermitido).toBe(false);
	});

	it("refuses every non-active state: the enum is reachable, not decorative", async () => {
		for (const estado of [
			ESTADO_LICENCIA.SUSPENDIDA,
			ESTADO_LICENCIA.REVOCADA,
		]) {
			const r = await acreditarContraRegistro(
				await credencial(),
				fuente([entrada({ estado })]),
				AHORA,
			);
			expect(r.ok).toBe(false);
			if (r.ok) continue;
			expect(Object.values(MOTIVO_RECHAZO_CONSULTA_REGISTRO)).toContain(
				r.motivo,
			);
			expect(r.accesoPermitido).toBe(false);
		}
	});

	it("refuses an unknown state instead of optimistically reading it as active", async () => {
		const roto = {
			...entrada(),
			estado: "archivada",
		} as unknown as EntradaRegistroLicencia;
		const r = await acreditarContraRegistro(
			await credencial(),
			fuente([roto]),
			AHORA,
		);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.ESTADO_REGISTRO_INVALIDO,
		);
	});

	// ── DEFECT 2: expiry, now on the registry side too ──
	it("refuses a licence the registry itself reports as lapsed", async () => {
		const cred = await credencial({ vigenteHasta: AHORA + 10 * DIA });
		const r = await acreditarContraRegistro(
			cred,
			fuente([entrada({ vigenteHasta: AHORA - DIA })]),
			AHORA,
		);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_CADUCADA);
	});

	it("treats expiry as exclusive at the exact millisecond", async () => {
		// Both windows close at the same instant — the credential may never claim a
		// longer window than the registry grants, so a wider credential is refused
		// before the boundary can be probed in isolation.
		const cred = await credencial({ vigenteHasta: AHORA + 2 * DIA });
		const reg = fuente([entrada({ vigenteHasta: AHORA + 2 * DIA })]);

		await expect(
			acreditarContraRegistro(cred, reg, AHORA + 2 * DIA - 1),
		).resolves.toMatchObject({ ok: true });
		await expect(
			acreditarContraRegistro(cred, reg, AHORA + 2 * DIA),
		).resolves.toMatchObject({ ok: false });
	});
});

// ── form is still checked before the registry is consulted ──────────────────

describe("acreditarContraRegistro — form precedes substance", () => {
	it("refuses a credential whose own validity window has closed", async () => {
		const caduca = await credencial({
			emitidoEn: AHORA - 400 * DIA,
			vigenteHasta: AHORA - DIA,
		});
		const r = await acreditarContraRegistro(caduca, fuente([entrada()]), AHORA);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.CREDENCIAL_MAL_FORMADA,
		);
		// The credential's own reason is preserved for operators.
		expect(r.detalle).toContain("credencial_caducada");
	});

	it("never spends a lookup on a malformed credential", async () => {
		let consultas = 0;
		const contadora: FuenteAcreditacion = {
			paisesSoportados: ["CO"],
			versionRegistro: () => VERSION,
			consultar: () => {
				consultas += 1;
				return undefined;
			},
		};

		const malo = { ...(await credencial()), firma: new Uint8Array(0) };
		const r = await acreditarContraRegistro(malo, contadora, AHORA);

		expect(r.ok).toBe(false);
		expect(consultas).toBe(0);
	});

	it("refuses a registry entry that answers a CO query with an ES entry", async () => {
		const cruzada: FuenteAcreditacion = {
			paisesSoportados: ["CO"],
			versionRegistro: () => VERSION,
			consultar: () => entrada({ pais: "ES" }),
		};
		const r = await acreditarContraRegistro(await credencial(), cruzada, AHORA);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.ENTRADA_DE_OTRO_PAIS,
		);
	});

	it("refuses a specialty the registry holds under a different slug", async () => {
		const esp = await credencial({
			tipo: TIPO_CREDENCIAL.ESPECIALIDAD,
			especialidad: "cardiologia",
		});
		const r = await acreditarContraRegistro(
			esp,
			fuente([entrada({ especialidad: "radiologia" })]),
			AHORA,
		);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.ESPECIALIDAD_NO_REGISTRADA,
		);
	});

	it("treats a throwing transport as a failure, not as a plain miss", async () => {
		const rota: FuenteAcreditacion = {
			paisesSoportados: ["CO"],
			versionRegistro: () => VERSION,
			consultar: () => {
				throw new Error("replica inalcanzable");
			},
		};
		const r = await acreditarContraRegistro(await credencial(), rota, AHORA);

		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.CONSULTA_FALLIDA);
		expect(r.detalle).toContain("replica inalcanzable");
	});
});

// ── REQUIREMENT: determinism ────────────────────────────────────────────────

describe("acreditarContraRegistro — the reason is stable", () => {
	it("returns a byte-identical refusal across repeated calls", async () => {
		const cred = await credencial();
		const casos = [
			fuente([entrada({ hashLicencia: hashAUSENTE })]),
			fuente([entrada({ estado: ESTADO_LICENCIA.SUSPENDIDA })]),
			fuente([entrada({ estado: ESTADO_LICENCIA.REVOCADA })]),
			fuente([entrada({ vigenteHasta: AHORA - DIA })]),
			fuente([]),
		];

		for (const reg of casos) {
			const primera = await acreditarContraRegistro(cred, reg, AHORA);
			for (let i = 0; i < 5; i++) {
				const otra = await acreditarContraRegistro(cred, reg, AHORA);
				expect(JSON.stringify(otra)).toBe(JSON.stringify(primera));
			}
		}
	});

	it("returns a byte-identical acceptance across repeated calls", async () => {
		const cred = await credencial();
		const reg = fuente([entrada()]);
		const primera = await acreditarContraRegistro(cred, reg, AHORA);
		const otra = await acreditarContraRegistro(cred, reg, AHORA);
		expect(JSON.stringify(otra)).toBe(JSON.stringify(primera));
	});

	it("gives the same reason for the same failure regardless of call order", async () => {
		const cred = await credencial();
		const suspendido = fuente([
			entrada({ estado: ESTADO_LICENCIA.SUSPENDIDA }),
		]);
		const revocado = fuente([entrada({ estado: ESTADO_LICENCIA.REVOCADA })]);

		const primero = await acreditarContraRegistro(cred, suspendido, AHORA);
		const segundo = await acreditarContraRegistro(cred, revocado, AHORA);
		const tercero = await acreditarContraRegistro(cred, suspendido, AHORA);

		expect(primero.motivo).toBe(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_SUSPENDIDA,
		);
		expect(segundo.motivo).toBe(
			MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_REVOCADA,
		);
		expect(tercero.motivo).toBe(primero.motivo);
	});
});

// ── REQUIREMENT 5: the Phase 3 extension point ──────────────────────────────

describe("EstrategiaAcreditacion — the seam Phase 3 fills, not a branch", () => {
	it("dispatches to the registry strategy when asked for registro_por_pais", async () => {
		const r = await acreditarCon(
			"registro_por_pais",
			await credencial(),
			fuente([entrada()]),
			AHORA,
		);
		expect(r.ok).toBe(true);
	});

	it("fails closed for a class that has no strategy yet", async () => {
		for (const clase of CLASES_NO_IMPLEMENTADAS) {
			const r = await acreditarCon(
				clase,
				await credencial(),
				fuente([entrada()]),
				AHORA,
			);
			expect(r.ok).toBe(false);
			if (r.ok) continue;
			// "Not built yet" must never read as "nothing to check".
			expect(r.motivo).toBe(
				MOTIVO_RECHAZO_CONSULTA_REGISTRO.METODO_NO_IMPLEMENTADO,
			);
			expect(r.accesoPermitido).toBe(false);
			expect(r.detalle).toContain(clase);
		}
	});

	it("names the implemented strategy so the registry can enumerate strategies", () => {
		expect(ESTRATEGIA_REGISTRO_POR_PAIS.clase).toBe("registro_por_pais");
	});

	it("builds the metodoVerificacion an Aval must carry, in one place", () => {
		expect(metodoRegistroPorPais("co", VERSION)).toEqual({
			clase: "registro_por_pais",
			pais: "CO",
			versionRegistro: VERSION,
		});
	});
});

describe("RegistroLicenciasEnMemoria — the injected seam", () => {
	it("answers only for the country it holds, case-insensitively", async () => {
		const reg = fuente([entrada()]);
		expect(reg.consultar({ pais: "CO", hashLicencia: hashCO })).toBeDefined();
		expect(reg.consultar({ pais: "co", hashLicencia: hashCO })).toBeDefined();
		expect(reg.consultar({ pais: "ES", hashLicencia: hashCO })).toBeUndefined();
	});

	it("stores only hashes, never a licence number", () => {
		const reg = fuente([entrada()]);
		expect(JSON.stringify([...reg.paisesSoportados])).not.toContain("12-345");
		expect(
			JSON.stringify(reg.consultar({ pais: "CO", hashLicencia: hashCO })),
		).not.toContain("12-345");
	});

	it("holds a suspended and a revoked licence as distinct entries, not as absence", async () => {
		const reg = fuente([
			entrada({ hashLicencia: hashAUSENTE, estado: ESTADO_LICENCIA.REVOCADA }),
		]);
		const r = await acreditarContraRegistro(
			await credencial({ idLicencia: hashAUSENTE }),
			reg,
			AHORA,
		);
		// Present in the registry and still refused: membership is not validity.
		expect(r.ok).toBe(false);
		if (r.ok) return;
		expect(r.motivo).toBe(MOTIVO_RECHAZO_CONSULTA_REGISTRO.LICENCIA_REVOCADA);
	});
});
