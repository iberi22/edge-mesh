/**
 * Aval (endorsement) model tests.
 *
 * The load-bearing rule under test: an `Aval` is a peer assertion about a
 * *claim*, never about an *encounter*. Only `licencia_verificada` and
 * `especialidad_verificada` may promote a credential to `atestiguada_pares`.
 * Counting clinical interactions toward licensure is the hole that admits a
 * well-liked non-doctor into a network of doctors.
 */

import { describe, expect, it } from "vitest";
import {
	createPostQuantumIdentity,
	type PostQuantumIdentity,
} from "../../src/identity/index.js";
import {
	type Aval,
	aTransaccionKarma,
	avalCuentaParaPromocion,
	type BorradorAval,
	crearAval,
	hashCredencial,
	idAval,
	MOTIVO_RECHAZO_AVAL,
	OBJETO_AVAL,
	OBJETO_QUE_CUENTA,
	prepararCredencialParaAval,
	resumirAvales,
	validarAval,
	validarAvalFirmado,
	verificarFirmaAval,
} from "../../src/medico/index.js";
import {
	ALCANCE_AVAL,
	ESTADO_EMISION,
	TIPO_CREDENCIAL,
} from "../../src/medico/types.js";
import type { NodoId } from "../../src/types/index.js";

const AHORA = 1_700_000_000_000;
const DIA = 86_400_000;

const AVALADOR = `mlkem${"a".repeat(32)}` as NodoId;
const AVALADO = `mlkem${"b".repeat(32)}` as NodoId;

async function identidad(nodoId: NodoId): Promise<PostQuantumIdentity> {
	return createPostQuantumIdentity(nodoId);
}

function borrador(over: Partial<BorradorAval> = {}): BorradorAval {
	return {
		avalador: AVALADOR,
		avalado: AVALADO,
		objetoAval: OBJETO_AVAL.LICENCIA_VERIFICADA,
		credencialRef: "cred-1",
		hashCredencial: "d".repeat(64),
		metodoVerificacion: {
			clase: "registro_por_pais",
			pais: "CO",
			versionRegistro: "rethus-2026-01",
		},
		evidenciaHash: "e".repeat(64),
		alcance: ALCANCE_AVAL.ANUAL,
		emitidoEn: AHORA - DIA,
		vigenteHasta: AHORA + 364 * DIA,
		nonce: "nonce-1",
		...over,
	};
}

/** A signed `Aval`, bound to a real credential hash. */
async function avalFirmado(
	over: Partial<BorradorAval> = {},
	id?: PostQuantumIdentity,
): Promise<Aval> {
	const ident = id ?? (await identidad(AVALADOR));
	const b = borrador(over);
	return crearAval(b, ident, { hash: b.hashCredencial });
}

describe("Aval — construction and signature", () => {
	it("accepts a valid signed endorsement", async () => {
		const ident = await identidad(AVALADOR);
		const aval = await avalFirmado({}, ident);
		const r = validarAval(aval, AHORA);
		expect(r.ok).toBe(true);
		// The signature covers the canonical bytes: it verifies directly...
		await expect(
			verificarFirmaAval(aval, ident, ident.exportarPublico()),
		).resolves.toBe(true);

		const firmado = await validarAvalFirmado(
			aval,
			ident,
			ident.exportarPublico(),
			AHORA,
		);
		expect(firmado.ok).toBe(true);
	});

	it("verifies against the avalador key, never the avalado one", async () => {
		const identAvalador = await identidad(AVALADOR);
		const identAvalado = await identidad(AVALADO);
		const aval = await avalFirmado({}, identAvalador);
		// The entire content of an endorsement is that a second party looked and
		// agreed, so the avalado's own key must not validate it.
		await expect(
			verificarFirmaAval(aval, identAvalado, identAvalado.exportarPublico()),
		).resolves.toBe(false);
	});

	it("rejects an aval without a signature", async () => {
		const aval = await avalFirmado();
		for (const firma of [new Uint8Array(0), undefined, null]) {
			const r = validarAval({ ...aval, firma } as unknown as Aval, AHORA);
			expect(r.ok).toBe(false);
			if (!r.ok) {
				expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.FIRMA_AUSENTE);
				expect(r.cuentaParaPromocion).toBe(false);
			}
		}
	});

	it("rejects an aval whose signature does not verify against the avalador key", async () => {
		const honest = await identidad(AVALADOR);
		const impostor = await identidad(`mlkem${"c".repeat(32)}` as NodoId);
		// Signed by the impostor while claiming to come from the honest avalador.
		const aval = await crearAval(
			borrador({ avalador: honest.nodoId }),
			impostor,
			{
				hash: borrador().hashCredencial,
			},
		);

		const r = await validarAvalFirmado(
			aval,
			honest,
			honest.exportarPublico(),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) {
			expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.FIRMA_INVALIDA);
			expect(r.cuentaParaPromocion).toBe(false);
		}
	});

	it("rejects a tampered aval even though the original signature was valid", async () => {
		// The exact attack the `Aval`-is-not-a-`Cita` boundary exists for: relabel a
		// clinical interaction as a licence verification after the fact. The aval was
		// signed as `interaccion_clinica`, so this label change must not verify.
		const ident = await identidad(AVALADOR);
		const clinico = await avalFirmado(
			{ objetoAval: OBJETO_AVAL.INTERACCION_CLINICA },
			ident,
		);
		const alterado = {
			...clinico,
			objetoAval: OBJETO_AVAL.LICENCIA_VERIFICADA,
		};
		const r = await validarAvalFirmado(
			alterado,
			ident,
			ident.exportarPublico(),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.FIRMA_INVALIDA);
	});

	it("refuses self-endorsement, the auto_emision rule copied from karma.ts", async () => {
		const nodo = AVALADOR;
		const aval = await avalFirmado({ avalador: nodo, avalado: nodo });
		const r = validarAval(aval, AHORA);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.AUTO_ENDORSEMENT);
	});

	it("refuses to mint an aval against a hash that does not match the credential", async () => {
		const ident = await identidad(AVALADOR);
		await expect(
			crearAval(borrador({ hashCredencial: "f".repeat(64) }), ident, {
				hash: "0".repeat(64),
			}),
		).rejects.toThrow(/no corresponde a la credencial verificada/);
	});

	it("builds an id that is unique per avalador, avalado, timestamp and nonce", () => {
		const base = idAval(AVALADOR, AVALADO, AHORA, "n1");
		expect(base).toBe(`${AVALADOR}:${AVALADO}:${AHORA}:n1`);
		// The nonce is what stops a replayed aval from colliding with a fresh one.
		expect(idAval(AVALADOR, AVALADO, AHORA, "n2")).not.toBe(base);
		expect(idAval(AVALADO, AVALADOR, AHORA, "n1")).not.toBe(base);
	});
});

describe("Aval — validation fails closed", () => {
	it("rejects an expired aval", async () => {
		const aval = await avalFirmado({ vigenteHasta: AHORA - DIA });
		const r = validarAval(aval, AHORA);
		expect(r.ok).toBe(false);
		if (!r.ok) {
			expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.AVAL_CADUCADO);
			expect(r.cuentaParaPromocion).toBe(false);
		}
	});

	it("rejects a non-revocable aval — every endorsement must be revocable", async () => {
		const aval = await avalFirmado();
		const r = validarAval(
			{ ...aval, revocable: false as unknown as true },
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO);
	});

	it("rejects a registry check with no versionRegistro — a stale snapshot must be nameable", async () => {
		const aval = await avalFirmado({
			metodoVerificacion: {
				clase: "registro_por_pais",
				pais: "CO",
				versionRegistro: "",
			},
		});
		const r = validarAval(aval, AHORA);
		expect(r.ok).toBe(false);
		if (!r.ok)
			expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.VERSION_REGISTRO_AUSENTE);
	});

	it("rejects incomplete metodoVerificacion for each class", async () => {
		const colegio = await avalFirmado({
			metodoVerificacion: { clase: "colegio_directo", ref: "" },
		});
		expect(validarAval(colegio, AHORA).ok).toBe(false);

		const sup = await avalFirmado({
			metodoVerificacion: { clase: "supervision", desde: 5, hasta: 1 },
		});
		const rSup = validarAval(sup, AHORA);
		expect(rSup.ok).toBe(false);
		if (!rSup.ok)
			expect(rSup.motivo).toBe(MOTIVO_RECHAZO_AVAL.VIGENCIA_INVALIDA);

		const desconocido = await avalFirmado({
			metodoVerificacion: {
				clase: "vibes",
			} as unknown as BorradorAval["metodoVerificacion"],
		});
		expect(validarAval(desconocido, AHORA).ok).toBe(false);
	});

	it("rejects an aval with no credential reference at all", async () => {
		const aval = await avalFirmado();
		const r = validarAval(
			{ ...aval, credencialRef: "", hashCredencial: "" },
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.CAMPO_INVALIDO);
	});

	it("rejects incoherent dates", async () => {
		const aval = await avalFirmado();
		const r = validarAval({ ...aval, emitidoEn: AHORA + 400 * DIA }, AHORA);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.motivo).toBe(MOTIVO_RECHAZO_AVAL.VIGENCIA_INVALIDA);

		const sinVigencia = validarAval(
			{ ...aval, vigenteHasta: undefined as unknown as number },
			AHORA,
		);
		expect(sinVigencia.ok).toBe(false);
		if (!sinVigencia.ok)
			expect(sinVigencia.motivo).toBe(MOTIVO_RECHAZO_AVAL.VIGENCIA_INVALIDA);
	});
});

describe("Aval vs Cita — the structural boundary", () => {
	it("only two objetos count toward promotion", () => {
		expect(avalCuentaParaPromocion(OBJETO_AVAL.LICENCIA_VERIFICADA)).toBe(true);
		expect(avalCuentaParaPromocion(OBJETO_AVAL.ESPECIALIDAD_VERIFICADA)).toBe(
			true,
		);
		// The load-bearing rule: a physician cannot buy their way to licensure.
		expect(avalCuentaParaPromocion(OBJETO_AVAL.INTERACCION_CLINICA)).toBe(
			false,
		);
		expect(avalCuentaParaPromocion(OBJETO_AVAL.DOCENCIA)).toBe(false);
	});

	it("keeps the rule in one exported place", () => {
		expect([...OBJETO_QUE_CUENTA].sort()).toEqual([
			"especialidad_verificada",
			"licencia_verificada",
		]);
	});

	it("counts clinical interactions in the summary but never toward promotion", async () => {
		const interacciones = await Promise.all(
			[0, 1, 2, 3].map((i) =>
				avalFirmado({
					objetoAval: OBJETO_AVAL.INTERACCION_CLINICA,
					nonce: `int-${i}`,
					avalador:
						`mlkem${String.fromCharCode(100 + i)}${"".padEnd(27, "0")}` as NodoId,
				}),
			),
		);
		const resumen = resumirAvales(interacciones, AHORA);
		expect(resumen.total).toBe(4);
		expect(resumen.porObjeto[OBJETO_AVAL.INTERACCION_CLINICA]).toBe(4);
		// 4 interactions, zero licence verifications: nothing was proven.
		expect(resumen.verificacionesLicencia).toBe(0);
	});

	it("carries no patient data fields, so a clinical aval is only a boolean with a signer", async () => {
		const aval = await avalFirmado({
			objetoAval: OBJETO_AVAL.INTERACCION_CLINICA,
		});
		// Asserts "a real encounter occurred" — no date, no diagnosis, no content.
		expect(aval.objetoAval).toBe(OBJETO_AVAL.INTERACCION_CLINICA);
		const forbidden = [
			"paciente",
			"diagnostico",
			"diagnóstico",
			"cita",
			"tratamiento",
			"sintomas",
		];
		for (const key of Object.keys(aval)) {
			expect(forbidden).not.toContain(key);
		}
	});
});

describe("Aval — summary fold", () => {
	it("counts distinct avaladores, so one peer cannot move the threshold", async () => {
		const uno = await identidad(AVALADOR);
		const muchos = await Promise.all(
			[0, 1, 2, 3, 4].map((i) => avalFirmado({ nonce: `n-${i}` }, uno)),
		);
		const resumen = resumirAvales(muchos, AHORA);
		expect(resumen.total).toBe(5);
		// Five endorsements, one signer.
		expect(resumen.avaladoresUnicos).toBe(1);
		expect(resumen.verificacionesLicencia).toBe(1);
	});

	it("drops expired avals from the fold, so revocation and lapse both lower the count", async () => {
		const vigente = await avalFirmado({ nonce: "ok" });
		const caducado = await avalFirmado({
			nonce: "cad",
			vigenteHasta: AHORA - DIA,
		});
		const resumen = resumirAvales([vigente, caducado], AHORA);
		expect(resumen.total).toBe(1);
	});

	it("drops unsigned avals from the fold", async () => {
		const sinFirma = await avalFirmado();
		const resumen = resumirAvales(
			[{ ...sinFirma, firma: new Uint8Array(0) }],
			AHORA,
		);
		expect(resumen.total).toBe(0);
	});

	it("reports the newest endorsement time", async () => {
		const a = await avalFirmado({ nonce: "a", emitidoEn: AHORA - 10 * DIA });
		const b = await avalFirmado({ nonce: "b", emitidoEn: AHORA - DIA });
		expect(resumirAvales([a, b], AHORA).ultimoAval).toBe(AHORA - DIA);
		expect(resumirAvales([], AHORA).ultimoAval).toBeUndefined();
	});
});

describe("Aval — reuse of TransaccionKarma", () => {
	it("adapts to the karma shape, carrying the endorsed node as sujeto", async () => {
		const aval = await avalFirmado();
		const tx = aTransaccionKarma(aval, 25);
		expect(tx.id).toBe(aval.id);
		expect(tx.emisor).toBe(aval.avalador);
		expect(tx.timestamp).toBe(aval.emitidoEn);
		expect(tx.firma).toBe(aval.firma);
		// The node earning standing is the endorsed one.
		expect(tx.sujeto).toBe(aval.avalado);
		expect(tx.delta).toBe(25);
		expect(tx.razon).toContain("licencia_verificada");
		expect(tx.razon).toContain("registro_por_pais");
	});

	it("leaves the delta as policy, never picking one silently", async () => {
		const aval = await avalFirmado();
		expect(aTransaccionKarma(aval, 1).delta).toBe(1);
		expect(aTransaccionKarma(aval, 10).delta).toBe(10);
	});
});

describe("Aval — binds to exact credential bytes", () => {
	it("changes hash when the credential is edited, invalidating prior endorsements", async () => {
		const emisor = await createPostQuantumIdentity("emisor-cred" as NodoId);
		const { crearCredencial } = await import("../../src/medico/index.js");
		const credencial = await crearCredencial(
			{
				tipo: TIPO_CREDENCIAL.LICENCIA,
				pais: "CO",
				autoridad: "minsalud-rethus",
				idLicencia: "a".repeat(64),
				emitidoEn: AHORA - DIA,
				vigenteHasta: AHORA + 365 * DIA,
				estadoEmision: ESTADO_EMISION.ATESTIGUADA_PARES,
				emisor: AVALADO,
			},
			emisor,
		);

		const h1 = await prepararCredencialParaAval(credencial);
		expect(h1).toBe(await hashCredencial(credencial));
		// Even a non-semantic-looking field change breaks the binding.
		expect(
			await hashCredencial({ ...credencial, autoridad: "otro-colegio" }),
		).not.toBe(h1);
	});
});
