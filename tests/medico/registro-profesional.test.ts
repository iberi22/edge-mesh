/**
 * `RegistroProfesional` — the aggregate record.
 *
 * Two properties matter more than the field list:
 *
 * 1. The shape has no field capable of holding patient data. Not "we won't
 *    populate it" — the type does not admit it. Health data is a special
 *    category under GDPR Art. 9 and sensitive under Ley 1581/2012 Art. 5, whose
 *    household exemption of Art. 2(a) is lost the moment a peer holds a copy.
 * 2. A record that validates but is not a *certified doctor* is a legitimate
 *    node with a smaller capability set, not a failure. A physician with a valid
 *    licence and no specialty is a real doctor (DECISIÓN A.4).
 */

import { describe, expect, it } from "vitest";
import { createPostQuantumIdentity } from "../../src/identity/index.js";
import {
	type BorradorAval,
	type CredencialMedica,
	crearAval,
	crearCredencial,
	ESTADO_EMISION,
	MOTIVO_RECHAZO_REGISTRO,
	OBJETO_AVAL,
	type RegistroProfesional,
	recalcularAvalRecibido,
	resumirAvales,
	TIPO_CREDENCIAL,
	validarRegistroProfesional,
} from "../../src/medico/index.js";
import type { NodoId } from "../../src/types/index.js";

const AHORA = 1_700_000_000_000;
const DIA = 86_400_000;

const SUJETO = `mlkem${"1".repeat(32)}` as NodoId;
const AVALADOR = `mlkem${"2".repeat(32)}` as NodoId;
const PEER2 = `mlkem${"3".repeat(32)}` as NodoId;

async function cred(
	over: Partial<Parameters<typeof crearCredencial>[0]> = {},
	hash = "a".repeat(64),
): Promise<CredencialMedica> {
	const ident = await createPostQuantumIdentity(SUJETO);
	return crearCredencial(
		{
			tipo: TIPO_CREDENCIAL.LICENCIA,
			pais: "CO",
			autoridad: "minsalud-rethus",
			idLicencia: hash,
			emitidoEn: AHORA - DIA,
			vigenteHasta: AHORA + 365 * DIA,
			estadoEmision: ESTADO_EMISION.ATESTIGUADA_PARES,
			emisor: SUJETO,
			...over,
		},
		ident,
	);
}

async function registro(
	over: Partial<RegistroProfesional> = {},
): Promise<RegistroProfesional> {
	const licencia = await cred();
	const especialidad = await cred(
		{ tipo: TIPO_CREDENCIAL.ESPECIALIDAD, especialidad: "cardiologia" },
		"b".repeat(64),
	);
	return {
		version: 1,
		nodoId: SUJETO,
		credenciales: [licencia, especialidad],
		especialidades: ["cardiologia"],
		avalRecibido: resumirAvales([], AHORA),
		declaracion: { jurisdiccion: "CO" },
		...over,
	};
}

async function avalDe(
	avalador: NodoId,
	nonce: string,
	objetoAval = OBJETO_AVAL.LICENCIA_VERIFICADA,
): Promise<BorradorAval> {
	return {
		avalador,
		avalado: SUJETO,
		objetoAval,
		credencialRef: "cred-1",
		hashCredencial: "c".repeat(64),
		metodoVerificacion: { clase: "testimonio_directo" },
		evidenciaHash: "d".repeat(64),
		alcance: "anual",
		emitidoEn: AHORA - DIA,
		vigenteHasta: AHORA + 364 * DIA,
		nonce,
	};
}

describe("RegistroProfesional — validation", () => {
	it("accepts a well-formed record and reports certified-doctor status", async () => {
		const r = validarRegistroProfesional(await registro(), AHORA);
		expect(r.ok).toBe(true);
		if (r.ok) expect(r.esCertificado).toBe(true);
	});

	it("accepts a licence-only record as valid but NOT certified", async () => {
		const lic = await cred();
		const r = validarRegistroProfesional(
			await registro({ credenciales: [lic], especialidades: [] }),
			AHORA,
		);
		expect(r.ok).toBe(true);
		if (r.ok) {
			// A licensed doctor without a specialty is legitimate, just lower tier.
			expect(r.esCertificado).toBe(false);
		}
	});

	it("rejects a record containing one lapsed credential, naming the cause", async () => {
		const lic = await cred();
		const caducada = await cred(
			{
				tipo: TIPO_CREDENCIAL.ESPECIALIDAD,
				especialidad: "cardiologia",
				emitidoEn: AHORA - 400 * DIA,
				vigenteHasta: AHORA - DIA,
			},
			"b".repeat(64),
		);
		const r = validarRegistroProfesional(
			await registro({ credenciales: [lic, caducada] }),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) {
			expect(r.motivo).toBe(MOTIVO_RECHAZO_REGISTRO.CREDENCIAL_INVALIDA);
			expect(r.accesoPermitido).toBe(false);
			// The credential's own reason is preserved so an operator knows which field.
			expect(r.detalle).toContain("credencial_caducada");
		}
	});

	it("refuses to let especialidades over-claim what the credentials prove", async () => {
		// Lists 'radiologia' with no specialty credential behind it: an
		// unauthenticated claim about a person's qualifications.
		const r = validarRegistroProfesional(
			await registro({ especialidades: ["cardiologia", "radiologia"] }),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) {
			expect(r.motivo).toBe(
				MOTIVO_RECHAZO_REGISTRO.ESPECIALIDAD_SIN_CREDENCIAL,
			);
			expect(r.detalle).toContain("radiologia");
		}
	});

	it("rejects a specialty credential with no specialty name", async () => {
		const sinNombre = await cred(
			{ tipo: TIPO_CREDENCIAL.ESPECIALIDAD },
			"b".repeat(64),
		);
		const r = validarRegistroProfesional(
			await registro({ credenciales: [sinNombre], especialidades: [] }),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok)
			expect(r.motivo).toBe(MOTIVO_RECHAZO_REGISTRO.ESPECIALIDAD_SIN_NOMBRE);
	});

	it("rejects duplicate credential ids", async () => {
		const lic = await cred();
		const r = validarRegistroProfesional(
			await registro({ credenciales: [lic, lic], especialidades: [] }),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok)
			expect(r.motivo).toBe(MOTIVO_RECHAZO_REGISTRO.CREDENCIAL_DUPLICADA);
	});

	it("rejects a bad jurisdiction and an unsupported version", async () => {
		const juris = validarRegistroProfesional(
			await registro({ declaracion: { jurisdiccion: "Colombia" } }),
			AHORA,
		);
		expect(juris.ok).toBe(false);
		if (!juris.ok)
			expect(juris.motivo).toBe(MOTIVO_RECHAZO_REGISTRO.JURISDICCION_INVALIDA);

		const version = validarRegistroProfesional(
			await registro({ version: 2 as unknown as 1 }),
			AHORA,
		);
		expect(version.ok).toBe(false);
		if (!version.ok)
			expect(version.motivo).toBe(MOTIVO_RECHAZO_REGISTRO.ESTRUCTURA_INVALIDA);
	});
});

describe("RegistroProfesional — the summary is a cache, never the truth", () => {
	it("recomputes from live avals, so a withdrawal lowers the count", async () => {
		const ident = await createPostQuantumIdentity(AVALADOR);
		const b = await avalDe(AVALADOR, "n1");
		const aval = await crearAval(b, ident, { hash: b.hashCredencial });
		expect(resumirAvales([aval], AHORA).verificacionesLicencia).toBe(1);

		// The author withdraws it: the aval simply stops being passed to the fold.
		const trasRetirada = recalcularAvalRecibido(await registro(), [], AHORA);
		expect(trasRetirada.avalRecibido.verificacionesLicencia).toBe(0);
	});

	it("does not let a clinical interaction raise the licence count", async () => {
		const ident1 = await createPostQuantumIdentity(AVALADOR);
		const ident2 = await createPostQuantumIdentity(PEER2);
		const b1 = await avalDe(AVALADOR, "c1", OBJETO_AVAL.INTERACCION_CLINICA);
		const b2 = await avalDe(PEER2, "c2", OBJETO_AVAL.INTERACCION_CLINICA);
		const avales = [
			await crearAval(b1, ident1, { hash: b1.hashCredencial }),
			await crearAval(b2, ident2, { hash: b2.hashCredencial }),
		];

		const resumen = resumirAvales(avales, AHORA);
		expect(resumen.total).toBe(2);
		expect(resumen.avaladoresUnicos).toBe(2);
		// Two peers vouching for encounters; nothing proven about licensure.
		expect(resumen.verificacionesLicencia).toBe(0);
	});

	it("excludes self-endorsement from the fold entirely", async () => {
		const ident = await createPostQuantumIdentity(SUJETO);
		const b = await avalDe(SUJETO, "self");
		const aval = await crearAval(b, ident, { hash: b.hashCredencial });
		expect(resumirAvales([aval], AHORA).total).toBe(0);
	});
});

describe("RegistroProfesional — no patient data can be expressed", () => {
	it("has exactly the documented top-level fields", async () => {
		const r = await registro();
		expect(Object.keys(r).sort()).toEqual([
			"avalRecibido",
			"credenciales",
			"declaracion",
			"especialidades",
			"nodoId",
			"version",
		]);
		expect(Object.keys(r.declaracion).sort()).toEqual(["jurisdiccion"]);
	});

	it("keeps directory PII out of the shape by default", async () => {
		const r = await registro();
		// Name and contact are opt-in (DECISIÓN A.5, Lex Artis), and sealed.
		expect(r.declaracion.nombreMostrado).toBeUndefined();
		expect(r.declaracion.contactoCifrado).toBeUndefined();
	});
});
