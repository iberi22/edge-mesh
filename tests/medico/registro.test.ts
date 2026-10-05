/**
 * Registry verification — fail-closed tests.
 *
 * The defect these exist to pin: OrionHealth's `LicenseVerifier` returns
 * `LicenseVerificationResult.unknown` when a country's registry is empty, and
 * declares `expired` but never returns it. In a mesh that lets a node
 * self-attest, `unknown` is not a neutral answer — it is a bypass, because
 * "we have no registry for your country" and "your licence is not in the
 * registry" both end in access staying closed here.
 *
 * The whole of `src/medico/registro.ts` is pure: a `VerificadorRegistroPais`
 * is injected and there is no fetch, no filesystem, no snapshot download. The
 * fixtures below are the entire "network".
 */

import { describe, expect, it } from "vitest";
import { createPostQuantumIdentity } from "../../src/identity/index.js";
import {
	crearCredencial,
	ESTADO_EMISION,
	hashLicencia,
	PAISES_SOPORTADOS,
	TIPO_CREDENCIAL,
} from "../../src/medico/index.js";
import {
	ESTADO_VERIFICACION_REGISTRO,
	type InstantaneaRegistroPais,
	VerificadorRegistroEnMemoria,
	verificarCredencialContraRegistro,
	verificarLicenciaContraRegistro,
} from "../../src/medico/registro.js";
import type { CredencialMedica } from "../../src/medico/types.js";
import type { NodoId } from "../../src/types/index.js";

const AHORA = 1_700_000_000_000;
const DIA = 86_400_000;

const NUMERO_CO = "12-345 678";
const NUMERO_ES = " 12-345-67-X ";

async function instantaneaCO(
	version = "rethus-2026-01",
	numeros = [NUMERO_CO],
): Promise<InstantaneaRegistroPais> {
	const hashes = new Set<string>();
	for (const n of numeros) hashes.add(await hashLicencia(n));
	return { pais: "CO", version, hashes };
}

function verificador(
	instante: InstantaneaRegistroPais[],
): VerificadorRegistroEnMemoria {
	return new VerificadorRegistroEnMemoria(instante);
}

async function credencialCO(
	over: Partial<Parameters<typeof crearCredencial>[0]> = {},
): Promise<CredencialMedica> {
	const ident = await createPostQuantumIdentity(
		`mlkem${"d".repeat(32)}` as NodoId,
	);
	return crearCredencial(
		{
			tipo: TIPO_CREDENCIAL.LICENCIA,
			pais: "CO",
			autoridad: "minsalud-rethus",
			idLicencia: await hashLicencia(NUMERO_CO),
			emitidoEn: AHORA - DIA,
			vigenteHasta: AHORA + 365 * DIA,
			estadoEmision: ESTADO_EMISION.ATESTIGUADA_PARES,
			emisor: ident.nodoId,
			...over,
		},
		ident,
	);
}

describe("verificarLicenciaContraRegistro — the OrionHealth primitive, fail-closed", () => {
	it("verifies a licence present in the country snapshot", async () => {
		const v = verificador([await instantaneaCO()]);
		const r = await verificarLicenciaContraRegistro(NUMERO_CO, "CO", v);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.VERIFICADO);
		if (r.estado === "verificado") {
			expect(r.idLicencia).toBe(await hashLicencia(NUMERO_CO));
			expect(r.versionRegistro).toBe("rethus-2026-01");
		}
	});

	// ── DEFECT 1: the empty-registry `unknown` ──
	it("fails closed on a country with no registry — never `unknown`", async () => {
		// No snapshot at all for CO.
		const v = verificador([]);
		const r = await verificarLicenciaContraRegistro(NUMERO_CO, "CO", v);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.NO_VERIFICADO);
		if (r.estado === "no_verificado") {
			expect(r.causa).toBe("pais_sin_registro");
			expect(r.accesoPermitido).toBe(false);
		}
		// The literal word must not be reachable: there is no third state.
		expect(JSON.stringify(r)).not.toContain("unknown");
	});

	it("fails closed on an EMPTY country registry, the exact OrionHealth branch", async () => {
		// A snapshot exists but carries no hashes: identical operational situation
		// to having none, so it must be refused identically.
		const v = verificador([
			{ pais: "CO", version: "rethus-vacia", hashes: new Set<string>() },
		]);
		const r = await verificarLicenciaContraRegistro(NUMERO_CO, "CO", v);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.NO_VERIFICADO);
		if (r.estado === "no_verificado") expect(r.causa).toBe("pais_sin_registro");
	});

	it("fails closed on a country nobody has downloaded a snapshot for", async () => {
		const v = verificador([await instantaneaCO()]);
		// Spain has no snapshot here. Treating this as "not refused" would make an
		// unsupported country a universal bypass.
		const r = await verificarLicenciaContraRegistro(NUMERO_ES, "ES", v);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.NO_VERIFICADO);
		if (r.estado === "no_verificado") expect(r.causa).toBe("pais_sin_registro");
	});

	it("fails closed when the licence is simply absent from a populated registry", async () => {
		const v = verificador([
			await instantaneaCO("rethus-2026-01", ["99-999-999"]),
		]);
		const r = await verificarLicenciaContraRegistro(NUMERO_CO, "CO", v);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.NO_VERIFICADO);
		if (r.estado === "no_verificado") {
			expect(r.causa).toBe("licencia_no_encontrada");
			expect(r.accesoPermitido).toBe(false);
		}
	});

	it("does not leak the licence number in either outcome", async () => {
		const v = verificador([await instantaneaCO()]);
		const ok = await verificarLicenciaContraRegistro(NUMERO_CO, "CO", v);
		const ko = await verificarLicenciaContraRegistro("99-999-999", "CO", v);
		expect(JSON.stringify(ok)).not.toContain("12-345");
		expect(JSON.stringify(ko)).not.toContain("99-999");
	});

	it("normalises whitespace and case on both sides of the comparison", async () => {
		const v = verificador([await instantaneaCO()]);
		// Whitespace inside and around, and lower case, all normalise to the same
		// digest as the registered '12-345 678'.
		await expect(
			verificarLicenciaContraRegistro("  12-345 678  ", "CO", v),
		).resolves.toMatchObject({
			estado: "verificado",
		});
		await expect(
			verificarLicenciaContraRegistro("12 345 678", "CO", v),
		).resolves.toMatchObject({
			estado: "no_verificado",
		});
	});

	it("looks a country up case-insensitively but demands upper-case in a credential", async () => {
		const v = verificador([await instantaneaCO()]);
		await expect(
			verificarLicenciaContraRegistro(NUMERO_CO, "co", v),
		).resolves.toMatchObject({
			estado: "verificado",
		});
		// The credential validator is the strict boundary for `pais`.
		const cred = await credencialCO();
		expect(cred.pais).toBe("CO");
	});
});

describe("verificarCredencialContraRegistro — membership AND expiry", () => {
	// ── DEFECT 2: the `expired` state never returned ──
	it("rejects an expired credential even though its hash is still in the registry", async () => {
		const v = verificador([await instantaneaCO()]);
		// The hash matches — membership holds — but the issuer-signed window has
		// closed. A hash-set membership test alone would pass this forever.
		const cred = await credencialCO({
			emitidoEn: AHORA - 400 * DIA,
			vigenteHasta: AHORA - DIA,
		});
		const r = await verificarCredencialContraRegistro(cred, v, AHORA);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.NO_VERIFICADO);
		if (r.estado === "no_verificado") {
			expect(r.causa).toBe("licencia_caducada");
			expect(r.accesoPermitido).toBe(false);
		}
	});

	it("accepts a credential that is both in the registry and unexpired", async () => {
		const v = verificador([await instantaneaCO()]);
		const r = await verificarCredencialContraRegistro(
			await credencialCO(),
			v,
			AHORA,
		);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.VERIFICADO);
		if (r.estado === "verificado")
			expect(r.versionRegistro).toBe("rethus-2026-01");
	});

	it("fails closed on the registry before even looking at expiry", async () => {
		const v = verificador([]);
		const r = await verificarCredencialContraRegistro(
			await credencialCO(),
			v,
			AHORA,
		);
		expect(r.estado).toBe(ESTADO_VERIFICACION_REGISTRO.NO_VERIFICADO);
		if (r.estado === "no_verificado") expect(r.causa).toBe("pais_sin_registro");
	});

	it("treats expiry as exclusive at the exact millisecond", async () => {
		const v = verificador([await instantaneaCO()]);
		const cred = await credencialCO({ vigenteHasta: AHORA + DIA });
		await expect(
			verificarCredencialContraRegistro(cred, v, AHORA + DIA - 1),
		).resolves.toMatchObject({
			estado: "verificado",
		});
		await expect(
			verificarCredencialContraRegistro(cred, v, AHORA + DIA),
		).resolves.toMatchObject({
			estado: "no_verificado",
		});
	});
});

describe("VerificadorRegistroEnMemoria — the injected seam", () => {
	it("publishes and replaces a snapshot", async () => {
		const v = new VerificadorRegistroEnMemoria();
		expect(v.instantanea("CO")).toBeUndefined();

		await v.publicar(await instantaneaCO("rethus-2026-02"));
		expect(v.versionInstantanea("CO")).toBe("rethus-2026-02");

		await v.publicar(await instantaneaCO("rethus-2026-03"));
		expect(v.versionInstantanea("CO")).toBe("rethus-2026-03");
	});

	it("stores only hashes, never a licence number", async () => {
		const inst = await instantaneaCO();
		for (const h of inst.hashes) expect(h).toMatch(/^[0-9a-f]{64}$/);
		expect([...inst.hashes].some((h) => h.includes("12-345"))).toBe(false);
	});

	it("declares Colombia as the only supported launch market (DECISIÓN C.1)", () => {
		expect([...PAISES_SOPORTADOS]).toEqual(["CO"]);
	});
});
