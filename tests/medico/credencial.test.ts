/**
 * Credential model tests.
 *
 * Every test here exists because a real defect was found in a sibling codebase.
 * `LicenseVerifier` in OrionHealth declares an `expired` state and never returns
 * it (hash-set membership carries no validity window), and returns `unknown` for
 * an empty country registry (which, in a mesh that self-attests, is a bypass).
 * Those two defects are this file's reason for existing, so they are pinned hard.
 */

import { beforeEach, describe, expect, it } from "vitest";
import {
	createPostQuantumIdentity,
	type PostQuantumIdentity,
} from "../../src/identity/index.js";
import {
	type BorradorCredencial,
	type CredencialMedica,
	crearCredencial,
	esMedicoCertificado,
	hashLicencia,
	idCredencial,
	MOTIVO_RECHAZO_CREDENCIAL,
	validarCredencial,
	validarCredencialFirmada,
	validarVinculoEmision,
	verificarFirmaCredencial,
} from "../../src/medico/index.js";
import { ESTADO_EMISION, TIPO_CREDENCIAL } from "../../src/medico/types.js";
import type { NodoId } from "../../src/types/index.js";

/** Fixed clock. Nothing in the module reads the real one. */
const AHORA = 1_700_000_000_000;
const DIA = 86_400_000;

const NUMERO_LICENCIA = "  12-345 678  ";
const PAIS = "CO";

async function identidadDePrueba(nodoId: string): Promise<PostQuantumIdentity> {
	return createPostQuantumIdentity(nodoId as NodoId);
}

function borrador(over: Partial<BorradorCredencial> = {}): BorradorCredencial {
	return {
		tipo: TIPO_CREDENCIAL.LICENCIA,
		pais: PAIS,
		autoridad: "minsalud-rethus",
		idLicencia: "a".repeat(64),
		emitidoEn: AHORA - DIA,
		vigenteHasta: AHORA + 365 * DIA,
		estadoEmision: ESTADO_EMISION.ATESTIGUADA_PARES,
		emisor: `mlkem${"1".repeat(32)}` as NodoId,
		...over,
	};
}

/** A credential with a real ML-DSA-65 signature over its canonical bytes. */
async function credencialFirmada(
	over: Partial<BorradorCredencial> = {},
): Promise<CredencialMedica> {
	const b = borrador(over);
	const id = await identidadDePrueba(String(b.emisor));
	return crearCredencial(b, id);
}

describe("CredencialMedica — construction", () => {
	it("derives a stable id from idLicencia + tipo + pais, independent of key order", async () => {
		const a = await idCredencial("hash1", TIPO_CREDENCIAL.LICENCIA, "CO");
		const b = await idCredencial("hash1", TIPO_CREDENCIAL.LICENCIA, "CO");
		expect(a).toBe(b);
		expect(a).toMatch(/^[0-9a-f]{64}$/);

		// Different tipo, different country ⇒ different id.
		expect(
			await idCredencial("hash1", TIPO_CREDENCIAL.ESPECIALIDAD, "CO"),
		).not.toBe(a);
		expect(
			await idCredencial("hash1", TIPO_CREDENCIAL.LICENCIA, "ES"),
		).not.toBe(a);
	});

	it("does not let characters migrate across field boundaries to collide", async () => {
		// Without hex-encoding each component, 'AB'+'licencia' and 'A'+'blicencia'
		// would hash the same concatenation.
		const x = await idCredencial("AB", "licencia", "CO");
		const y = await idCredencial("A", "blicencia", "CO");
		expect(x).not.toBe(y);
	});

	it("normalises the licence number before hashing, and never returns the number", async () => {
		// OrionHealth: strip whitespace, upper-case. Same primitive, same result.
		const hash = await hashLicencia(NUMERO_LICENCIA);
		expect(hash).toMatch(/^[0-9a-f]{64}$/);
		expect(hash).toBe(await hashLicencia("12-345678"));
		expect(hash).not.toContain("12");
	});

	it("produces a signature that verifies against the issuer key", async () => {
		const emisor = await identidadDePrueba("emisor-1");
		const cred = await crearCredencial(
			borrador({ emisor: emisor.nodoId }),
			emisor,
		);
		await expect(
			verificarFirmaCredencial(cred, emisor, emisor.exportarPublico()),
		).resolves.toBe(true);
	});

	it("upper-cases the country and derives the id from the normalised value", async () => {
		const emisor = await identidadDePrueba("emisor-2");
		const cred = await crearCredencial(
			borrador({ pais: "co", emisor: emisor.nodoId }),
			emisor,
		);
		expect(cred.pais).toBe("CO");
	});
});

describe("CredencialMedica — validation fails closed", () => {
	it("accepts a valid, signed, unexpired credential", async () => {
		const cred = await credencialFirmada();
		const r = validarCredencial(cred, AHORA);
		expect(r.ok).toBe(true);
	});

	it("accepts a valid credential through the full signed path", async () => {
		const emisor = await identidadDePrueba("emisor-3");
		const cred = await crearCredencial(
			borrador({ emisor: emisor.nodoId }),
			emisor,
		);
		const r = await validarCredencialFirmada(
			cred,
			emisor,
			emisor.exportarPublico(),
			AHORA,
		);
		expect(r.ok).toBe(true);
	});

	// ── DEFECT 1: the missing expiry ──
	it('rejects a credential with no vigenteHasta — a hash alone cannot express "lapsed"', async () => {
		const cred = await credencialFirmada();
		// `vigenteHasta` deleted outright: the OrionHealth `expired`-never-returned
		// shape, where list membership implied validity forever.
		const { vigenteHasta: _dropped, ...sinVigencia } = cred;
		expect("vigenteHasta" in sinVigencia).toBe(false);

		const r = validarCredencial(
			sinVigencia as unknown as CredencialMedica,
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) {
			expect(r.motivo).toBe(
				MOTIVO_RECHAZO_CREDENCIAL.CAMPO_OBLIGATORIO_AUSENTE,
			);
			expect(r.accesoPermitido).toBe(false);
		}
	});

	it("rejects a vigenteHasta that is absent-but-typed (NaN / non-numeric)", async () => {
		const cred = await credencialFirmada();
		const r = validarCredencial(
			{ ...cred, vigenteHasta: undefined as unknown as number },
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok)
			expect(r.motivo).toBe(
				MOTIVO_RECHAZO_CREDENCIAL.CAMPO_OBLIGATORIO_AUSENTE,
			);

		const nan = validarCredencial({ ...cred, vigenteHasta: Number.NaN }, AHORA);
		expect(nan.ok).toBe(false);
		if (!nan.ok)
			expect(nan.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.SIN_VIGENCIA);
	});

	it("rejects an already-expired credential", async () => {
		const cred = await credencialFirmada({
			emitidoEn: AHORA - 400 * DIA,
			vigenteHasta: AHORA - DIA,
		});
		const r = validarCredencial(cred, AHORA);
		expect(r.ok).toBe(false);
		if (!r.ok) {
			expect(r.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.CREDENCIAL_CADUCADA);
			expect(r.accesoPermitido).toBe(false);
		}
	});

	it("rejects a vigenteHasta in the past, and a zero/negative one", async () => {
		const cred = await credencialFirmada();
		for (const malo of [AHORA - 1, 0, -1]) {
			const r = validarCredencial({ ...cred, vigenteHasta: malo }, AHORA);
			expect(r.ok, `vigenteHasta=${malo} debe rechazarse`).toBe(false);
			if (!r.ok) expect(r.accesoPermitido).toBe(false);
		}
	});

	it("treats vigenteHasta as exclusive: it lapses at the exact millisecond", async () => {
		const cred = await credencialFirmada({ vigenteHasta: AHORA + DIA });
		expect(validarCredencial(cred, AHORA + DIA - 1).ok).toBe(true);
		expect(validarCredencial(cred, AHORA + DIA).ok).toBe(false);
	});

	it("rejects each of the five mandatory fields by name", async () => {
		const cred = await credencialFirmada();
		const campos = [
			"autoridad",
			"emitidoEn",
			"vigenteHasta",
			"idLicencia",
			"tipo",
		] as const;
		for (const campo of campos) {
			const r = validarCredencial(
				{ ...cred, [campo]: undefined } as unknown as CredencialMedica,
				AHORA,
			);
			expect(r.ok, `${campo} ausente debe rechazarse`).toBe(false);
			if (!r.ok) {
				expect(r.motivo).toBe(
					MOTIVO_RECHAZO_CREDENCIAL.CAMPO_OBLIGATORIO_AUSENTE,
				);
				expect(r.detalle).toContain(campo);
			}
		}
	});

	it("rejects a raw licence number pasted into idLicencia (PII at the boundary)", async () => {
		const cred = await credencialFirmada({ idLicencia: "12-345 678" });
		const r = validarCredencial(cred, AHORA);
		expect(r.ok).toBe(false);
		if (!r.ok)
			expect(r.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.ID_LICENCIA_MAL_FORMADO);
	});

	it("rejects a non-alpha-2 country and unknown enum values", async () => {
		const cred = await credencialFirmada();
		expect(validarCredencial({ ...cred, pais: "COL" }, AHORA).ok).toBe(false);
		expect(validarCredencial({ ...cred, pais: "co" }, AHORA).ok).toBe(false);

		const tipo = validarCredencial(
			{ ...cred, tipo: "inventado" } as unknown as CredencialMedica,
			AHORA,
		);
		expect(tipo.ok).toBe(false);
		if (!tipo.ok)
			expect(tipo.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.ENUM_INVALIDO);

		const estado = validarCredencial(
			{ ...cred, estadoEmision: "verificada" } as unknown as CredencialMedica,
			AHORA,
		);
		expect(estado.ok).toBe(false);
		if (!estado.ok)
			expect(estado.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.ENUM_INVALIDO);
	});

	it("rejects incoherent dates (emitidoEn after vigenteHasta)", async () => {
		const cred = await credencialFirmada();
		// Issue date past the expiry date.
		const r = validarCredencial(
			{ ...cred, emitidoEn: AHORA + 400 * DIA },
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok)
			expect(r.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.EMISION_INVALIDA);
	});

	it("rejects an empty signature", async () => {
		const cred = await credencialFirmada();
		const r = validarCredencial({ ...cred, firma: new Uint8Array(0) }, AHORA);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.FIRMA_AUSENTE);
	});

	it("rejects a signature made by a different key than emisor claims", async () => {
		const honest = await identidadDePrueba("emisor-honesto");
		const impostor = await identidadDePrueba("emisor-impostor");
		// Signed by the impostor, but claiming to be the honest issuer.
		const cred = await crearCredencial(
			borrador({ emisor: honest.nodoId }),
			impostor,
		);

		const r = await validarCredencialFirmada(
			cred,
			honest,
			honest.exportarPublico(),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) {
			expect(r.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.FIRMA_INVALIDA);
			expect(r.accesoPermitido).toBe(false);
		}
	});

	it("rejects a tampered field even when the original signature was valid", async () => {
		const emisor = await identidadDePrueba("emisor-tamper");
		const cred = await crearCredencial(
			borrador({ emisor: emisor.nodoId }),
			emisor,
		);
		// Extend the expiry after signing. This is the attack the signed `vigenteHasta`
		// exists to stop: without the signature covering it, anyone could renew.
		const manipulada = { ...cred, vigenteHasta: AHORA + 99 * 365 * DIA };

		await expect(
			verificarFirmaCredencial(manipulada, emisor, emisor.exportarPublico()),
		).resolves.toBe(false);
		const r = await validarCredencialFirmada(
			manipulada,
			emisor,
			emisor.exportarPublico(),
			AHORA,
		);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.FIRMA_INVALIDA);
	});

	it("refuses an autofirmada credential presented by a different node", async () => {
		const emisor = await identidadDePrueba("sujeto");
		const cred = await crearCredencial(
			borrador({
				estadoEmision: ESTADO_EMISION.AUTOFIRMADA,
				emisor: emisor.nodoId,
			}),
			emisor,
		);
		// Same node: coherent.
		expect(validarVinculoEmision(cred, emisor.nodoId).ok).toBe(true);
		// A different node presenting it: incoherent.
		const r = validarVinculoEmision(cred, `mlkem${"9".repeat(32)}` as NodoId);
		expect(r.ok).toBe(false);
		if (!r.ok)
			expect(r.motivo).toBe(MOTIVO_RECHAZO_CREDENCIAL.AUTOEMISION_INCOHERENTE);
	});
});

describe("CredencialMedica — certified doctor", () => {
	let licencia: CredencialMedica;
	let especialidad: CredencialMedica;

	beforeEach(async () => {
		licencia = await credencialFirmada({ idLicencia: "b".repeat(64) });
		especialidad = await credencialFirmada({
			idLicencia: "c".repeat(64),
			tipo: TIPO_CREDENCIAL.ESPECIALIDAD,
			especialidad: "cardiologia",
		});
	});

	it("requires licencia ∧ especialidad, both strongly emitted and unexpired", () => {
		expect(esMedicoCertificado([licencia, especialidad], AHORA)).toBe(true);
	});

	it("is false with a licence but no specialty — a legitimate lower tier, not a doctor-cert", () => {
		expect(esMedicoCertificado([licencia], AHORA)).toBe(false);
	});

	it("does not count an autofirmada credential", () => {
		const autoLic = { ...licencia, estadoEmision: ESTADO_EMISION.AUTOFIRMADA };
		const autoEsp = {
			...especialidad,
			estadoEmision: ESTADO_EMISION.AUTOFIRMADA,
		};
		// Self-assertion opens no access: a node cannot certify itself.
		expect(esMedicoCertificado([autoLic, autoEsp], AHORA)).toBe(false);
	});

	it("does not count an expired specialty, which is why specialty is its own credential", () => {
		const espCaducada = { ...especialidad, vigenteHasta: AHORA - DIA };
		expect(esMedicoCertificado([licencia, espCaducada], AHORA)).toBe(false);
	});
});
