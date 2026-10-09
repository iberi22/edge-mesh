import { describe, expect, it } from "vitest";
import type { PostQuantumIdentity } from "../../src/identity/index.js";
import { crearIdentidadVinculada } from "../../src/identity/index.js";
import type {
	PayloadCifrado,
	SesionCifrada,
} from "../../src/protocol/index.js";
import {
	abrirPayload,
	aceptarSesionCifrada,
	BYTES_CIPHERTEXT_KEM_768,
	cifrarPayload,
	cifrarYSiguiente,
	createEnvelope,
	DIRECCION,
	derivarClavesSesion,
	derivarNonce,
	ErrorPayloadCifrado,
	ErrorReplayDetectado,
	ErrorReusoDeNonce,
	esEnvolventeCifrado,
	GuardiaReplay,
	iniciarSesionCifrada,
	medirOverhead,
	rotarSesion,
	signEnvelope,
	verifyEnvelopeSignature,
} from "../../src/protocol/index.js";
import type { Envolvente, NodoId } from "../../src/types/index.js";

/** A representative clinical record: the shape this layer exists for. */
const REG = {
	paciente: "PAC-8891",
	diagnostico: "Hipertension arterial esencial",
	presion: "148/94 mmHg",
	farmaco: "amlodipino 5mg",
} as const;

async function dosNodos(): Promise<{
	a: PostQuantumIdentity;
	b: PostQuantumIdentity;
}> {
	return {
		a: await crearIdentidadVinculada(),
		b: await crearIdentidadVinculada(),
	};
}

/** Byte-array equality without depending on Node's Buffer types. */
function iguales(x: Uint8Array, y: Uint8Array): boolean {
	if (x.length !== y.length) return false;
	return x.every((byte, i) => byte === y[i]);
}

/** Flip one bit at `indice` of a base64 string, keeping its length. */
function voltearBit(base64: string, indice: number): string {
	const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
	bytes[indice] ^= 0x01;
	let binario = "";
	for (const b of bytes) binario += String.fromCharCode(b);
	return btoa(binario);
}

describe("protocolo/cifrado — confidencialidad", () => {
	it("roundtrip: el receptor recupera el registro exacto", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);

		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		expect(esEnvolventeCifrado(env)).toBe(true);
		expect(abrirPayload(env, sesB, new GuardiaReplay()).payload).toEqual(REG);
	});

	it("el ciphertext no filtra ni un substring del registro", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA } = iniciarSesionCifrada(a, b.exportarKemPublico());

		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);
		const enElCable = JSON.stringify(env.payload);

		for (const secreto of Object.values(REG)) {
			expect(enElCable).not.toContain(secreto);
		}
	});

	it("limitación honesta: la cabecera del sobre NO va cifrada", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);

		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		// Quién, cuándo y de qué tipo siguen visibles por diseño: la firma ML-DSA
		// cubre esos campos, así que no se pueden ocultar sin romper la firma. Este
		// test existe para que esa limitación no la "arregle" alguien que la toma
		// por un bug.
		const enElCable = JSON.stringify(env);
		expect(enElCable).toContain(a.nodoId);
		expect(enElCable).toContain(b.nodoId);
		expect(enElCable).toContain('"timestamp"');
		expect(enElCable).not.toContain("Hipertension");
		expect(abrirPayload(env, sesB, new GuardiaReplay()).payload).toEqual(REG);
	});

	it("un tercero sin la clave de sesión no puede abrir el payload", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA } = iniciarSesionCifrada(a, b.exportarKemPublico());
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		// Sesión propia del atacante, con claves propias.
		const sesAtacante: SesionCifrada = {
			sesionId: "intrusa-00000000",
			epoch: 0,
			claves: {
				claveCifrado: new Uint8Array(32).fill(9),
				claveAutenticacion: new Uint8Array(32).fill(9),
			},
			direccion: DIRECCION.B_A_A,
			siguienteCounter: 0n,
		};

		expect(() => abrirPayload(env, sesAtacante, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("la firma sigue verificando sobre el sobre cifrado", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA } = iniciarSesionCifrada(a, b.exportarKemPublico());
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);
		const firmado = await signEnvelope(env, a);

		expect(await verifyEnvelopeSignature(firmado, a.exportarPublico(), b)).toBe(
			true,
		);
	});

	it("la firma de un sobre en claro sigue verificando tras este cambio", async () => {
		const { a, b } = await dosNodos();
		const env = await signEnvelope(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			a,
		);

		// Regresión sobre canonicalEnvelopeBytes: no debe haber cambiado un byte.
		expect(await verifyEnvelopeSignature(env, a.exportarPublico(), b)).toBe(
			true,
		);
	});

	it("un payload sin sellar se rechaza con error claro", async () => {
		const { a, b } = await dosNodos();
		const { handshake } = iniciarSesionCifrada(a, b.exportarKemPublico());
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);

		expect(() =>
			abrirPayload(
				createEnvelope("sync", b.nodoId, a.nodoId, REG),
				sesB,
				new GuardiaReplay(),
			),
		).toThrow(ErrorPayloadCifrado);
	});

	it("no se puede cifrar dos veces el mismo sobre", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA } = iniciarSesionCifrada(a, b.exportarKemPublico());
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		expect(() => cifrarPayload(env, sesA)).toThrow(/already sealed/);
	});
});

describe("protocolo/cifrado — autenticación Poly1305", () => {
	it("un bit volteado en el ciphertext falla la autenticación", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		const payload = env.payload as PayloadCifrado;
		const alterado: Envolvente = {
			...env,
			payload: { ...payload, ct: voltearBit(payload.ct, 0) },
		};

		expect(() => abrirPayload(alterado, sesB, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("el tag Poly1305 truncado se rechaza", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		const payload = env.payload as PayloadCifrado;
		const bytes = Uint8Array.from(atob(payload.ct), (c) => c.charCodeAt(0));
		const sinTag = bytes.subarray(0, bytes.length - 16);
		let binario = "";
		for (const b2 of sinTag) binario += String.fromCharCode(b2);
		const alterado: Envolvente = {
			...env,
			payload: { ...payload, ct: btoa(binario) },
		};

		expect(() => abrirPayload(alterado, sesB, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("cabecera alterada (remitente) falla por el AAD del AEAD", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		// La cabecera va como associated data: un ciphertext válido reemitido bajo
		// otro `origen` rompe Poly1305.
		const suplantado: Envolvente = {
			...env,
			origen: `mlkem${"f".repeat(32)}` as NodoId,
		};

		expect(() => abrirPayload(suplantado, sesB, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("timestamp alterado falla la autenticación", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		expect(() =>
			abrirPayload(
				{ ...env, timestamp: env.timestamp + 1 },
				sesB,
				new GuardiaReplay(),
			),
		).toThrow(ErrorPayloadCifrado);
	});

	it("un contador manipulado produce un nonce distinto y falla", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		const payload = env.payload as PayloadCifrado;
		const alterado: Envolvente = { ...env, payload: { ...payload, ctr: "7" } };

		expect(() => abrirPayload(alterado, sesB, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);
	});
});

describe("protocolo/cifrado — anti-replay", () => {
	it("rechaza un sobre reenviado con el mismo nonce/ctr", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const guardia = new GuardiaReplay();

		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		expect(abrirPayload(env, sesB, guardia).payload).toEqual(REG);
		// Mismo ciphertext, mismo contador, segunda entrega.
		expect(() => abrirPayload(env, sesB, guardia)).toThrow(
			ErrorReplayDetectado,
		);
	});

	it("rechaza el replay del sobre MÁS RECIENTE, no solo los antiguos", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const guardia = new GuardiaReplay();

		// Nada más se entregó, así que este ctr ES el high-water mark: el caso que
		// un guard mal implementado deja pasar.
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		expect(abrirPayload(env, sesB, guardia).payload).toEqual(REG);
		expect(() => abrirPayload(env, sesB, guardia)).toThrow(
			ErrorReplayDetectado,
		);
	});

	it("rechaza un replay reempaquetado con id de sobre nuevo", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);
		const guardia = new GuardiaReplay();

		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);
		abrirPayload(env, sesB, guardia);

		// El atacante reconstruye id/timestamp pero conserva el ciphertext y el
		// contador originales. Poly1305 ya lo tumba por la cabecera; si pasara, el
		// contador es el segundo muro.
		const reempaquetado: Envolvente = {
			...env,
			id: `${env.id}-replay`,
			timestamp: env.timestamp + 5_000,
		};
		expect(() => abrirPayload(reempaquetado, sesB, guardia)).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("tolera reordenamiento dentro de la ventana pero no replays exactos", () => {
		const guardia = new GuardiaReplay({ ventana: 16 });
		const s = "sesion-reorden";
		const dir = DIRECCION.A_A_B;

		// Entrega fuera de orden: 0, 2, 1
		expect(guardia.aceptar(s, dir, 0n)).toBe(true);
		expect(guardia.aceptar(s, dir, 2n)).toBe(true);
		expect(guardia.aceptar(s, dir, 1n)).toBe(true);
		// Y de nuevo cada uno
		expect(guardia.aceptar(s, dir, 0n)).toBe(false);
		expect(guardia.aceptar(s, dir, 2n)).toBe(false);
		expect(guardia.aceptar(s, dir, 1n)).toBe(false);
	});

	it("rechaza contadores por debajo de la ventana de frescura", () => {
		const guardia = new GuardiaReplay({ ventana: 8 });
		const s = "sesion-vieja";
		const dir = DIRECCION.B_A_A;

		expect(guardia.aceptar(s, dir, 1_000n)).toBe(true);
		expect(guardia.aceptar(s, dir, 900n)).toBe(false);
		expect(guardia.aceptar(s, dir, 1_001n)).toBe(true);
		expect(guardia.aceptar(s, dir, 1_000n)).toBe(false);
	});

	it("registra dirección y sesión por separado", () => {
		const guardia = new GuardiaReplay();
		expect(guardia.aceptar("s1", DIRECCION.A_A_B, 5n)).toBe(true);
		// Mismo contador, otra dirección: keystream distinto, así que es válido.
		expect(guardia.aceptar("s1", DIRECCION.B_A_A, 5n)).toBe(true);
		// Mismo contador, otra sesión: sal distinta.
		expect(guardia.aceptar("s2", DIRECCION.A_A_B, 5n)).toBe(true);
	});

	it("expone el high-water mark y el tamaño de ventana", () => {
		const guardia = new GuardiaReplay({ ventana: 32 });
		const s = "sesion-stats";
		expect(guardia.maxVisto(s, DIRECCION.A_A_B)).toBeNull();
		guardia.aceptar(s, DIRECCION.A_A_B, 3n);
		guardia.aceptar(s, DIRECCION.A_A_B, 4n);
		expect(guardia.maxVisto(s, DIRECCION.A_A_B)).toBe(4n);
		expect(guardia.tamañoVentana(s, DIRECCION.A_A_B)).toBe(2);
		guardia.reiniciar();
		expect(guardia.maxVisto(s, DIRECCION.A_A_B)).toBeNull();
	});

	it("rechaza un contador malformado en vez de tratarlo como nuevo", () => {
		const guardia = new GuardiaReplay();
		expect(() => guardia.aceptar("s", DIRECCION.A_A_B, -1n)).toThrow(TypeError);
		expect(() =>
			guardia.aceptar("s", DIRECCION.A_A_B, 5 as unknown as bigint),
		).toThrow(TypeError);
	});

	it("se niega a sellar dos veces bajo el mismo (sesión, dirección, contador)", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		cifrarPayload(createEnvelope("sync", a.nodoId, b.nodoId, REG), sesion);
		// El objeto de sesión no avanzó (una actualización perdida a través de la
		// malla): mismo nonce. XChaCha20-Poly1305 repetiría keystream.
		expect(() =>
			cifrarPayload(createEnvelope("sync", a.nodoId, b.nodoId, REG), sesion),
		).toThrow(ErrorReusoDeNonce);
	});

	it("el tag de dirección produce nonces distintos para el mismo contador", () => {
		const n1 = derivarNonce("abcdef0123456789", 0, DIRECCION.A_A_B, 7n);
		const n2 = derivarNonce("abcdef0123456789", 0, DIRECCION.B_A_A, 7n);
		expect(n1.length).toBe(24);
		expect(iguales(n1, n2)).toBe(false);
	});

	it("contador, epoch y sesión cambian cada uno el nonce", () => {
		const base = derivarNonce("abcdef0123456789", 0, DIRECCION.A_A_B, 7n);
		expect(
			iguales(derivarNonce("abcdef0123456789", 0, DIRECCION.A_A_B, 8n), base),
		).toBe(false);
		expect(
			iguales(derivarNonce("abcdef0123456789", 1, DIRECCION.A_A_B, 7n), base),
		).toBe(false);
		expect(
			iguales(derivarNonce("ffffffffffffffff", 0, DIRECCION.A_A_B, 7n), base),
		).toBe(false);
	});

	it("soporta un contador de 96 bits y falla al desbordar", () => {
		const maximo = (1n << 96n) - 1n;
		expect(
			derivarNonce("abcdef0123456789", 0, DIRECCION.A_A_B, maximo).length,
		).toBe(24);
		expect(() =>
			derivarNonce("abcdef0123456789", 0, DIRECCION.A_A_B, 1n << 96n),
		).toThrow(RangeError);
	});
});

describe("protocolo/cifrado — handshake ML-KEM-768", () => {
	it("ML-KEM corre una vez y ambos lados obtienen las mismas claves", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB, kemPublicoEmisor } = aceptarSesionCifrada(
			b,
			handshake,
		);

		expect(iguales(sesA.claves.claveCifrado, sesB.claves.claveCifrado)).toBe(
			true,
		);
		expect(
			iguales(sesA.claves.claveAutenticacion, sesB.claves.claveAutenticacion),
		).toBe(true);
		expect(iguales(kemPublicoEmisor, a.exportarKemPublico())).toBe(true);
	});

	it("deriva claves de cifrado y de autenticación distintas", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		expect(sesion.claves.claveCifrado.length).toBe(32);
		expect(sesion.claves.claveAutenticacion.length).toBe(32);
		expect(
			iguales(sesion.claves.claveCifrado, sesion.claves.claveAutenticacion),
		).toBe(false);
	});

	it("el mismo secreto con otra sesión da otras claves", () => {
		const secreto = new Uint8Array(32).fill(9);
		const uno = derivarClavesSesion(secreto, "sesion-a");
		const otro = derivarClavesSesion(secreto, "sesion-b");

		expect(iguales(uno.claveCifrado, otro.claveCifrado)).toBe(false);
	});

	it("rechaza entradas malformadas en la derivación", () => {
		expect(() => derivarClavesSesion(new Uint8Array(0), "sesion-a")).toThrow(
			TypeError,
		);
		expect(() =>
			derivarClavesSesion("no-son-bytes" as unknown as Uint8Array, "sesion-a"),
		).toThrow(TypeError);
		expect(() => derivarClavesSesion(new Uint8Array(32), "")).toThrow(
			TypeError,
		);
	});

	it("transporta un ciphertext ML-KEM-768 de 1088 bytes, pagado una vez", async () => {
		const { a, b } = await dosNodos();
		const { handshake } = iniciarSesionCifrada(a, b.exportarKemPublico());

		expect(atob(handshake.kemCipherText).length).toBe(BYTES_CIPHERTEXT_KEM_768);
		expect(BYTES_CIPHERTEXT_KEM_768).toBe(1088);
	});

	it("rechaza un ciphertext ML-KEM truncado", async () => {
		const { a, b } = await dosNodos();
		const { handshake } = iniciarSesionCifrada(a, b.exportarKemPublico());

		expect(() =>
			aceptarSesionCifrada(b, { ...handshake, kemCipherText: btoa("corto") }),
		).toThrow(ErrorPayloadCifrado);
	});

	it("rechaza un handshake de algoritmo desconocido", async () => {
		const { a, b } = await dosNodos();
		const { handshake } = iniciarSesionCifrada(a, b.exportarKemPublico());

		expect(() =>
			aceptarSesionCifrada(b, { ...handshake, alg: "rot13" }),
		).toThrow(ErrorPayloadCifrado);
		expect(() => aceptarSesionCifrada(b, { ...handshake, v: 99 })).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("el handshake no transporta secretos", async () => {
		const { a, b } = await dosNodos();
		const { handshake } = iniciarSesionCifrada(a, b.exportarKemPublico());
		const serializado = JSON.stringify(handshake);

		// Solo el ciphertext ML-KEM, inútil sin la clave privada correspondiente.
		expect(serializado).not.toContain(b.nodoId);
		expect(Object.keys(handshake).sort()).toEqual([
			"alg",
			"kemCipherText",
			"kemPublicoEmisor",
			"sesion",
			"v",
		]);
	});

	it("rotación: el epoch nuevo abre lo nuevo y el ciphertext viejo no", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA0, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);
		const { sesion: sesB0 } = aceptarSesionCifrada(b, handshake);
		const guardia = new GuardiaReplay();

		const { env: envViejo } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA0,
		);
		expect(abrirPayload(envViejo, sesB0, guardia).payload).toEqual(REG);

		// Ambos lados rotan a una encapsulación ML-KEM nueva, epoch + 1.
		const { sesion: sesA1, handshake: hs1 } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
			{
				epoch: sesA0.epoch + 1,
			},
		);
		const { sesion: sesB1 } = aceptarSesionCifrada(b, hs1, {
			epoch: sesB0.epoch + 1,
		});

		const { env: envNuevo } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA1,
		);
		expect(abrirPayload(envNuevo, sesB1, guardia).payload).toEqual(REG);
		expect(() => abrirPayload(envViejo, sesB1, guardia)).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("rotarSesion exige que el epoch avance", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		expect(() => rotarSesion(sesion, sesion.claves, sesion.epoch)).toThrow(
			/epoch must increase/,
		);
		expect(rotarSesion(sesion, sesion.claves, sesion.epoch + 1).epoch).toBe(1);
		expect(() =>
			rotarSesion(
				sesion,
				{
					claveCifrado: new Uint8Array(8),
					claveAutenticacion: sesion.claves.claveAutenticacion,
				},
				1,
			),
		).toThrow(TypeError);
	});

	it("rechaza un payload re-sellado bajo el propio tag de dirección", async () => {
		const { a, b } = await dosNodos();
		const { handshake } = iniciarSesionCifrada(a, b.exportarKemPublico());
		const { sesion: sesB } = aceptarSesionCifrada(b, handshake);

		// Escenario de reflexión: un atacante que somehow consigue re-sellar el
		// registro de A bajo el tag de dirección de B (el propio de la victima).
		// B no debe aceptarlo, porque entonces el tag de dirección dejaría de
		// separar los dos keystreams. Aqui el tag es el de B porque el sobre lo
		// sellamos con su sesion, que es justamente lo que se rechaza.
		const reSellado = cifrarPayload(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesB,
		);

		expect((reSellado.payload as PayloadCifrado).dir).toBe(DIRECCION.B_A_A);
		expect(() => abrirPayload(reSellado, sesB, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);
	});

	it("rechaza un payload de otra sesión", async () => {
		const { a, b } = await dosNodos();
		const { sesion: sesA } = iniciarSesionCifrada(a, b.exportarKemPublico());
		const { env } = cifrarYSiguiente(
			createEnvelope("sync", a.nodoId, b.nodoId, REG),
			sesA,
		);

		const otraSesion: SesionCifrada = { ...sesA, sesionId: "a".repeat(16) };
		expect(() => abrirPayload(env, otraSesion, new GuardiaReplay())).toThrow(
			ErrorPayloadCifrado,
		);
	});
});

describe("protocolo/cifrado — overhead medido", () => {
	it("el AEAD puro cuesta el tag de 16 bytes y el nonce 0", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		const m = medirOverhead(REG, sesion);

		// El coste criptográfico irreducible: 16 bytes del tag de Poly1305. El
		// nonce del AEAD no se transmite, se deriva.
		expect(m.tagBytes).toBe(16);
		expect(m.nonceBytes).toBe(0);
	});

	it("la parte FIJA del overhead (tag + framing) se mide, sin adornos", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		const m = medirOverhead(REG, sesion);
		const fijo = m.tagBytes + m.framingBytes;

		// El objetivo del diseno decia "~40 bytes"; medido son ~106, casi todo el
		// framing JSON de los campos del sobre sellado. Este test fija la cifra
		// REAL. Bajar a ~40 exigiria nombres de campo mas cortos o framing binario,
		// y el binario romperia la firma sobre `canonicalEnvelopeBytes`.
		expect(fijo).toBeGreaterThan(90);
		expect(fijo).toBeLessThan(120);
		expect(m.framingBytes).toBeGreaterThan(80);
	});

	it("el overhead total se descompone sin residuos", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		const m = medirOverhead(REG, sesion);

		expect(m.payloadBytes).toBeGreaterThan(100);
		expect(m.overheadBytes).toBe(m.tagBytes + m.encodingBytes + m.framingBytes);
		expect(m.wireBytes).toBeGreaterThan(m.payloadBytes);
	});

	it("la expansión base64 es el término dominante y escala con el payload", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		const pequeno = medirOverhead({ a: 1 }, sesion);
		const grande = medirOverhead({ a: "x".repeat(4000) }, sesion);

		// Lo que NO escala: el tag, idéntico byte a byte. El framing varía en 1
		// byte porque el campo `ctr` ocupa un dígito más con un contador grande.
		expect(grande.tagBytes).toBe(pequeno.tagBytes);
		expect(
			Math.abs(grande.framingBytes - pequeno.framingBytes),
		).toBeLessThanOrEqual(1);
		// Lo que SÍ escala: base64, ~33% del ciphertext.
		expect(grande.encodingBytes).toBeGreaterThan(pequeno.encodingBytes);
		expect(grande.encodingBytes / grande.payloadBytes).toBeGreaterThan(0.3);
		expect(grande.encodingBytes / grande.payloadBytes).toBeLessThan(0.36);
	});

	it("LIMITACIÓN REAL: el total nunca baja del 1%, el techo es base64", async () => {
		const { a, b } = await dosNodos();
		const { sesion } = iniciarSesionCifrada(a, b.exportarKemPublico());

		const grande = medirOverhead({ historia: "x".repeat(4096) }, sesion);

		expect(grande.payloadBytes).toBeGreaterThan(4_000);
		// El objetivo de diseño de "<1% por mensaje" NO es alcanzable con el
		// sobre en JSON: base64 expande 3 bytes a 4 caracteres, así que el
		// ciphertext pesa de por sí un 33% más. Este test fija ese suelo para que
		// nadie lo descubra en producción.
		expect(grande.ratio).toBeGreaterThan(0.33);
		expect(grande.ratio).toBeLessThan(0.37);
		// Lo que sí se amortiza es la parte fija: sobre un payload grande, el tag
		// y el framing son ruido.
		const parteFija =
			(grande.tagBytes + grande.framingBytes) / grande.payloadBytes;
		expect(parteFija).toBeLessThan(0.03);
	});

	it("ML-KEM-768 no forma parte del coste por mensaje", async () => {
		const { a, b } = await dosNodos();
		const { sesion, handshake } = iniciarSesionCifrada(
			a,
			b.exportarKemPublico(),
		);

		const bytesSesion = JSON.stringify(handshake).length;
		const m = medirOverhead(REG, sesion);

		// 1088 bytes del ciphertext ML-KEM, pagados UNA vez por sesión.
		expect(bytesSesion).toBeGreaterThan(1_000);
		expect(atob(handshake.kemCipherText).length).toBe(1088);
		// Y el resto de la sesión no los repite nunca.
		expect(m.overheadBytes).toBeLessThan(bytesSesion);
	});
});
