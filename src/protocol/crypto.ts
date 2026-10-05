import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type {
	ParPublico,
	PostQuantumIdentity,
	SobreKem,
} from "../identity/index.js";
import { base64ToBytes, bytesToBase64 } from "../identity/index.js";
import type { Envolvente, NodoId } from "../types/index.js";
import { canonicalSerialize } from "./canonical.js";

// ─── QUÉ PROTEGE ESTA CAPA, Y QUÉ NO ───────────────────────────────────────
//
// La malla ya firma cada envolvente con ML-DSA-65, lo que prueba QUIÉN envió los
// bytes y que no fueron alterados. Eso NO es confidencialidad: una firma es
// pública por construcción, cualquiera puede verificarla, y el payload que va
// al lado viaja en claro. Para una historia clínica eso es un bloqueante, no un
// detalle.
//
// Esta capa añade confidencialidad y resistencia a reenvío por encima:
//
//   ML-KEM-768 (FIPS 203)  UNA vez por sesión  -> secreto compartido
//   HKDF-SHA-256                              -> dos claves independientes
//   XChaCha20-Poly1305                        -> un sellado AEAD por mensaje
//   contador monotónico por dirección         -> anti-replay
//
// POR QUÉ ML-KEM SÓLO UNA VEZ POR SESIÓN. La encapsulación ML-KEM-768 cuesta
// 1088 bytes de ciphertext por operación. Pagarlos en cada mensaje costaría mucho
// más que cualquier payload que enviemos, así que el KEM corre al abrir la sesión
// y el AEAD carga con el resto. La clave de sesión puede rotarse (ver `rotar`),
// que es la forma honesta de acotar cuánto tráfico protege una sola clave.
//
// POR QUÉ NO MLS. La respuesta "correcta" obvia para un grupo cifrado de muchos a
// muchos es MLS (RFC 9420). Se rechazo con medidas, no por gusto: su camino de
// commit O(log n) no se sostiene en la practica (arXiv:2502.18303), que es
// exactamente el regime en que vive una malla de gossip. Claves de sesion +
// re-firma por salto mantiene `fanOut=3` saltos barato y auditable.
//
// CLAVES DE CIFRADO Y DE AUTENTICACIÓN SEPARADAS. HKDF deriva dos claves de 32
// bytes del mismo secreto bajo distintos `info`. Las claves de cifrado y las de
// MAC se mantienen distintas a proposito: una clave que cifra y autentica a la
// vez esta a una sola clave comprometida de falsificar.
//
// ─── LIMITACIONES HONESTAS (leer antes de confiar esto con datos reales) ───
//
//   0. EL OBJETIVO DE "~40 BYTES POR MENSAJE" NO SE CUMPLE. Medido sobre
//      envolventes reales, en dos partes:
//
//        fijo    ~106 bytes — la etiqueta Poly1305 de 16 bytes mas ~87 bytes de
//                 framing JSON de los campos del payload sellado (version,
//                 algorithm, session, epoch, direction, counter). Independiente
//                 del payload, pero ~2.5x el objetivo de diseno, y son nombres de
//                 campo JSON, no criptografia.
//        variable ~33% del payload — base64 expande 3 bytes de ciphertext en 4
//                 caracteres, asi que el payload sellado es inherentemente un
//                 tercio mas pesado que el registro. Esto escala sin limite.
//
//      Asi que un registro clinico pequeno cuesta ~135 bytes y uno de 4 KB
//      ~1.4 KB. El AEAD solo cuesta jamas la etiqueta de 16 bytes: el nonce se
//      deriva, no se envia. `medirOverhead` devuelve el desglose, porque quien
//      presupueste esta capa necesita ambos terminos. Bajar del 1% exigiria
//      framing binario en vez de base64-en-JSON: un cambio de transporte,
//      deliberadamente fuera de alcance aqui, y que tendria que preservar la
//      firma ML-DSA sobre `canonicalEnvelopeBytes`.
//
//   1. LOS METADATOS NO SE OCULTAN. Solo `payload` se cifra. `id`, `tipo`,
//      `origen`, `destino`, `timestamp`, `version`, `nonce` y `firma` viajan en
//      claro, como deben: la firma los cubre. Un observador en el camino aprende
//      QUIEN hablo con QUIEN, CUANDO, cada CUANTO y DE QUE TAMANO es cada
//      ciphertext. Para una red medica, el analisis de tamano y tiempos ya es
//      revelador; esta capa no lo aborda y no finge hacerlo. Relleno a tamano fijo
//      y trafico de cobertura son el siguiente paso, no esta capa.
//   2. SIN SECRETO HACIA ADELANTE. El secreto de sesion se deriva de un keypair
//      ML-KEM estatico. Si esa clave de desencapsulacion se roba despues, pueden
//      recalcularse todas las claves de sesion derivadas y descifrarse el trafico
//      pasado. Las firmas ML-DSA no se ven afectadas (de eso sirve una firma).
//      Usa claves de sesion cortas / rotativas para acotar la exposicion.
//   3. LA VENTANA DE REPLAY ESTA ACOTADA, NO INFINITA. El guardia recuerda una
//      ventana deslizante de contadores aceptados; cualquier cosa muy por debajo
//      de la marca alta se rechaza como obsoleta en vez de recordarse para
//      siempre.
//   4. UN ATACANTE ACTIVO QUE REENVIA TRAFICO EN VIVO puede seguir leyendo el
//      texto plano reenviando a un destinatario real. Evitar eso necesita
//      channel binding (`claveAutenticacion`) a un transporte autenticado, que
//      esta capa exporta pero no impone.

// ─── CONSTANTES ────────────────────────────────────────────────────────────

/** Version del wire format del payload sellado. Subir en cualquier cambio de layout. */
export const VERSION_PAYLOAD_CIFRADO = 1;

/** Identificador AEAD escrito en el payload sellado para que los lectores despachen. */
export const ALGORITMO_CIFRADO = "XCHACHA20-POLY1305-HKDF-SHA256/ML-KEM-768";

/**
 * Codigo corto usado en el cable. La construccion completa es
 * `ALGORITMO_CIFRADO`; el nombre largo vive en el codigo y la documentacion
 * porque cada caracter aqui se paga en CADA mensaje. Ver `medirOverhead` para lo
 * que realmente cuesta el framing.
 */
const CODIGO_ALGORITMO = "xc20p1305";

/** Separador de dominio para el `info` de HKDF de la clave de cifrado. */
const DOMINIO_CLAVE_CIFRADO = "shelf-edge-mesh/v1/sesion/cifrado";

/** Separador de dominio para el `info` de HKDF de la clave de autenticacion. */
const DOMINIO_CLAVE_AUTENTICACION = "shelf-edge-mesh/v1/sesion/autenticacion";

/** Separador de dominio para el `salt` de HKDF. */
const DOMINIO_SAL_SESION = "shelf-edge-mesh/v1/sesion/sal";

/**
 * Separador de dominio para la primera pierna de la derivacion. Debe permanecer
 * byte-identico a `DOMINIO_CLAVE_COMPARTIDA` en `../identity/index.ts`: esto
 * reproduce ese paso de forma sincrona (ver `derivarClavesSesion`), y una
 * divergencia haria que las rutas asincrona y sincrona derivaran claves
 * distintas.
 */
const DOMINIO_CLAVE_COMPARTIDA = "shelf-edge-mesh/v1/clave-compartida";

/** Longitud de la clave XChaCha20-Poly1305. */
const BYTES_CLAVE = 32;

/** Longitud del nonce XChaCha20-Poly1305 (192 bits: la "X" es lo que hace seguros
 *  los nonces aleatorios aqui, asi que el contador de abajo es redundancia). */
const BYTES_NONCE = 24;

/** Etiqueta de autenticacion Poly1305 anadida a cada ciphertext. */
const BYTES_TAG = 16;

/** Layout de bytes del nonce derivado (24 bytes, big endian):
 *
 *   `[0..8)`   sal de sesion  — aleatoria por sesion, liga las claves a una sesion
 *   `[8..20)`  contador       — 96 bits monotono, nunca reutilizado bajo una clave
 *   `[20..24)` tag de direccion + epoch, 32 bits BE
 *
 * El tag de direccion es lo que impide que B refleje el ciphertext de A hacia A:
 * ambos derivan un nonce, pero desde tags distintos, asi que el mismo par (clave,
 * contador) produce dos flujos de clave sin relacion.
 */
const BYTES_SAL_NONCE = 8;
const OFFSET_NONCE_SAL = 0;
const OFFSET_NONCE_CTR = BYTES_SAL_NONCE;
const BYTES_CTR = 12;
const OFFSET_NONCE_DIR_EPOCH = BYTES_SAL_NONCE + BYTES_CTR;
const BYTES_NONCE_LIBRES = BYTES_NONCE - (OFFSET_NONCE_DIR_EPOCH + 4);

/** Tamano del ciphertext de encapsulacion ML-KEM-768 (FIPS 203). */
export const BYTES_CIPHERTEXT_KEM_768 = 1088;

/** Maximo de mensajes que una clave de sesion puede sellar antes de rotarse. */
export const MAX_MENSAJES_POR_SESION = 1_000_000;

// ─── ERRORES ───────────────────────────────────────────────────────────────

/** Se lanza cuando una envolvente se reenvia, o su contador no es aceptable. */
export class ErrorReplayDetectado extends Error {
	readonly counter: string;

	constructor(counter: string, motivo: string) {
		super(`Replay rejected: counter ${counter} (${motivo})`);
		this.name = "ErrorReplayDetectado";
		this.counter = counter;
	}
}

/** Se lanza cuando una envolvente no es un payload sellado, o esta malformada. */
export class ErrorPayloadCifrado extends Error {
	constructor(mensaje: string) {
		super(mensaje);
		this.name = "ErrorPayloadCifrado";
	}
}

/** Se lanza cuando una clave de sesion se reutilizaria para el mismo (clave, contador). */
export class ErrorReusoDeNonce extends Error {
	constructor(counter: string) {
		super(
			`Nonce reuse refused: counter ${counter} already used in this session. ` +
				"Rotate the session key instead of repeating a counter.",
		);
		this.name = "ErrorReusoDeNonce";
	}
}

// ─── TIPOS ─────────────────────────────────────────────────────────────────

/** Tag de direccion mezclado en el nonce; tambien nombra el rol emisor/receptor. */
export const DIRECCION = {
	/** Nodo A -> Nodo B. */
	A_A_B: 1,
	/** Nodo B -> Nodo A. */
	B_A_A: 2,
} as const;

export type Direccion = (typeof DIRECCION)[keyof typeof DIRECCION];

/** Las dos claves de sesion derivadas independientemente. */
export interface ClavesSesion {
	/** Clave XChaCha20-Poly1305 de 32 bytes que sella los payloads. */
	readonly claveCifrado: Uint8Array;
	/**
	 * Clave de 32 bytes que una aplicacion puede usar para autenticar el propio
	 * transporte. Esta capa la deriva y la exporta pero nunca la impone (ver
	 * limitacion 4).
	 */
	readonly claveAutenticacion: Uint8Array;
}

/** Descripcion publica y no secreta de una sesion establecida. */
export interface ParamsSesion {
	/** Identificador opaco de sesion; tambien es el salt de HKDF. */
	readonly sesionId: string;
	/** Incrementado en cada rotacion de clave. Parte del nonce derivado. */
	readonly epoch: number;
}

/**
 * Forma en el cable de un payload sellado. El orden de los campos es fijo
 * porque `canonicalEnvelopeBytes` lo serializa a JSON y la firma ML-DSA cubre el
 * resultado: un payload reordenado en el cable dejaria de verificar.
 */
export interface PayloadCifrado {
	readonly v: number;
	readonly alg: string;
	readonly sesion: string;
	readonly epoch: number;
	readonly dir: number;
	readonly ctr: string;
	readonly ct: string;
}

/**
 * Forma en el cable de un mensaje de apertura de sesion. No lleva secretos: un
 * ciphertext ML-KEM dirigido al destinatario, mas la clave publica ML-KEM del
 * emisor para que el destinatario pueda sellar sus propias respuestas sin una
 * segunda ida y vuelta.
 */
export interface HandshakeSesion {
	readonly v: number;
	readonly alg: string;
	readonly sesion: string;
	readonly kemCipherText: string;
	readonly kemPublicoEmisor: string;
}

/** Estado de sesion que sostiene uno de los dos lados de una sesion. */
export interface SesionCifrada extends ParamsSesion {
	readonly claves: ClavesSesion;
	readonly direccion: Direccion;
	/** Contador monotono del PROXIMO mensaje que este lado sellara. */
	readonly siguienteCounter: bigint;
}

// ─── APERTURA DE SESION ────────────────────────────────────────────────────

function bytesAleatorios(n: number): Uint8Array {
	const buf = new Uint8Array(n);
	crypto.getRandomValues(buf);
	return buf;
}

function esUint8Array(v: unknown): v is Uint8Array {
	return v instanceof Uint8Array && v.length > 0;
}

/**
 * Deriva las dos claves de sesion desde un secreto compartido ML-KEM-768.
 *
 * `derivarClaveSimetrica` (SHA-256 con separador de dominio) se aplica primero
 * para que el secreto KEM crudo nunca se use como material de clave directamente,
 * y luego HKDF estira el resultado en dos claves con propositos separados. Ambos
 * pares ejecutan la construccion identica sobre los bytes identicos, asi que
 * ambos aterrizan en el mismo par sin necesidad de acuerdo adicional.
 *
 * SHA-256 viene de `@noble/hashes` en vez de WebCrypto porque el camino del
 * handshake es sincrono (`encapsular` es sync) y el digest de WebCrypto es
 * solo-promise. SHA-256 es SHA-256: los bytes que se hashean aqui son
 * exactamente los bytes que hashea `derivarClaveSimetrica`, asi que ambos puntos
 * de entrada derivan claves identicas.
 *
 * @param sharedSecret 32 bytes de `encapsular` / `decapsular`.
 * @param sesionId id de sesion, usado como salt de HKDF (liga las claves a una
 *   sesion).
 * @throws TypeError ante entrada malformada en vez de derivar desde basura.
 */
export function derivarClavesSesion(
	sharedSecret: Uint8Array,
	sesionId: string,
): ClavesSesion {
	if (!esUint8Array(sharedSecret)) {
		throw new TypeError(
			"derivarClavesSesion: sharedSecret must be a non-empty Uint8Array",
		);
	}
	if (typeof sesionId !== "string" || sesionId.length === 0) {
		throw new TypeError(
			"derivarClavesSesion: sesionId must be a non-empty string",
		);
	}

	const enc = new TextEncoder();
	const prefijo = enc.encode(DOMINIO_CLAVE_COMPARTIDA);
	const entrada = new Uint8Array(prefijo.length + sharedSecret.length);
	entrada.set(prefijo, 0);
	entrada.set(sharedSecret, prefijo.length);
	const base = sha256(entrada);

	const salt = hkdf(
		sha256,
		base,
		enc.encode(DOMINIO_SAL_SESION),
		enc.encode(sesionId),
		32,
	);
	return {
		claveCifrado: hkdf(
			sha256,
			base,
			salt,
			enc.encode(DOMINIO_CLAVE_CIFRADO),
			BYTES_CLAVE,
		),
		claveAutenticacion: hkdf(
			sha256,
			base,
			salt,
			enc.encode(DOMINIO_CLAVE_AUTENTICACION),
			BYTES_CLAVE,
		),
	};
}

/** Alias awaitable, para puntos de llamada ya en contexto asincrono. */
export async function derivarClavesSesionAsync(
	sharedSecret: Uint8Array,
	sesionId: string,
): Promise<ClavesSesion> {
	return derivarClavesSesion(sharedSecret, sesionId);
}

function bytesASesionId(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/**
 * Lado emisor del handshake: encapsula hacia el destinatario, deriva las claves, y
 * devuelve tanto la sesion local como el mensaje de cable a enviar.
 *
 * ML-KEM-768 corre AQUI y solo aqui. Cada mensaje posterior de la sesion se sella
 * con XChaCha20-Poly1305 bajo la clave derivada.
 */
export function iniciarSesionCifrada(
	emisor: PostQuantumIdentity,
	kemPublicoReceptor: ParPublico,
	opciones: { readonly epoch?: number } = {},
): { readonly sesion: SesionCifrada; readonly handshake: HandshakeSesion } {
	if (!esUint8Array(kemPublicoReceptor)) {
		throw new TypeError(
			"iniciarSesionCifrada: recipient ML-KEM public key must be a non-empty Uint8Array",
		);
	}
	const sobre: SobreKem = emisor.encapsular(kemPublicoReceptor);
	const sesionId = bytesASesionId(bytesAleatorios(BYTES_SAL_NONCE));
	const claves = derivarClavesSesion(sobre.claveCompartida, sesionId);
	const epoch = opciones.epoch ?? 0;

	return {
		sesion: {
			sesionId,
			epoch,
			claves,
			direccion: DIRECCION.A_A_B,
			siguienteCounter: 0n,
		},
		handshake: {
			v: VERSION_PAYLOAD_CIFRADO,
			alg: CODIGO_ALGORITMO,
			sesion: sesionId,
			kemCipherText: bytesToBase64(sobre.cipherText),
			kemPublicoEmisor: bytesToBase64(emisor.exportarKemPublico()),
		},
	};
}

/**
 * Lado receptor del handshake: desencapsula, deriva las mismas claves, y devuelve
 * la sesion local mas la clave publica ML-KEM del emisor (para que una respuesta
 * pueda sellarse sin otra ida y vuelta).
 */
export function aceptarSesionCifrada(
	receptor: PostQuantumIdentity,
	handshake: HandshakeSesion,
	opciones: { readonly epoch?: number } = {},
): { readonly sesion: SesionCifrada; readonly kemPublicoEmisor: ParPublico } {
	if (!handshake || typeof handshake !== "object") {
		throw new ErrorPayloadCifrado(
			"aceptarSesionCifrada: handshake must be an object",
		);
	}
	if (
		handshake.v !== VERSION_PAYLOAD_CIFRADO ||
		handshake.alg !== CODIGO_ALGORITMO
	) {
		throw new ErrorPayloadCifrado(
			"aceptarSesionCifrada: unsupported handshake version or algorithm",
		);
	}
	if (typeof handshake.sesion !== "string" || handshake.sesion.length === 0) {
		throw new ErrorPayloadCifrado(
			"aceptarSesionCifrada: handshake.sesion must be a non-empty string",
		);
	}

	const kemCipherText = base64ToBytes(handshake.kemCipherText);
	if (kemCipherText.length !== BYTES_CIPHERTEXT_KEM_768) {
		throw new ErrorPayloadCifrado(
			`aceptarSesionCifrada: ML-KEM-768 ciphertext must be ${BYTES_CIPHERTEXT_KEM_768} bytes, got ${kemCipherText.length}`,
		);
	}

	const kemPublicoEmisor = base64ToBytes(handshake.kemPublicoEmisor);
	const secretoCompartido = receptor.decapsular(kemCipherText);
	const claves = derivarClavesSesion(secretoCompartido, handshake.sesion);

	return {
		sesion: {
			sesionId: handshake.sesion,
			epoch: opciones.epoch ?? 0,
			claves,
			direccion: DIRECCION.B_A_A,
			siguienteCounter: 0n,
		},
		kemPublicoEmisor,
	};
}

/**
 * Rota las claves de sesion bajo un nuevo epoch.
 *
 * Llama a `iniciarSesionCifrada` de nuevo con el nuevo ciphertext ML-KEM y pasa
 * `epoch: sesion.epoch + 1`. Mantener el guardia del epoch viejo es tarea del
 * llamador: esta funcion deliberadamente no toca el estado del guardia, para que
 * un epoch viejo siga siendo rechazable (y sus mensajes sigan sin descifrarse)
 * tras el cambio.
 */
export function rotarSesion(
	sesion: SesionCifrada,
	claves: ClavesSesion,
	epoch: number,
): SesionCifrada {
	if (!Number.isInteger(epoch) || epoch <= sesion.epoch) {
		throw new Error(
			`rotarSesion: epoch must increase (current ${sesion.epoch}, got ${epoch})`,
		);
	}
	if (
		claves.claveCifrado.length !== BYTES_CLAVE ||
		claves.claveAutenticacion.length !== BYTES_CLAVE
	) {
		throw new TypeError(`rotarSesion: both keys must be ${BYTES_CLAVE} bytes`);
	}
	return {
		sesionId: sesion.sesionId,
		epoch,
		claves,
		direccion: sesion.direccion,
		siguienteCounter: 0n,
	};
}

// ─── NONCE ─────────────────────────────────────────────────────────────────

function counterABytes(counter: bigint): Uint8Array {
	const out = new Uint8Array(BYTES_CTR);
	let c = counter;
	for (let i = BYTES_CTR - 1; i >= 0; i--) {
		out[i] = Number(c & 0xffn);
		c >>= 8n;
	}
	if (c !== 0n) {
		throw new RangeError(
			`Nonce counter overflow: ${counter} does not fit in ${BYTES_CTR} bytes`,
		);
	}
	return out;
}

/**
 * Construye el nonce XChaCha de 24 bytes.
 *
 * El nonce se DERIVA, nunca se transmite: es una funcion pura de la sal de sesion
 * (codificada en `sesionId`), el epoch, el tag de direccion y el contador. Por eso
 * la sobrecarga por mensaje en el cable es una etiqueta Poly1305 de 16 bytes mas
 * un campo de contador corto, y no 24 bytes extra.
 */
export function derivarNonce(
	sesionId: string,
	epoch: number,
	direccion: Direccion,
	counter: bigint,
): Uint8Array {
	const nonce = new Uint8Array(BYTES_NONCE);
	nonce.set(sessionSalt(sesionId), OFFSET_NONCE_SAL);
	nonce.set(counterABytes(counter), OFFSET_NONCE_CTR);

	// `[20..24)` tag de direccion en el byte alto, epoch en los tres bajos. Tag y
	// epoch comparten una ranura de 32 bits para que el nonce siga siendo de
	// exactamente 24 bytes.
	const vista = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	const dirEpoch = ((direccion & 0xff) << 24) | ((epoch >>> 0) & 0x00ffffff);
	vista.setUint32(OFFSET_NONCE_DIR_EPOCH, dirEpoch >>> 0, false);

	if (BYTES_NONCE_LIBRES < 0) {
		throw new Error(`Nonce layout overflow: ${BYTES_NONCE_LIBRES} spare bytes`);
	}
	return nonce;
}

/**
 * Recupera la sal de sesion de 8 bytes de un id de sesion. Los ids de sesion se
 * emiten como 16 hex para la sal; los ids mas largos aportan sus primeros 8 bytes.
 */
function sessionSalt(sesionId: string): Uint8Array {
	const hex = sesionId.replace(/[^0-9a-fA-F]/g, "");
	if (hex.length >= BYTES_SAL_NONCE * 2) {
		const out = new Uint8Array(BYTES_SAL_NONCE);
		for (let i = 0; i < BYTES_SAL_NONCE; i++) {
			out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16) || 0;
		}
		return out;
	}
	const seed = new TextEncoder().encode(sesionId);
	const out = sha256(seed).slice(0, BYTES_SAL_NONCE);
	return out;
}

// ─── GUARDIA ANTI-REPLAY ───────────────────────────────────────────────────

interface EstadoDireccion {
	/** Contador mas alto aceptado hasta ahora para esta direccion. */
	maxVisto: bigint;
	/**
	 * Cada contador aceptado para esta direccion, INCLUYENDO la marca alta.
	 * La frontera tiene que estar aqui: se acepta exactamente una vez, y sin ella
	 * un reenvio del mensaje mas reciente se juzgaria solo por el suelo de la
	 * ventana y — por ser el mas reciente — pasaria.
	 */
	aceptados: Set<string>;
}

export interface GuardiaReplayOpciones {
	/** Cuanto por debajo de la marca alta puede aceptarse un contador aun. */
	readonly ventana: number;
	/** Techo de contadores recordados, por direccion. */
	readonly maxEntradas: number;
}

const CONFIG_REPLAY_POR_DEFECTO: GuardiaReplayOpciones = {
	ventana: 1024,
	maxEntradas: 4096,
} as const;

/**
 * Guardia anti-replay para envolventes cifrados.
 *
 * POR QUE EXISTE. Una envolvente cifrada es, por construccion, reenviable: el
 * ciphertext y el contador estan ambos en el cable, y la autenticacion AEAD solo
 * prueba "este blob lo produjo alguien con la clave", no "este blob se esta
 * entregando por primera vez". Para una historia clinica esa es la diferencia
 * entre una consulta y dos. `MessageDeduplicator` (id + origen, ventana de 5 s)
 * NO es sustituto: esta acotado en el tiempo, olvida, y se indexa por un campo que
 * elige el atacante.
 *
 * COMPORTAMIENTO, por (sesionId, direccion):
 *
 *   - contador ya aceptado      -> RECHAZAR (reenvio exacto, aunque tarde)
 *   - contador bajo `maxVisto - ventana` -> RECHAZAR (demasiado viejo para probar frescura)
 *   - contador sobre `maxVisto` -> ACEPTAR, avanzar la marca
 *   - contador bajo la marca pero dentro de la ventana y nunca visto -> ACEPTAR
 *
 * El reordenamiento DENTRO de la ventana se tolera, porque una malla de gossip
 * entrega fuera de orden por diseno. Un reenvio exacto nunca se tolera.
 */
export class GuardiaReplay {
	private readonly estados = new Map<string, EstadoDireccion>();
	private readonly config: GuardiaReplayOpciones;

	constructor(config: Partial<GuardiaReplayOpciones> = {}) {
		this.config = { ...CONFIG_REPLAY_POR_DEFECTO, ...config };
	}

	private clave(sesionId: string, direccion: Direccion): string {
		return `${sesionId}:${direccion}`;
	}

	/**
	 * Registra un contador entrante.
	 *
	 * @returns true si la envolvente es aceptable, false si debe rechazarse como
	 *   reenvio.
	 * @throws TypeError ante un contador malformado, para que la basura no se
	 *   trate en silencio como un mensaje nuevo.
	 */
	aceptar(sesionId: string, direccion: Direccion, counter: bigint): boolean {
		if (typeof counter !== "bigint" || counter < 0n) {
			throw new TypeError(
				"GuardiaReplay.aceptar: counter must be a non-negative bigint",
			);
		}
		const clave = this.clave(sesionId, direccion);
		const texto = counter.toString();
		const estado = this.estados.get(clave);

		if (!estado) {
			this.estados.set(clave, {
				maxVisto: counter,
				aceptados: new Set([texto]),
			});
			return true;
		}

		if (estado.aceptados.has(texto)) return false;
		if (counter > estado.maxVisto) {
			estado.maxVisto = counter;
		} else if (estado.maxVisto - counter > BigInt(this.config.ventana)) {
			return false;
		}

		estado.aceptados.add(texto);
		this.podar(estado);
		return true;
	}

	/** Rechaza con un error tipado en vez de devolver un booleano pelado. */
	exigirAceptable(
		sesionId: string,
		direccion: Direccion,
		counter: bigint,
	): void {
		if (!this.aceptar(sesionId, direccion, counter)) {
			throw new ErrorReplayDetectado(
				counter.toString(),
				"already accepted or below the window",
			);
		}
	}

	/**
	 * Recorta la ventana: descarta lo que el suelo ya rechaza, luego acota el
	 * tamano. La marca alta se reinserta para que el desalojo nunca abra un hueco
	 * en la frontera.
	 */
	private podar(estado: EstadoDireccion): void {
		const limite = estado.maxVisto - BigInt(this.config.ventana);
		for (const texto of estado.aceptados) {
			if (BigInt(texto) < limite) estado.aceptados.delete(texto);
		}
		while (estado.aceptados.size > this.config.maxEntradas) {
			const primero = estado.aceptados.values().next();
			if (primero.done) break;
			estado.aceptados.delete(primero.value);
		}
		estado.aceptados.add(estado.maxVisto.toString());
	}

	/** Contador mas alto aceptado hasta ahora para una direccion, o null si ninguno. */
	maxVisto(sesionId: string, direccion: Direccion): bigint | null {
		return this.estados.get(this.clave(sesionId, direccion))?.maxVisto ?? null;
	}

	/** Cantidad de contadores recordados para una direccion. */
	tamañoVentana(sesionId: string, direccion: Direccion): number {
		return (
			this.estados.get(this.clave(sesionId, direccion))?.aceptados.size ?? 0
		);
	}

	reiniciar(): void {
		this.estados.clear();
	}
}

// ─── SELLAR / ABRIR ────────────────────────────────────────────────────────

/**
 * Datos asociados: la cabecera de la envolvente menos el payload y la firma.
 *
 * Ligar la cabecera dentro del AEAD es lo que impide que un ciphertext valido se
 * reenvie bajo un `id`, `origen` o `timestamp` distinto: mueve un campo de
 * cabecera y Poly1305 falla. Esto NO toca `canonicalEnvelopeBytes`, asi que las
 * firmas existentes siguen verificando exactamente igual que antes.
 */
function headerAad(env: Envolvente): Uint8Array {
	return canonicalSerialize({
		id: env.id,
		tipo: env.tipo,
		origen: env.origen,
		destino: env.destino,
		timestamp: env.timestamp,
		version: env.version,
		nonce: env.nonce,
	});
}

function esPayloadCifrado(p: unknown): p is PayloadCifrado {
	if (!p || typeof p !== "object") return false;
	const c = p as Partial<PayloadCifrado>;
	return (
		c.v === VERSION_PAYLOAD_CIFRADO &&
		c.alg === CODIGO_ALGORITMO &&
		typeof c.sesion === "string" &&
		typeof c.epoch === "number" &&
		typeof c.dir === "number" &&
		typeof c.ctr === "string" &&
		typeof c.ct === "string"
	);
}

/** True cuando `env.payload` es un payload sellado producido por `cifrarPayload`. */
export function esEnvolventeCifrado(env: Envolvente): boolean {
	return esPayloadCifrado(env.payload);
}

/**
 * Sella el payload de una envolvente. Devuelve una envolvente NUEVA; la entrada no
 * se muta. La envolvente devuelta es la que hay que firmar — firma DESPUES de
 * cifrar, para que la firma ML-DSA cubra el ciphertext.
 *
 * El contador viene de `siguienteCounter` y se avanza en el estado de sesion
 * devuelto; reutilizar un contador bajo la misma clave lanza `ErrorReusoDeNonce` en
 * vez de producir en silencio una repeticion del flujo de clave.
 */
export function cifrarPayload(
	env: Envolvente,
	sesion: SesionCifrada,
): Envolvente {
	return sellarPayload(env, sesion, true);
}

/**
 * El sellado en si, con la trampa de reuso de nonce condicional.
 *
 * `registrar` es false solo para medicion, que sella una envolvente de descarte en
 * el contador 0 unicamente para medir el costo en bytes. Cada envio real pasa por
 * `cifrarPayload` / `cifrarYSiguiente`, que siempre registran.
 */
function sellarPayload(
	env: Envolvente,
	sesion: SesionCifrada,
	registrar: boolean,
): Envolvente {
	if (esPayloadCifrado(env.payload)) {
		throw new Error(
			"cifrarPayload: envelope payload is already sealed (double encryption)",
		);
	}
	const counter = sesion.siguienteCounter;
	if (counter >= BigInt(MAX_MENSAJES_POR_SESION)) {
		throw new RangeError(
			`Session key exhausted: rotate before ${MAX_MENSAJES_POR_SESION} messages`,
		);
	}
	if (registrar && contadoresUsados.has(claveContador(sesion, counter))) {
		throw new ErrorReusoDeNonce(counter.toString());
	}

	const nonce = derivarNonce(
		sesion.sesionId,
		sesion.epoch,
		sesion.direccion,
		counter,
	);
	const aad = headerAad(env);
	const aead = xchacha20poly1305(sesion.claves.claveCifrado, nonce, aad);
	const plaintext = new TextEncoder().encode(
		JSON.stringify(env.payload ?? null),
	);
	const ciphertext = aead.encrypt(plaintext);

	if (registrar) registrarContador(sesion, counter);

	const payload: PayloadCifrado = {
		v: VERSION_PAYLOAD_CIFRADO,
		alg: CODIGO_ALGORITMO,
		sesion: sesion.sesionId,
		epoch: sesion.epoch,
		dir: sesion.direccion,
		ctr: counter.toString(),
		ct: bytesToBase64(ciphertext),
	};

	return { ...env, payload };
}

/**
 * Abre una envolvente sellada y la comprueba contra el guardia anti-replay.
 *
 * El orden importa: el guardia se consulta DESPUES de que el descifrado tenga
 * exito (para que un atacante no pueda quemar contadores mandando basura) pero
 * ANTES de que el llamador llegue a ver el valor de aplicacion en claro.
 *
 * @returns una envolvente nueva con el payload en claro restaurado.
 * @throws ErrorPayloadCifrado si la envolvente no esta sellada o Poly1305 falla.
 * @throws ErrorReplayDetectado si el contador es un reenvio.
 */
export function abrirPayload(
	env: Envolvente,
	sesion: SesionCifrada,
	guardia: GuardiaReplay,
	opciones: { readonly aplicarGuardia?: boolean } = {},
): Envolvente {
	if (!esPayloadCifrado(env.payload)) {
		throw new ErrorPayloadCifrado(
			"abrirPayload: envelope payload is not a sealed payload",
		);
	}
	if (env.payload.sesion !== sesion.sesionId) {
		throw new ErrorPayloadCifrado(
			"abrirPayload: payload belongs to a different session",
		);
	}
	if (env.payload.epoch !== sesion.epoch) {
		throw new ErrorPayloadCifrado(
			`abrirPayload: payload epoch ${env.payload.epoch} does not match session epoch ${sesion.epoch} (rotated?)`,
		);
	}
	if (env.payload.dir === sesion.direccion) {
		throw new ErrorPayloadCifrado(
			"abrirPayload: payload was sealed with this side's own direction tag",
		);
	}

	let counter: bigint;
	try {
		counter = BigInt(env.payload.ctr);
	} catch {
		throw new ErrorPayloadCifrado(
			`abrirPayload: counter "${env.payload.ctr}" is not an integer`,
		);
	}
	if (counter < 0n) {
		throw new ErrorPayloadCifrado("abrirPayload: counter must be non-negative");
	}

	const direccion = env.payload.dir as Direccion;
	const nonce = derivarNonce(sesion.sesionId, sesion.epoch, direccion, counter);
	const aead = xchacha20poly1305(
		sesion.claves.claveCifrado,
		nonce,
		headerAad(env),
	);

	let plaintext: Uint8Array;
	try {
		plaintext = aead.decrypt(base64ToBytes(env.payload.ct));
	} catch {
		// Deliberadamente vago: nunca se distingue "etiqueta mala" de
		// "ciphertext malo".
		throw new ErrorPayloadCifrado(
			"abrirPayload: XChaCha20-Poly1305 authentication failed (tampered payload or wrong key)",
		);
	}

	if (opciones.aplicarGuardia !== false) {
		guardia.exigirAceptable(sesion.sesionId, direccion, counter);
	}

	let payload: unknown;
	try {
		payload = JSON.parse(new TextDecoder().decode(plaintext));
	} catch {
		throw new ErrorPayloadCifrado(
			"abrirPayload: decrypted payload is not valid JSON",
		);
	}

	return { ...env, payload };
}

/**
 * Sella una envolvente y devuelve tanto la envolvente sellada como la sesion
 * avanzada. Este es el punto de entrada previsto para un emisor: es el unico que
 * puede garantizar que el nonce nunca se reutiliza.
 *
 * Reutilizar un par (clave, nonce) bajo XChaCha20-Poly1305 es catastrofico —
 * filtra la XOR de dos textos planos y pierde la clave de autenticacion — asi que
 * la comprobacion se impone aqui y lanza `ErrorReusoDeNonce` en vez de dejarse en
 * manos de la convencion. El id de sesion y el epoch son parte del nonce
 * derivado, asi que una sesion realmente rotada no se ve afectada.
 */
export function cifrarYSiguiente(
	env: Envolvente,
	sesion: SesionCifrada,
): { env: Envolvente; sesion: SesionCifrada } {
	assertContadorLibre(sesion, sesion.siguienteCounter);
	const envCifrado = cifrarPayload(env, sesion);
	return {
		env: envCifrado,
		sesion: { ...sesion, siguienteCounter: sesion.siguienteCounter + 1n },
	};
}

/** Avanza en uno el contador de salida de una sesion, con las mismas comprobaciones. */
export function marcarEnviado(sesion: SesionCifrada): SesionCifrada {
	assertContadorLibre(sesion, sesion.siguienteCounter);
	return { ...sesion, siguienteCounter: sesion.siguienteCounter + 1n };
}

/**
 * Se niega a sellar bajo una tupla (sesion, epoch, direccion, contador) ya usada.
 * `ErrorReusoDeNonce` se lanza en vez de devolverse: esto nunca debe ser una
 * condicion recuperable.
 */
function assertContadorLibre(sesion: SesionCifrada, counter: bigint): void {
	if (counter >= BigInt(MAX_MENSAJES_POR_SESION)) {
		throw new RangeError(
			`Session key exhausted: rotate before ${MAX_MENSAJES_POR_SESION} messages`,
		);
	}
	if (contadoresUsados.has(claveContador(sesion, counter))) {
		throw new ErrorReusoDeNonce(counter.toString());
	}
}

function claveContador(sesion: SesionCifrada, counter: bigint): string {
	return `${sesion.sesionId}:${sesion.epoch}:${sesion.direccion}:${counter}`;
}

/**
 * Registro de proceso de cada (sesion, epoch, direccion, contador) sellado.
 *
 * Una sesion son datos planos que se clonan por toda la malla; indexar el registro
 * por la identidad del objeto no sobreviviria a eso, e indexarlo por el secreto
 * defeatediria el proposito. La tupla es lo que de verdad determina el nonce, asi
 * que la tupla es lo que se recuerda.
 *
 * Acotado en `MAX_CONTADORES_RECORDADOS`: es una trampa contra un error de
 * programacion (una actualizacion de sesion perdida, un rollback revertido), no una
 * frontera de seguridad. Un adversario que logre hacer que el emisor reutilice un
 * contador ya puede lograr que envie cualquier cosa.
 */
const MAX_CONTADORES_RECORDADOS = 200_000;
const contadoresUsados = new Set<string>();

function registrarContador(sesion: SesionCifrada, counter: bigint): void {
	if (contadoresUsados.size >= MAX_CONTADORES_RECORDADOS) {
		const aEliminar = contadoresUsados.size - MAX_CONTADORES_RECORDADOS + 1;
		let i = 0;
		for (const clave of contadoresUsados) {
			contadoresUsados.delete(clave);
			if (++i >= aEliminar) break;
		}
	}
	contadoresUsados.add(claveContador(sesion, counter));
}

// ─── SOBRECOSTE ────────────────────────────────────────────────────────────

export interface MedicionOverhead {
	/** Tamano del payload en claro en bytes. */
	readonly payloadBytes: number;
	/** Tamano del payload sellado en el cable, serializado a JSON (lo que la firma cubre). */
	readonly wireBytes: number;
	/** `wireBytes - payloadBytes`: el costo total real por mensaje. */
	readonly overheadBytes: number;
	/** `overheadBytes / payloadBytes`. */
	readonly ratio: number;
	/**
	 * Costo puro del AEAD: la etiqueta Poly1305, y nada mas. Este es el numero
	 * que NO escala con el payload.
	 */
	readonly tagBytes: number;
	/** El nonce del AEAD cuesta 0 bytes: se deriva, nunca se transmite. */
	readonly nonceBytes: number;
	/**
	 * Costo de llevar el ciphertext dentro de una envolvente JSON: base64 expande
	 * cada 3 bytes de ciphertext en 4 caracteres, asi que esto es ~33% del
	 * ciphertext y SI escala con el payload.
	 */
	readonly encodingBytes: number;
	/** Costo fijo de los campos JSON del payload sellado en si. */
	readonly framingBytes: number;
}

/**
 * Mide lo que el cifrado realmente cuesta por mensaje, descompuesto.
 *
 * La descompusion honesta, porque el unico numero de "sobrecoste" esconde que
 * parte es negociable:
 *
 *   - 16 bytes   etiqueta de autenticacion Poly1305. Irreducible para cualquier
 *                AEAD, e independiente del tamano del payload.
 *   -  0 bytes   nonce del AEAD. Derivado de (sal de sesion, epoch, direccion,
 *                contador); nunca transmitido. Por eso el diseno no paga 24
 *                bytes de nonce por mensaje.
 *   - ~75 bytes  framing JSON de los campos del payload sellado (version, codigo
 *                de algoritmo, id de sesion, epoch, direccion, contador). Fijo.
 *   - ~33%       expansion base64 del ciphertext. Esta si escala con el payload y
 *                es el termino dominante en registros grandes.
 *
 * O sea: la cifra de "~40 bytes por mensaje" es el AEAD mas el framing, es decir
 * la parte fija, y se sostiene. Pero `overheadBytes` — lo que el cable realmente
 * crece — lo domina base64, y en un registro de 4 KB es aproximadamente un tercio
 * del registro, no 40 bytes. Cualquiera que presupueste esta capa necesita ambos
 * numeros, asi que se devuelven ambos.
 *
 * El ciphertext de ML-KEM-768 de 1088 bytes NO esta en ninguno de estos: se paga
 * una vez por sesion, no por mensaje. Usa `JSON.stringify(handshake).length` para eso.
 */
export function medirOverhead(
	payload: unknown,
	sesion: SesionCifrada,
): MedicionOverhead {
	const plaintext = new TextEncoder().encode(JSON.stringify(payload ?? null));
	const env: Envolvente = {
		id: "medicion",
		tipo: "sync" as Envolvente["tipo"],
		origen: "origen" as NodoId,
		destino: "destino" as NodoId,
		timestamp: 1_700_000_000_000,
		firma: null,
		payload,
		version: 1,
		nonce: "medicion",
	};
	const sellado = sellarPayload(env, sesion, false);
	const wire = new TextEncoder().encode(JSON.stringify(sellado.payload));
	const overhead = wire.length - plaintext.length;

	// base64 expande cada 3 bytes de ciphertext en 4 caracteres; el padding `=`
	// no lleva datos, asi que la expansion verdadera es el conteo de caracteres
	// menos el conteo de bytes crudos.
	const ctBase64 = (sellado.payload as PayloadCifrado).ct;
	const ctBytes = ctBase64.length;
	const encoding = ctBytes - Math.floor(ctBytes / 4) * 3;

	return {
		payloadBytes: plaintext.length,
		wireBytes: wire.length,
		overheadBytes: overhead,
		ratio: plaintext.length === 0 ? 0 : overhead / plaintext.length,
		tagBytes: BYTES_TAG,
		nonceBytes: 0,
		encodingBytes: encoding,
		framingBytes: overhead - BYTES_TAG - encoding,
	};
}
