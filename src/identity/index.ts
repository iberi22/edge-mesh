import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { bytesAHex, hexABytes } from "../protocol/utils.js";
import type { NodoId, ParPublico } from "../types/index.js";

export type { ParPublico };

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const ALGORITMO = "ML-DSA-65" as const;
const ALGORITMO_KEM = "ML-KEM-768" as const;

/**
 * Separadores de dominio. Cada derivacion de este modulo prefija su entrada
 * con uno de estos, de modo que un valor derivado para un proposito jamas pueda
 * reutilizarse como valor de otro (p. ej. un nodoId nunca colisiona con una
 * clave).
 *
 * These literals are load-bearing across two files: `DOMINIO_CLAVE_COMPARTIDA`
 * is reproduced byte-identically in `src/protocol/crypto.ts`, which performs the
 * same derivation synchronously (WebCrypto's digest is promise-only, and the
 * KEM handshake is sync). A divergence would make the sync and async paths
 * derive different session keys from the same shared secret.
 */
const DOMINIO_NODO_ID = "shelf-edge-mesh/v1/nodo-id";
const DOMINIO_CLAVE_COMPARTIDA = "shelf-edge-mesh/v1/clave-compartida";

/** Prefijo de un identificador de nodo derivado criptograficamente. */
export const PREFIJO_NODO_DERIVADO = "mlkem";

/** Bytes de digest conservados en un nodoId derivado (16 bytes -> 32 hex). */
const BYTES_NODO_ID = 16;

export const TIPO_IDENTIDAD = {
	MAESTRA: "maestra",
	EPHEMERA: "ephemera",
	SERVICIO: "servicio",
} as const;

export type TipoIdentidad =
	(typeof TIPO_IDENTIDAD)[keyof typeof TIPO_IDENTIDAD];

/**
 * QUE PRUEBA ML-DSA-65 Y QUE PROTEGE ML-KEM-768: son garantias distintas y
 * ninguna sustituye a la otra.
 *
 * - ML-DSA-65 (firma, `firmar` / `verificar`): **autenticidad + integridad**.
 *   Prueba que el tenedor de la clave privada escribio esos bytes exactos y que
 *   no fueron alterados en transito. No revela nada: cualquiera puede verificar.
 *
 * - ML-KEM-768 (encapsulacion, `encapsular` / `decapsular`): **confidencialidad
 *   del secreto compartido**. Solo el dueno de la clave privada correspondiente
 *   puede recuperarlo; el ciphertext que viaja es inservible para cualquier otro.
 *   No dice NADA sobre quien envio el mensaje.
 *
 * Un envolvente correcto necesita ambos: ML-KEM para que solo el destinatario
 * lea el payload, ML-DSA para que el destinatario pruebe quien lo envio.
 */
export const ALGORITMOS = {
	FIRMA: ALGORITMO,
	KEM: ALGORITMO_KEM,
} as const;

// ─── KEYPAIR ───────────────────────────────────────────────────────────────

export interface PostQuantumKeypair {
	readonly parPrivado: Uint8Array;
	readonly parPublico: ParPublico;
	/**
	 * Clave de desencapsulacion ML-KEM-768. Ausente solo para keypairs restaurados
	 * de la serializacion legacy (pre-KEM); en ese caso se genera una nueva.
	 */
	readonly kemPrivado?: Uint8Array;
	/** Clave de encapsulacion ML-KEM-768. Esto es lo que viaja por el cable. */
	readonly kemPublico?: Uint8Array;
	readonly algoritmo: string;
	readonly tipo: TipoIdentidad;
	readonly fechaCreacion: number;
}

export interface IdentityProvider {
	sign(data: string): Promise<string>;
	verify(
		data: string,
		signature: string,
		publicKey: Uint8Array,
	): Promise<boolean>;
}

/** Resultado de `encapsular`: el ciphertext a enviar mas el secreto local. */
export interface SobreKem {
	readonly cipherText: Uint8Array;
	readonly claveCompartida: Uint8Array;
}

export interface PostQuantumIdentity extends IdentityProvider {
	readonly nodoId: NodoId;
	readonly keypair: PostQuantumKeypair;

	firmar(datos: Uint8Array): Promise<Uint8Array>;
	verificar(
		datos: Uint8Array,
		firma: Uint8Array,
		parPublico: ParPublico,
	): Promise<boolean>;
	exportarPublico(): ParPublico;
	obtenerAlgoritmo(): string;

	// ── Superficie ML-KEM-768 (confidencialidad) ──

	/** Clave publica ML-KEM-768 de este nodo. Segura para poner en el cable. */
	exportarKemPublico(): ParPublico;
	/**
	 * Clave publica ML-KEM del destinatario, recuperada de nuestra clave de
	 * desencapsulacion. Esto contrasta el par almacenado, de modo que una
	 * serializacion manipulada o incoherente se detecta antes de que alguien
	 * intente cifrar hacia nosotros.
	 */
	obtenerKemPublico(): ParPublico;
	/** Sella un secreto compartido para el dueno de `kemPublicoReceptor`. */
	encapsular(kemPublicoReceptor: ParPublico): SobreKem;
	/** Recupera el secreto compartido de un ciphertext dirigido a nosotros. */
	decapsular(cipherText: Uint8Array): Uint8Array;
	/** Deriva la clave simetrica de 32 bytes de un ciphertext dirigido a nosotros. */
	derivarClaveSimetricaDesde(cipherText: Uint8Array): Promise<Uint8Array>;
}

// ─── HELPERS DE HASH (WebCrypto) ────────────────────────────────────────────

function concatBytes(...partes: Uint8Array[]): Uint8Array {
	const total = partes.reduce((n, p) => n + p.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of partes) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

async function sha256(datos: Uint8Array): Promise<Uint8Array> {
	// Copiamos en un ArrayBuffer nuevo: `datos` puede ser una vista sobre un
	// backing store mayor y no tipado como ArrayBuffer, que subtle.digest rechaza.
	const buffer = new ArrayBuffer(datos.length);
	new Uint8Array(buffer).set(datos);
	return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
}

// ─── GENERATE ──────────────────────────────────────────────────────────────

/**
 * Genera un keypair de nodo: un par de firma ML-DSA-65 **y** un par de
 * encapsulacion ML-KEM-768. Ambos hacen falta para una identidad de malla
 * utilizable: el par de firma prueba quien eres, el par KEM permite que otros
 * te hablen en privado.
 */
export function generateKeypair(
	tipo: TipoIdentidad = TIPO_IDENTIDAD.EPHEMERA,
): PostQuantumKeypair {
	const { secretKey, publicKey } = ml_dsa65.keygen();
	const kem = ml_kem768.keygen();

	return {
		parPrivado: secretKey,
		parPublico: publicKey,
		kemPrivado: kem.secretKey,
		kemPublico: kem.publicKey,
		algoritmo: ALGORITMO,
		tipo,
		fechaCreacion: Date.now(),
	};
}

/**
 * Garantiza que el keypair lleve un par ML-KEM utilizable.
 *
 * Un keypair restaurado de la serializacion legacy (escrita antes de que
 * existiera ML-KEM) no tiene material KEM. En vez de dejar el cifrado
 * indisponible, generamos un par KEM nuevo: se preserva la identidad de firma y,
 * como el nodoId se deriva de la clave KEM, un nodo legacy reporta un id
 * derivado distinto tras la migracion — que es exactamente lo que hace que la
 * rotacion sea auditable y no silenciosa.
 */
function conKem(keypair: PostQuantumKeypair): PostQuantumKeypair {
	if (keypair.kemPrivado && keypair.kemPublico) return keypair;
	const kem = ml_kem768.keygen();
	return { ...keypair, kemPrivado: kem.secretKey, kemPublico: kem.publicKey };
}

// ─── NODO ID DERIVADO ──────────────────────────────────────────────────────

/**
 * Deriva un identificador de nodo de forma determinista desde una clave publica
 * ML-KEM-768.
 *
 * Esta es la correccion anti-suplantacion: un nodo no puede elegir, heredar ni
 * adivinar el id de otro, porque el id *es* el hash de la clave que ese nodo debe
 * presentar para probar posesion. Dos claves distintas nunca producen el mismo id
 * con probabilidad significativa, y ninguna clave produce el id de otro.
 *
 * Formato: `mlkem<32 hex>` (primeros 16 bytes de SHA-256, con separacion de
 * dominio).
 */
export async function derivarNodoId(kemPublico: ParPublico): Promise<NodoId> {
	if (!(kemPublico instanceof Uint8Array) || kemPublico.length === 0) {
		throw new TypeError(
			"derivarNodoId: ML-KEM public key must be a non-empty Uint8Array",
		);
	}
	const prefijo = new TextEncoder().encode(DOMINIO_NODO_ID);
	const digest = await sha256(concatBytes(prefijo, kemPublico));
	return `${PREFIJO_NODO_DERIVADO}${bytesAHex(digest.slice(0, BYTES_NODO_ID))}` as NodoId;
}

/** True cuando `nodoId` tiene la forma de un id derivado. Filtro barato. */
export function esNodoIdDerivado(nodoId: string): boolean {
	return (
		nodoId.startsWith(PREFIJO_NODO_DERIVADO) &&
		nodoId.length === PREFIJO_NODO_DERIVADO.length + BYTES_NODO_ID * 2
	);
}

/**
 * Verifica que `nodoId` sea realmente el id derivado de la clave ML-KEM de este
 * nodo.
 *
 * Nodos legacy (ids asignados antes de esta correccion, p. ej. `'doctor-01'`)
 * devuelven `false` aqui y los maneja la ruta de migracion de abajo, no un
 * rechazo.
 */
export async function verificarNodoIdVinculado(
	nodoId: NodoId,
	kemPublico: ParPublico,
): Promise<boolean> {
	if (!esNodoIdDerivado(nodoId)) return false;
	return (await derivarNodoId(kemPublico)) === nodoId;
}

// ─── MIGRACION DE NODO IDS LEGACY (ASIGNADOS A MANO) ───────────────────────

export type EstadoVinculoNodoId =
	/** el id es el hash de la clave ML-KEM: ligado criptograficamente, nada que hacer. */
	| { readonly estado: "vinculado" }
	/** id libre legacy de antes de existir los ids derivados; se acepta y se fija. */
	| { readonly estado: "heredado"; readonly idEsperado: NodoId }
	/** id legacy que no es el derivado, y el llamador no dio opt-in. */
	| { readonly estado: "conflicto"; idEsperado: NodoId };

/**
 * Decide que hacer con un nodo id configurado antes de que existieran los ids
 * derivados. **Nunca se sobrescribe nada en silencio.**
 *
 * - Id derivado que coincide con la clave → `vinculado`.
 * - Id no derivado (libre) → `heredado`: el nodo sigue funcionando con su id
 *   configurado, y fijamos ese id en el almacen de confianza para que una
 *   rotacion posterior de identidad no pueda moverlo. `idEsperado` es el id
 *   derivado a adoptar cuando el nodo rote su clave.
 * - Id con forma derivada que NO coincide con la clave → `conflicto`: eso es un
 *   intento de suplantacion (reclamar el id derivado de otro nodo), y el
 *   llamador debe negarse.
 *
 * @param permitirHeredado opt-in para nodos legacy. Los llamadores legacy que
 *   pasan un id configurado (la forma previa `createPostQuantumIdentity(nodoId)`)
 *   deben ponerlo en `true`; el default es `false`, es decir, fallar cerrado.
 */
export async function evaluarVinculoNodoId(
	nodoId: NodoId,
	kemPublico: ParPublico,
	permitirHeredado = false,
): Promise<EstadoVinculoNodoId> {
	const idEsperado = await derivarNodoId(kemPublico);
	if (idEsperado === nodoId) return { estado: "vinculado" };
	if (esNodoIdDerivado(nodoId)) return { estado: "conflicto", idEsperado };
	if (permitirHeredado) return { estado: "heredado", idEsperado };
	return { estado: "conflicto", idEsperado };
}

// ─── DERIVACION DE SECRETO COMPARTIDO ──────────────────────────────────────

/**
 * Convierte un secreto compartido ML-KEM-768 en una clave simetrica de 32 bytes
 * apta para AEAD (AES-GCM / ChaCha20-Poly1305).
 *
 * El secreto compartido crudo de ML-KEM son 32 bytes de material de clave;
 * hashearlo con un separador de dominio evita que se use directamente como clave
 * de AEAD sin este paso, y lo mantiene distinto de cualquier otro valor derivado.
 *
 * Exportado para la capa de cifrado: este es el unico lugar donde el secreto
 * ML-KEM de un nodo se vuelve material de cifrado.
 */
export async function derivarClaveSimetrica(
	sharedSecret: Uint8Array,
): Promise<Uint8Array> {
	const prefijo = new TextEncoder().encode(DOMINIO_CLAVE_COMPARTIDA);
	return sha256(concatBytes(prefijo, sharedSecret));
}

// ─── IDENTITY IMPLEMENTATION ───────────────────────────────────────────────

class PostQuantumIdentityImpl implements PostQuantumIdentity {
	readonly nodoId: NodoId;
	readonly keypair: PostQuantumKeypair;

	constructor(nodoId: NodoId, keypair: PostQuantumKeypair) {
		this.nodoId = nodoId;
		this.keypair = conKem(keypair);
	}

	async firmar(datos: Uint8Array): Promise<Uint8Array> {
		// @noble/post-quantum ML-DSA: sign(message, secretKey)
		return ml_dsa65.sign(datos, this.keypair.parPrivado);
	}

	async verificar(
		datos: Uint8Array,
		firma: Uint8Array,
		parPublico: ParPublico,
	): Promise<boolean> {
		try {
			// @noble/post-quantum ML-DSA: verify(signature, message, publicKey)
			return ml_dsa65.verify(firma, datos, parPublico);
		} catch {
			return false;
		}
	}

	async sign(data: string): Promise<string> {
		const bytes = new TextEncoder().encode(data);
		const firmaBytes = await this.firmar(bytes);
		return bytesAHex(firmaBytes);
	}

	async verify(
		data: string,
		signature: string,
		publicKey: Uint8Array,
	): Promise<boolean> {
		try {
			const bytes = new TextEncoder().encode(data);
			const firmaBytes = hexABytes(signature);
			return await this.verificar(bytes, firmaBytes, publicKey);
		} catch {
			return false;
		}
	}

	exportarPublico(): ParPublico {
		return new Uint8Array(this.keypair.parPublico);
	}

	obtenerAlgoritmo(): string {
		return this.keypair.algoritmo;
	}

	// ── ML-KEM-768: confidencialidad ──

	private kemPrivate(): Uint8Array {
		if (!this.keypair.kemPrivado)
			throw new Error("ML-KEM decapsulation key missing");
		return this.keypair.kemPrivado;
	}

	exportarKemPublico(): ParPublico {
		if (!this.keypair.kemPublico)
			throw new Error("ML-KEM encapsulation key missing");
		return new Uint8Array(this.keypair.kemPublico);
	}

	/**
	 * Nuestra clave publica ML-KEM, recalculada desde la privada. Contrasta el par
	 * almacenado, de modo que una serializacion manipulada o incoherente se
	 * detecta antes de que alguien intente cifrar hacia nosotros.
	 */
	obtenerKemPublico(): ParPublico {
		return ml_kem768.getPublicKey(this.kemPrivate());
	}

	encapsular(kemPublicoReceptor: ParPublico): SobreKem {
		const { cipherText, sharedSecret } =
			ml_kem768.encapsulate(kemPublicoReceptor);
		return { cipherText, claveCompartida: sharedSecret };
	}

	decapsular(cipherText: Uint8Array): Uint8Array {
		return ml_kem768.decapsulate(cipherText, this.kemPrivate());
	}

	async derivarClaveSimetricaDesde(
		cipherText: Uint8Array,
	): Promise<Uint8Array> {
		return derivarClaveSimetrica(this.decapsular(cipherText));
	}
}

// ─── FACTORY ───────────────────────────────────────────────────────────────

/**
 * Crea una identidad para un nodo.
 *
 * El argumento `nodoId` se conserva por compatibilidad de cable y almacen. Para
 * nodos NUEVOS prefiere `crearIdentidadVinculada(keypair)`, que deriva el id de
 * la clave ML-KEM para que no pueda suplantarse. Un `nodoId` pasado aqui es
 * siempre un id legacy; llama a `evaluarVinculoNodoId` para comprobarlo y fija el
 * resultado en el almacen de confianza.
 */
export function createPostQuantumIdentity(
	nodoId: NodoId,
	keypair?: PostQuantumKeypair,
): PostQuantumIdentity {
	const kp = keypair ?? generateKeypair();
	return new PostQuantumIdentityImpl(nodoId, kp);
}

/**
 * Crea una identidad cuyo `nodoId` ES el hash de su propia clave publica
 * ML-KEM-768. Este es el constructor recomendado: el nodo puede probar que posee
 * el id y nadie mas puede acuñarlo.
 *
 * @throws si el `nodoId` del keypair (si lo hay) conflicto con el derivado — un
 *   id derivado reclamado que no coincide con la clave es un intento de
 *   suplantacion y no debe emparentarse.
 */
export async function crearIdentidadVinculada(
	keypair?: PostQuantumKeypair,
): Promise<PostQuantumIdentity> {
	const kp = conKem(keypair ?? generateKeypair());
	const nodoId = await derivarNodoId(kp.kemPublico as ParPublico);
	return new PostQuantumIdentityImpl(nodoId, kp);
}

// ─── UTILITY ───────────────────────────────────────────────────────────────

/**
 * Restaura una identidad desde un **keypair serializado** producido por
 * `serializeKeypair`. Pasar solo una clave privada cruda e incoherente es
 * inseguro y ya no se soporta.
 *
 * Para una identidad aleatoria nueva usa `createPostQuantumIdentity(nodoId)`, o
 * `crearIdentidadVinculada()` para obtener un id que no se pueda suplantar.
 */
export function identityFromSecret(
	nodoId: NodoId,
	semilla: Uint8Array,
	tipo: TipoIdentidad = TIPO_IDENTIDAD.EPHEMERA,
): PostQuantumIdentity {
	// Preferimos la ruta de deserializacion cuando los bytes parecen nuestro formato
	// de serializacion (prefijos de longitud).
	if (semilla.length >= 8) {
		try {
			const view = new DataView(
				semilla.buffer,
				semilla.byteOffset,
				semilla.byteLength,
			);
			const privLen = view.getUint32(0, true);
			const pubLen = view.getUint32(4, true);
			if (
				privLen > 0 &&
				pubLen > 0 &&
				8 + privLen + pubLen === semilla.length
			) {
				const parPrivado = semilla.slice(8, 8 + privLen);
				const parPublico = semilla.slice(8 + privLen, 8 + privLen + pubLen);
				return createPostQuantumIdentity(nodoId, {
					parPrivado,
					parPublico,
					algoritmo: ALGORITMO,
					tipo,
					fechaCreacion: Date.now(),
				});
			}
			// El layout v2 anade la clave de desencapsulacion ML-KEM tras las de firma.
			if (semilla.length >= 12) {
				const kemPrivLen = view.getUint32(8, true);
				if (
					privLen > 0 &&
					pubLen > 0 &&
					kemPrivLen > 0 &&
					12 + privLen + pubLen + kemPrivLen === semilla.length
				) {
					const parPrivado = semilla.slice(12, 12 + privLen);
					const parPublico = semilla.slice(12 + privLen, 12 + privLen + pubLen);
					const kemPrivado = semilla.slice(12 + privLen + pubLen);
					return createPostQuantumIdentity(nodoId, {
						parPrivado,
						parPublico,
						kemPrivado,
						kemPublico: ml_kem768.getPublicKey(kemPrivado),
						algoritmo: ALGORITMO,
						tipo,
						fechaCreacion: Date.now(),
					});
				}
			}
		} catch {
			// fall through
		}
	}

	// Inseguro: clave privada propia sin clave publica que coincida. Se rechaza y
	// se acuña un par coherente. Los llamadores que dependian de esta ruta deben
	// migrar a serializeKeypair.
	return createPostQuantumIdentity(nodoId, generateKeypair(tipo));
}

function bytesToBase64(bytes: Uint8Array): string {
	// Chunk to avoid call-stack limits on large ML-DSA keys
	let binary = "";
	const chunk = 0x8000;
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
	}
	return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
	const binary = atob(b64);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		out[i] = binary.charCodeAt(i);
	}
	return out;
}

export { base64ToBytes, bytesToBase64 };

/**
 * Serializa un keypair a un unico string. Layout v2:
 *
 *   u32 privLen | u32 pubLen | u32 kemPrivLen | priv | pub | kemPriv
 *
 * La clave publica ML-KEM NO se almacena: se recupera de `kemPriv` via
 * `ml_kem768.getPublicKey`, de modo que las dos nunca pueden discrepar en disco.
 *
 * El layout v1 (solo claves de firma, 8 bytes de cabecera) sigue siendo legible:
 * `deserializeKeypair` lo detecta y genera un par KEM nuevo, igual que
 * `conKem`. Un despliegue existente no pierde su identidad de firma al migrar.
 */
export function serializeKeypair(keypair: PostQuantumKeypair): string {
	const kp = conKem(keypair);
	const privLen = kp.parPrivado.length;
	const pubLen = kp.parPublico.length;
	const kemPrivLen = (kp.kemPrivado as Uint8Array).length;
	const bytes = new Uint8Array(12 + privLen + pubLen + kemPrivLen);
	const view = new DataView(bytes.buffer);
	view.setUint32(0, privLen, true);
	view.setUint32(4, pubLen, true);
	view.setUint32(8, kemPrivLen, true);
	bytes.set(kp.parPrivado, 12);
	bytes.set(kp.parPublico, 12 + privLen);
	bytes.set(kp.kemPrivado as Uint8Array, 12 + privLen + pubLen);
	return bytesToBase64(bytes);
}

export function deserializeKeypair(serializada: string): PostQuantumKeypair {
	const raw = base64ToBytes(serializada);
	const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
	const privLen = view.getUint32(0, true);
	const pubLen = view.getUint32(4, true);

	// Layout v2 (con ML-KEM) o layout legacy v1 (solo claves de firma).
	const kemPrivLen = raw.length >= 12 ? view.getUint32(8, true) : 0;
	const tieneKem =
		kemPrivLen > 0 && 12 + privLen + pubLen + kemPrivLen === raw.length;
	const base = tieneKem ? 12 : 8;

	const parPrivado = raw.slice(base, base + privLen);
	const parPublico = raw.slice(base + privLen, base + privLen + pubLen);
	const kemPrivado = tieneKem ? raw.slice(base + privLen + pubLen) : undefined;

	return {
		parPrivado,
		parPublico,
		...(kemPrivado
			? { kemPrivado, kemPublico: ml_kem768.getPublicKey(kemPrivado) }
			: {}),
		algoritmo: ALGORITMO,
		tipo: TIPO_IDENTIDAD.EPHEMERA,
		fechaCreacion: Date.now(),
	};
}
