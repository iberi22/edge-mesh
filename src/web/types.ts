import type { Role } from "./admission.js";
import type { MeshStore } from "./store.js";

/** Minimal vault contract. An adapter comes from @swal/vault/web (not a dependency here). */
export interface VaultClient {
	readonly deviceId: string;
	/** Public identity key of this device (raw bytes, whatever scheme `verify` understands). */
	readonly devicePublicKey: Uint8Array;
	getOrCreateMeshKey(): Promise<Uint8Array>;
	setMeshKey(raw: Uint8Array): Promise<void>;
	sign(data: Uint8Array): Promise<Uint8Array>;
	verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
	/**
	 * Optional: persistent static P-256 ECDH key of this device (non-extractable private key + raw public key),
	 * used to wrap rotated mesh keys pairwise. Without it the mesh keeps an in-memory key for the session only,
	 * so a device that reloads while peers hold wraps for its old key cannot catch up: provide it in production.
	 */
	getEcdhIdentity?(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }>;
	/**
	 * Optional: persist the rotation epoch (otherwise it lives in the mesh's device-local store). The epoch is never
	 * taken from the shared doc.
	 */
	getEpoch?(): Promise<number> | number;
	setEpoch?(epoch: number): Promise<void> | void;
	/**
	 * Optional: persistent, device-local key/value store for the mesh's trust state (pinned root, verified
	 * admissions, revocations). Used when MeshOptions.store is not given. Without either (and without
	 * persist:'idb') that state lives in memory only and a reloaded device must be paired again.
	 */
	store?: MeshStore;
}

/** A bidirectional message pipe to one remote peer (WebRTC data channel, loopback, ...). */
export interface PeerLink {
	readonly id: string;
	send(data: Uint8Array): void;
	onMessage(cb: (data: Uint8Array) => void): void;
	onClose(cb: () => void): void;
	close(): void;
	/**
	 * Optional backpressure (BL3): resolves when the link's own send queue is low again. The mesh awaits it before
	 * handing over each frame, so a large message is paced by the peer instead of piling up in memory.
	 */
	drain?(): Promise<void>;
}

/** Wire message of the signaling protocol (see docs/SIGNALING-PROTOCOL.md). */
export interface SigMessage {
	type: "join" | "signal" | "leave";
	rid: string;
	from: string;
	to?: string;
	/** opaque, base64url, encrypted client-side; the server never parses it */
	payload?: string;
}

/** A signaling server/channel: peers exchange SigMessages, we build WebRTC links on top. */
export interface SignalingChannel {
	readonly kind: "signal";
	readonly name: string;
	join(rid: string, selfId: string): Promise<void>;
	send(msg: SigMessage): void;
	onMessage(cb: (msg: SigMessage) => void): () => void;
	leave(rid: string): void;
	close(): void;
}

/** A transport that hands out ready PeerLinks itself (qr-sdp, in-memory loopback). `rid` is '' when room-less. */
export interface LinkTransport {
	readonly kind: "link";
	readonly name: string;
	join(rid: string, selfId: string): Promise<void>;
	onLink(cb: (link: PeerLink, rid: string) => void): () => void;
	leave(rid: string): void;
	close(): void;
}

export type SigTransport = SignalingChannel | LinkTransport;

export interface Device {
	deviceId: string;
	/** base64url identity public key */
	pub: string;
	name: string;
	addedAt: number;
	/** Role from the device's verified admission (set by `Mesh.devices()`). */
	role?: Role;
	/** deviceId of the admitting device (set by `Mesh.devices()`). */
	admittedBy?: string;
}

export interface RtcOptions {
	/** Default [] = host candidates only (no public STUN). */
	iceServers?: RTCIceServer[];
	/** Injectable for tests / non-browser runtimes. */
	RTCPeerConnection?: typeof RTCPeerConnection;
}
