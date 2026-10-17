/**
 * Default STUN servers for WebRTC.
 *
 * Note: A public STUN server sees the client's public IP address.
 * To opt-out and restrict candidates to host only, explicitly pass
 * `iceServers: []` in the RtcOptions.
 */
export const DEFAULT_ICE_SERVERS: readonly RTCIceServer[] = [
	{ urls: "stun:stun.l.google.com:19302" },
];
