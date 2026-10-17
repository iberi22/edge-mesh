/**
 * Default public STUN servers for WebRTC NAT traversal.
 *
 * Note: A STUN server sees the client's public IP address.
 * If privacy is a concern or you are on a same-LAN environment,
 * you can opt out and use host candidates only by passing `iceServers: []`.
 */
export const DEFAULT_ICE_SERVERS: RTCIceServer[] = [
	{ urls: "stun:stun.l.google.com:19302" },
];
