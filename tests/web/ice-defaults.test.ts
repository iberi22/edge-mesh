import { describe, expect, it } from "vitest";
import { DEFAULT_ICE_SERVERS } from "../../src/web/ice.js";
import { qrSdpTransport } from "../../src/web/transports/qr-sdp.js";
import { connectViaSignaling } from "../../src/web/webrtc.js";
import { b64uEncode, utf8 } from "../../src/web/util.js";
import { importAesKey, sealUpdate } from "../../src/web/crypto.js";

let capturedIceServers: RTCIceServer[] | undefined;

class FakeRTCPeerConnection {
	constructor(config?: RTCConfiguration) {
		capturedIceServers = config?.iceServers as RTCIceServer[] | undefined;
	}
	createDataChannel() { return { addEventListener: () => {} }; }
	setLocalDescription() { return Promise.resolve(); }
	createOffer() { return Promise.resolve({}); }
	setRemoteDescription() { return Promise.resolve(); }
	createAnswer() { return Promise.resolve({}); }
	addEventListener() {}
	close() {}
	get localDescription() { return { sdp: "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=ice-options:trickle\r\na=candidate:1 1 udp 2113937151 192.168.1.5 5000 typ host\r\na=fingerprint:sha-256 AA:BB" }; }
}

const mockRTC = FakeRTCPeerConnection as any as typeof RTCPeerConnection;
const mockSig = { join: () => Promise.resolve(), onMessage: () => () => {}, send: () => Promise.resolve(), addEventListener: () => {}, removeEventListener: () => {}, readyState: "open" } as any;

describe("ICE Defaults", () => {
	it("webrtc default gives DEFAULT_ICE_SERVERS", async () => {
		capturedIceServers = undefined;
		let cb: any;
		mockSig.onMessage = (fn: any) => { cb = fn; return () => {}; };
		const key = await importAesKey(new Uint8Array(32));
		await connectViaSignaling(mockSig, { selfId: "a", rid: "b", key, onPeer: () => {}, rtc: { RTCPeerConnection: mockRTC } });
		try { await cb({ type: "join", rid: "b", from: "c", to: "a", payload: "" }); } catch (e) {}
		expect(capturedIceServers).toEqual(DEFAULT_ICE_SERVERS);
	});

	it("webrtc explicit [] gives []", async () => {
		capturedIceServers = undefined;
		let cb: any;
		mockSig.onMessage = (fn: any) => { cb = fn; return () => {}; };
		const key = await importAesKey(new Uint8Array(32));
		await connectViaSignaling(mockSig, { selfId: "a", rid: "b", key, onPeer: () => {}, rtc: { iceServers: [], RTCPeerConnection: mockRTC } });
		try { await cb({ type: "join", rid: "b", from: "c", to: "a", payload: "" }); } catch (e) {}
		expect(capturedIceServers).toEqual([]);
	});

	it("webrtc custom list passes through", async () => {
		capturedIceServers = undefined;
		const custom = [{ urls: "stun:custom.stun" }];
		let cb: any;
		mockSig.onMessage = (fn: any) => { cb = fn; return () => {}; };
		const key = await importAesKey(new Uint8Array(32));
		await connectViaSignaling(mockSig, { selfId: "a", rid: "b", key, onPeer: () => {}, rtc: { iceServers: custom, RTCPeerConnection: mockRTC } });
		try { await cb({ type: "join", rid: "b", from: "c", to: "a", payload: "" }); } catch (e) {}
		expect(capturedIceServers).toEqual(custom);
	});

	it("qr-sdp default gives []", async () => {
		capturedIceServers = undefined;
		const tp = qrSdpTransport({ rtc: { RTCPeerConnection: mockRTC } });
		await tp.createOffer();
		expect(capturedIceServers).toEqual([]);
	});

	it("qr-sdp custom list passes through", async () => {
		capturedIceServers = undefined;
		const custom = [{ urls: "stun:custom.stun" }];
		const tp = qrSdpTransport({ rtc: { iceServers: custom, RTCPeerConnection: mockRTC } });
		await tp.createOffer();
		expect(capturedIceServers).toEqual(custom);
	});
});
