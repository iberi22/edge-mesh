import { describe, expect, it } from "vitest";
import { DEFAULT_ICE_SERVERS } from "../../src/web/ice.js";
import { qrSdpTransport } from "../../src/web/transports/qr-sdp.js";
import type { SignalingChannel } from "../../src/web/types.js";
import { connectViaSignaling } from "../../src/web/webrtc.js";

class FakeRTCPeerConnection {
	iceServers?: RTCIceServer[];
	ondatachannel: any;
	onconnectionstatechange: any;
	localDescription: any = { sdp: "dummy sdp" };
	constructor(config: RTCConfiguration = {}) {
		this.iceServers = config.iceServers;
	}
	createDataChannel() {
		return {
			readyState: "open",
			addEventListener: (e: any, cb: any) => {
				if (e === "open") cb();
			},
		};
	}
	createOffer() {
		return Promise.resolve({});
	}
	createAnswer() {
		return Promise.resolve({});
	}
	setLocalDescription() {
		return Promise.resolve();
	}
	setRemoteDescription() {
		return Promise.resolve();
	}
	close() {}
	addEventListener(e: string, cb: any) {
		if (e === "icegatheringstatechange") {
			cb();
		}
	}
	get iceGatheringState() {
		return "complete";
	}
}

const fakeKey = {} as CryptoKey;
const makeSignaling = (triggerJoin: (cb: any) => void) => ({
	send: () => {},
	onMessage: (cb: any) => {
		triggerJoin(cb);
		return () => {};
	},
	join: () => Promise.resolve(),
	leave: () => {},
});

describe("ICE Defaults", () => {
	describe("webrtc", () => {
		it("webrtc default gives DEFAULT_ICE_SERVERS", async () => {
			let createdPc: FakeRTCPeerConnection | undefined;
			class TestPc extends FakeRTCPeerConnection {
				constructor(config: RTCConfiguration = {}) {
					super(config);
					createdPc = this;
				}
			}

			const close = await connectViaSignaling(
				makeSignaling((cb) => {
					setTimeout(() => {
						cb({ type: "join", rid: "test", from: "other" }); // me < other, so "me" initiates
					}, 0);
				}),
				{
					rid: "test",
					selfId: "me",
					key: fakeKey,
					rtc: { RTCPeerConnection: TestPc as any },
					onLink: () => {},
				},
			);

			await new Promise((r) => setTimeout(r, 10)); // wait for join to trigger initiate

			expect(createdPc).toBeDefined();
			expect(createdPc?.iceServers).toEqual(DEFAULT_ICE_SERVERS);
			close();
		});

		it("webrtc explicit [] gives []", async () => {
			let createdPc: FakeRTCPeerConnection | undefined;
			class TestPc extends FakeRTCPeerConnection {
				constructor(config: RTCConfiguration = {}) {
					super(config);
					createdPc = this;
				}
			}

			const close = await connectViaSignaling(
				makeSignaling((cb) => {
					setTimeout(() => {
						cb({ type: "join", rid: "test", from: "other" });
					}, 0);
				}),
				{
					rid: "test",
					selfId: "me",
					key: fakeKey,
					rtc: { iceServers: [], RTCPeerConnection: TestPc as any },
					onLink: () => {},
				},
			);

			await new Promise((r) => setTimeout(r, 10));

			expect(createdPc).toBeDefined();
			expect(createdPc?.iceServers).toEqual([]);
			close();
		});

		it("webrtc custom list passes through", async () => {
			let createdPc: FakeRTCPeerConnection | undefined;
			class TestPc extends FakeRTCPeerConnection {
				constructor(config: RTCConfiguration = {}) {
					super(config);
					createdPc = this;
				}
			}

			const close = await connectViaSignaling(
				makeSignaling((cb) => {
					setTimeout(() => {
						cb({ type: "join", rid: "test", from: "other" });
					}, 0);
				}),
				{
					rid: "test",
					selfId: "me",
					key: fakeKey,
					rtc: {
						iceServers: [{ urls: "stun:custom" }],
						RTCPeerConnection: TestPc as any,
					},
					onLink: () => {},
				},
			);

			await new Promise((r) => setTimeout(r, 10));

			expect(createdPc).toBeDefined();
			expect(createdPc?.iceServers).toEqual([{ urls: "stun:custom" }]);
			close();
		});
	});

	describe("qr-sdp", () => {
		it("qr-sdp default gives []", async () => {
			let createdPc: FakeRTCPeerConnection | undefined;
			class TestPc extends FakeRTCPeerConnection {
				constructor(config: RTCConfiguration = {}) {
					super(config);
					createdPc = this;
				}
			}

			const tr = qrSdpTransport({ rtc: { RTCPeerConnection: TestPc as any } });
			await tr.createOffer();

			expect(createdPc).toBeDefined();
			expect(createdPc?.iceServers).toEqual([]);
		});

		it("qr-sdp custom list passes through", async () => {
			let createdPc: FakeRTCPeerConnection | undefined;
			class TestPc extends FakeRTCPeerConnection {
				constructor(config: RTCConfiguration = {}) {
					super(config);
					createdPc = this;
				}
			}

			const tr = qrSdpTransport({
				rtc: {
					iceServers: [{ urls: "stun:custom" }],
					RTCPeerConnection: TestPc as any,
				},
			});
			await tr.createOffer();

			expect(createdPc).toBeDefined();
			expect(createdPc?.iceServers).toEqual([{ urls: "stun:custom" }]);
		});
	});
});
