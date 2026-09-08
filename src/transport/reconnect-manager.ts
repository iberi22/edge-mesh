export const DEFAULT_HEARTBEAT_INTERVAL_MS = 15000;
export const DEFAULT_DISCONNECT_THRESHOLD_MS = 30000;

export interface ReconnectManagerOptions {
	/** Heartbeat ping interval in milliseconds (default: 15000) */
	readonly heartbeatIntervalMs?: number;
	/** Timeout threshold after which a peer is marked disconnected (default: 30000) */
	readonly disconnectThresholdMs?: number;
	/** Callback to send ping message to a peer */
	readonly sendPing?: (peerId: string) => void | Promise<void>;
	/** Callback to send pong response to a peer */
	readonly sendPong?: (peerId: string) => void | Promise<void>;
	/** Callback triggered when ICE renegotiation is required */
	readonly onRenegotiate?: (peerId: string, pc?: any) => void | Promise<void>;
	/** Callback triggered when a peer passes the disconnect threshold */
	readonly onDisconnect?: (peerId: string) => void | Promise<void>;
	/** Callback triggered when a peer re-establishes connection */
	readonly onReconnect?: (peerId: string) => void | Promise<void>;
}

export interface PeerReconnectState {
	readonly peerId: string;
	lastPingSent: number;
	lastPongReceived: number;
	iceConnectionState: string;
	isRenegotiating: boolean;
	heartbeatTimer?: ReturnType<typeof setInterval>;
	checkTimer?: ReturnType<typeof setInterval>;
	pc?: any;
	options?: ReconnectManagerOptions;
}

export interface HeartbeatPayload {
	type: "__ping__" | "__pong__";
	timestamp: number;
}

/**
 * ReconnectManager handles ping/pong heartbeats and automatic ICE candidate renegotiation
 * for WebRTC transport connections, specifically designed for mobile network resilience.
 */
export class ReconnectManager {
	private readonly globalOptions: ReconnectManagerOptions;
	private readonly peers: Map<string, PeerReconnectState>;

	constructor(options: ReconnectManagerOptions = {}) {
		this.globalOptions = {
			heartbeatIntervalMs: DEFAULT_HEARTBEAT_INTERVAL_MS,
			disconnectThresholdMs: DEFAULT_DISCONNECT_THRESHOLD_MS,
			...options,
		};
		this.peers = new Map();
	}

	/**
	 * Registers a peer connection for heartbeat keep-alives and ICE monitoring.
	 */
	trackPeer(
		peerId: string,
		pc?: any,
		peerCallbacks?: Partial<ReconnectManagerOptions>,
	): void {
		const now = Date.now();
		const options: ReconnectManagerOptions = {
			...this.globalOptions,
			...peerCallbacks,
		};

		// If peer already tracked, clear timers before replacing
		if (this.peers.has(peerId)) {
			this.untrackPeer(peerId);
		}

		const state: PeerReconnectState = {
			peerId,
			lastPingSent: 0,
			lastPongReceived: now,
			iceConnectionState: pc?.iceConnectionState || "connected",
			isRenegotiating: false,
			pc,
			options,
		};

		this.peers.set(peerId, state);

		if (pc && typeof pc.addEventListener === "function") {
			pc.addEventListener("iceconnectionstatechange", () => {
				this.handleIceStateChange(peerId, pc.iceConnectionState, pc).catch(
					() => {},
				);
			});
		} else if (pc && typeof pc.oniceconnectionstatechange !== "undefined") {
			const originalHandler = pc.oniceconnectionstatechange;
			pc.oniceconnectionstatechange = (event: any) => {
				if (typeof originalHandler === "function") {
					originalHandler.call(pc, event);
				}
				this.handleIceStateChange(peerId, pc.iceConnectionState, pc).catch(
					() => {},
				);
			};
		}

		this.startHeartbeat(peerId);
	}

	/**
	 * Stops monitoring and untracks a peer connection.
	 */
	untrackPeer(peerId: string): void {
		const state = this.peers.get(peerId);
		if (!state) return;

		this.stopHeartbeat(peerId);
		this.peers.delete(peerId);
	}

	/**
	 * Starts heartbeat timers for a tracked peer.
	 */
	startHeartbeat(peerId: string): void {
		const state = this.peers.get(peerId);
		if (!state) return;

		this.stopHeartbeat(peerId);

		const heartbeatInterval =
			state.options?.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
		const disconnectThreshold =
			state.options?.disconnectThresholdMs ?? DEFAULT_DISCONNECT_THRESHOLD_MS;

		// Timer to periodically send pings
		state.heartbeatTimer = setInterval(() => {
			this.sendHeartbeatPing(peerId);
		}, heartbeatInterval);

		// Timer to check if pong timeout exceeded
		const checkInterval = Math.min(heartbeatInterval, 5000);
		state.checkTimer = setInterval(() => {
			const now = Date.now();
			const elapsedSincePong = now - state.lastPongReceived;

			if (elapsedSincePong >= disconnectThreshold) {
				if (state.options?.onDisconnect) {
					try {
						state.options.onDisconnect(peerId);
					} catch {
						// Ignorar
					}
				}
			}
		}, checkInterval);
	}

	/**
	 * Stops heartbeat timers for a peer.
	 */
	stopHeartbeat(peerId: string): void {
		const state = this.peers.get(peerId);
		if (!state) return;

		if (state.heartbeatTimer) {
			clearInterval(state.heartbeatTimer);
			state.heartbeatTimer = undefined;
		}
		if (state.checkTimer) {
			clearInterval(state.checkTimer);
			state.checkTimer = undefined;
		}
	}

	/**
	 * Sends a heartbeat ping message to the specified peer.
	 */
	sendHeartbeatPing(peerId: string): void {
		const state = this.peers.get(peerId);
		if (!state) return;

		state.lastPingSent = Date.now();
		const sendPingFn = state.options?.sendPing;
		if (sendPingFn) {
			try {
				sendPingFn(peerId);
			} catch {
				// Ignorar
			}
		}
	}

	/**
	 * Process incoming message to check if it's a heartbeat ping/pong.
	 * Returns true if the message was handled as a heartbeat, false otherwise.
	 */
	processIncomingMessage(peerId: string, data: unknown): boolean {
		if (typeof data !== "object" || data === null) return false;

		const msg = data as Partial<HeartbeatPayload>;
		if (msg.type === "__ping__") {
			this.handlePing(peerId);
			return true;
		}
		if (msg.type === "__pong__") {
			this.handlePong(peerId);
			return true;
		}
		return false;
	}

	/**
	 * Handles receipt of a ping from a remote peer, responding with pong.
	 */
	handlePing(peerId: string): void {
		const state = this.peers.get(peerId);
		const sendPongFn = state?.options?.sendPong ?? this.globalOptions.sendPong;
		if (sendPongFn) {
			try {
				sendPongFn(peerId);
			} catch {
				// Ignorar
			}
		}
	}

	/**
	 * Handles receipt of a pong response from a remote peer.
	 */
	handlePong(peerId: string): void {
		const state = this.peers.get(peerId);
		if (!state) return;

		state.lastPongReceived = Date.now();
	}

	/**
	 * Record pong received (alias for handlePong).
	 */
	recordPong(peerId: string): void {
		this.handlePong(peerId);
	}

	/**
	 * Handles RTCPeerConnection iceConnectionState changes.
	 * On 'disconnected', triggers auto-renegotiation WITHOUT tearing down the channel session.
	 */
	async handleIceStateChange(
		peerId: string,
		newState: string,
		pc?: any,
	): Promise<void> {
		const state = this.peers.get(peerId);
		if (!state) return;

		const previousState = state.iceConnectionState;
		state.iceConnectionState = newState;

		if (
			(newState === "disconnected" || newState === "failed") &&
			!state.isRenegotiating
		) {
			state.isRenegotiating = true;
			try {
				const renegotiateFn =
					state.options?.onRenegotiate ?? this.globalOptions.onRenegotiate;

				if (renegotiateFn) {
					await renegotiateFn(peerId, pc || state.pc);
				} else if (pc || state.pc) {
					const peerConn = pc || state.pc;
					if (typeof peerConn.restartIce === "function") {
						peerConn.restartIce();
					} else if (typeof peerConn.createOffer === "function") {
						const offer = await peerConn.createOffer({ iceRestart: true });
						if (typeof peerConn.setLocalDescription === "function") {
							await peerConn.setLocalDescription(offer);
						}
					}
				}
			} catch {
				// ICE renegotiation attempt failed
			} finally {
				state.isRenegotiating = false;
			}
		} else if (newState === "connected" || newState === "completed") {
			state.isRenegotiating = false;
			state.lastPongReceived = Date.now();

			if (
				previousState === "disconnected" ||
				previousState === "failed" ||
				previousState === "checking"
			) {
				const reconnectFn =
					state.options?.onReconnect ?? this.globalOptions.onReconnect;
				if (reconnectFn) {
					try {
						reconnectFn(peerId);
					} catch {
						// Ignorar
					}
				}
			}
		}
	}

	/**
	 * Returns whether the specified peer is considered alive and connected.
	 */
	isPeerAlive(peerId: string): boolean {
		const state = this.peers.get(peerId);
		if (!state) return false;

		const disconnectThreshold =
			state.options?.disconnectThresholdMs ?? DEFAULT_DISCONNECT_THRESHOLD_MS;
		const elapsed = Date.now() - state.lastPongReceived;

		return (
			elapsed <= disconnectThreshold &&
			state.iceConnectionState !== "failed" &&
			state.iceConnectionState !== "closed"
		);
	}

	/**
	 * Returns current peer state if tracked.
	 */
	getPeerState(peerId: string): PeerReconnectState | undefined {
		return this.peers.get(peerId);
	}

	/**
	 * Clears all timers and untracks all peers.
	 */
	destroy(): void {
		for (const peerId of Array.from(this.peers.keys())) {
			this.untrackPeer(peerId);
		}
		this.peers.clear();
	}
}
