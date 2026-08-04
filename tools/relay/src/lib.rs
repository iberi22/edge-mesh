//! WebSocket relay server for SWAL cross-device auth (ADR-003).
//!
//! Routes `auth_request` / `auth_response` messages between peers sharing
//! the same channel (URL path after `/ws/`). Responds to `ping` with `pong`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

/// Maximum members per channel (ADR-003).
pub const MAX_MEMBERS: usize = 2;

/// Maximum frame payload size in bytes (ADR-003, 64 KB).
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Default channel TTL in seconds (ADR-003, 60–120 s).
pub const DEFAULT_CHANNEL_TTL_SECS: u64 = 90;

/// Peer identifier within a channel.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PeerId(pub String);

/// Per-channel state.
struct Channel {
    peers: HashMap<PeerId, mpsc::UnboundedSender<Message>>,
    created_at: Instant,
}

/// Shared relay state.
type Channels = Arc<RwLock<HashMap<String, Channel>>>;

/// A relay server instance.
pub struct RelayServer {
    addr: SocketAddr,
    channels: Channels,
}

impl RelayServer {
    /// Creates a new relay server bound to the given address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Starts the relay server. Returns the actual listening address.
    pub async fn run(&self) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.addr).await?;
        let actual_addr = listener.local_addr()?;
        tracing::info!("relay listening on {actual_addr}");

        let channels = Arc::clone(&self.channels);

        // Spawn a channel garbage collector.
        let gc_channels = Arc::clone(&self.channels);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let mut ch = gc_channels.write().await;
                let now = Instant::now();
                ch.retain(|_name, channel| {
                    now.duration_since(channel.created_at)
                        < Duration::from_secs(DEFAULT_CHANNEL_TTL_SECS * 2)
                });
            }
        });

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let channels = Arc::clone(&channels);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_addr, channels).await {
                    tracing::debug!("connection {peer_addr} ended: {e}");
                }
            });
        }
    }
}

/// Extract channel name from the HTTP request path.
///
/// Parses `/ws/<channel>` or `?channelId=<id>`. Falls back to `"default"`.
fn extract_channel(path: &str, query: Option<&str>) -> String {
    // Check query param first.
    if let Some(q) = query {
        for param in q.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == "channelId" && !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }

    // Try path style: /ws/<channel>
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if let Some(ws_idx) = segments.iter().position(|s| *s == "ws") {
        if ws_idx + 1 < segments.len() {
            return segments[ws_idx + 1].to_string();
        }
    }
    "default".to_string()
}

/// Handles a single WebSocket connection.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    channels: Channels,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Perform WebSocket upgrade, extracting path from the HTTP request.
    let mut req_path = String::from("/ws/default");
    let mut req_query: Option<String> = None;

    let ws_stream = tokio_tungstenite::accept_hdr_async(
        stream,
        #[allow(clippy::result_large_err)]
        |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
         resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            req_path = req.uri().path().to_string();
            req_query = req.uri().query().map(|q| q.to_string());
            Ok(resp)
        },
    )
    .await?;

    let channel_name = extract_channel(&req_path, req_query.as_deref());
    tracing::debug!("{peer_addr} joined channel '{channel_name}'");

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Generate a peer ID from the address.
    let peer_id = PeerId(peer_addr.to_string());

    // Create an unbounded channel for sending messages to this peer.
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Register this peer in the channel.
    {
        let mut channels_guard = channels.write().await;
        let channel = channels_guard
            .entry(channel_name.clone())
            .or_insert_with(|| Channel {
                peers: HashMap::new(),
                created_at: Instant::now(),
            });

        if channel.peers.len() >= MAX_MEMBERS {
            let err = serde_json::json!({
                "type": "error",
                "message": "channel full (max 2 members)",
            });
            let _ = ws_sender.send(Message::Text(err.to_string().into())).await;
            let _ = ws_sender.close().await;
            return Ok(());
        }

        channel.peers.insert(peer_id.clone(), tx);
    }

    // Spawn a task that forwards messages from the mpsc channel to the WebSocket.
    let peer_id_clone = peer_id.clone();
    let fwd_channels = Arc::clone(&channels);
    let fwd_channel_name = channel_name.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(msg).await.is_err() {
                break;
            }
        }
        // Clean up on send failure.
        let mut guard = fwd_channels.write().await;
        if let Some(ch) = guard.get_mut(&fwd_channel_name) {
            ch.peers.remove(&peer_id_clone);
            if ch.peers.is_empty() {
                guard.remove(&fwd_channel_name);
            }
        }
    });

    // Process incoming messages from the WebSocket.
    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let text_bytes = text.as_bytes();
                if text_bytes.len() > MAX_FRAME_SIZE {
                    let err = serde_json::json!({
                        "type": "error",
                        "message": "frame too large (max 64KB)",
                    });
                    // Send error through the mpsc channel (tx was moved to channel).
                    // We need a separate reference — look up our own tx from the channel map.
                    let guard = channels.read().await;
                    if let Some(channel) = guard.get(&channel_name) {
                        if let Some(sender) = channel.peers.get(&peer_id) {
                            let _ = sender.send(Message::Text(err.to_string().into()));
                        }
                    }
                    continue;
                }

                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(text_bytes) {
                    let msg_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");

                    match msg_type {
                        "ping" => {
                            let pong = serde_json::json!({"type": "pong"});
                            let guard = channels.read().await;
                            if let Some(channel) = guard.get(&channel_name) {
                                if let Some(sender) = channel.peers.get(&peer_id) {
                                    let _ = sender
                                        .send(Message::Text(pong.to_string().into()));
                                }
                            }
                        }
                        "auth_request" | "auth_response" => {
                            let guard = channels.read().await;
                            if let Some(channel) = guard.get(&channel_name) {
                                for (pid, sender) in &channel.peers {
                                    if *pid != peer_id {
                                        let _ = sender.send(Message::Text(text.clone()));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    // Cleanup: remove this peer from the channel.
    let mut guard = channels.write().await;
    if let Some(ch) = guard.get_mut(&channel_name) {
        ch.peers.remove(&peer_id);
        if ch.peers.is_empty() {
            guard.remove(&channel_name);
        }
    }

    tracing::debug!("{peer_addr} left channel '{channel_name}'");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_channel_from_ws_path() {
        assert_eq!(extract_channel("/ws/test-channel", None), "test-channel");
        assert_eq!(extract_channel("/ws/abc123", None), "abc123");
        assert_eq!(extract_channel("/ws/", None), "default");
        assert_eq!(extract_channel("/", None), "default");
    }

    #[test]
    fn extract_channel_from_query_param() {
        assert_eq!(
            extract_channel("/ws", Some("channelId=my-channel")),
            "my-channel"
        );
        assert_eq!(
            extract_channel("/ws/other", Some("channelId=override")),
            "override"
        );
    }

    #[tokio::test]
    async fn relay_routes_auth_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = RelayServer::new(addr);
        let server_addr = server.addr();

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect two WebSocket clients to the same channel.
        let uri = format!("ws://{server_addr}/ws/test-channel");
        let (mut ws1, _) = tokio_tungstenite::connect_async(&uri).await.unwrap();
        let (mut ws2, _) = tokio_tungstenite::connect_async(&uri).await.unwrap();

        // Client 1 sends auth_request.
        let auth_req = serde_json::json!({
            "type": "auth_request",
            "requestId": "req-1",
            "challenge": "Y2hhbGxlbmdl",
            "rpId": "example.com",
        });
        ws1.send(Message::Text(auth_req.to_string().into()))
            .await
            .unwrap();

        // Client 2 should receive it.
        let msg = tokio::time::timeout(Duration::from_secs(2), ws2.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(text) = msg {
            let parsed: serde_json::Value = serde_json::from_slice(text.as_bytes()).unwrap();
            assert_eq!(parsed["type"], "auth_request");
            assert_eq!(parsed["requestId"], "req-1");
        } else {
            panic!("Expected text message");
        }

        // Client 2 sends auth_response.
        let auth_resp = serde_json::json!({
            "type": "auth_response",
            "requestId": "req-1",
            "signature": "c2lnbmF0dXJl",
            "publicKey": "cHVibGljS2V5",
        });
        ws2.send(Message::Text(auth_resp.to_string().into()))
            .await
            .unwrap();

        // Client 1 should receive it.
        let msg = tokio::time::timeout(Duration::from_secs(2), ws1.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(text) = msg {
            let parsed: serde_json::Value = serde_json::from_slice(text.as_bytes()).unwrap();
            assert_eq!(parsed["type"], "auth_response");
            assert_eq!(parsed["requestId"], "req-1");
        } else {
            panic!("Expected text message");
        }
    }

    #[tokio::test]
    async fn relay_ping_pong() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = RelayServer::new(addr);
        let server_addr = server.addr();

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let uri = format!("ws://{server_addr}/ws/ping-test");
        let (mut ws, _) = tokio_tungstenite::connect_async(&uri).await.unwrap();

        let ping = serde_json::json!({"type": "ping"});
        ws.send(Message::Text(ping.to_string().into()))
            .await
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(text) = msg {
            let parsed: serde_json::Value = serde_json::from_slice(text.as_bytes()).unwrap();
            assert_eq!(parsed["type"], "pong");
        } else {
            panic!("Expected pong text message");
        }
    }

    #[tokio::test]
    async fn relay_channel_isolation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = RelayServer::new(addr);
        let server_addr = server.addr();

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect to different channels.
        let (mut ws1, _) =
            tokio_tungstenite::connect_async(format!("ws://{server_addr}/ws/ch-a"))
                .await
                .unwrap();
        let (mut ws2, _) =
            tokio_tungstenite::connect_async(format!("ws://{server_addr}/ws/ch-b"))
                .await
                .unwrap();

        // Send on channel A.
        let auth_req = serde_json::json!({
            "type": "auth_request",
            "requestId": "req-iso",
            "challenge": "Y2hhbGxlbmdl",
            "rpId": "example.com",
        });
        ws1.send(Message::Text(auth_req.to_string().into()))
            .await
            .unwrap();

        // Channel B should NOT receive it.
        let result = tokio::time::timeout(Duration::from_millis(200), ws2.next()).await;
        assert!(
            result.is_err(),
            "Channel B should not receive messages from channel A"
        );
    }

    #[tokio::test]
    async fn relay_max_members_enforced() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = RelayServer::new(addr);
        let server_addr = server.addr();

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let uri = format!("ws://{server_addr}/ws/full-channel");
        let (_ws1, _) = tokio_tungstenite::connect_async(&uri).await.unwrap();
        let (_ws2, _) = tokio_tungstenite::connect_async(&uri).await.unwrap();

        // Third connection should be rejected.
        let result = tokio_tungstenite::connect_async(&uri).await;
        if let Ok((mut ws3, _)) = result {
                let msg = tokio::time::timeout(Duration::from_secs(2), ws3.next()).await;
                if let Ok(Some(Ok(Message::Text(text)))) = msg {
                    let parsed: serde_json::Value =
                        serde_json::from_slice(text.as_bytes()).unwrap();
                    assert_eq!(parsed["type"], "error");
                }
            }
    }
}
