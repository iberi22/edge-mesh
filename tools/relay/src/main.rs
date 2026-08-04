use std::net::SocketAddr;
use std::str::FromStr;

use swal_relay::RelayServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr_str = std::env::var("RELAY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let addr = SocketAddr::from_str(&addr_str)?;

    let server = RelayServer::new(addr);
    let actual = server.run().await?;
    tracing::info!("relay ready on {actual}");

    // Keep the main task alive.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
