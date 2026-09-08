//! Synthetic Atlas server for local UI review — in-memory annotations, the demo routes seed,
//! no database and no egress. `main.rs` remains the only production entry point.

use std::net::SocketAddr;

use atlas::{app, build_dev_state};

const LISTEN_ADDR: &str = "127.0.0.1:9137";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = LISTEN_ADDR.parse().expect("fixed fixture address is valid");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind fixture server at {addr}: {error}"));

    tracing::info!(%addr, "Atlas synthetic fixture listening");
    axum::serve(listener, app(build_dev_state()))
        .await
        .expect("fixture server");
}
