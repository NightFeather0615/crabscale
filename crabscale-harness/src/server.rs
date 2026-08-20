//! Server startup helper for the harness.

use std::net::SocketAddr;

use crabscale_control::{ControlConfig, ControlPlane};
use crabscale_proto::MachineKey;
use crabscale_server::{ControlRouter, ServerHandle, ServerKey, serve_on_addr};
use crabscale_transport::NoiseResponder;

use crate::config::HarnessConfig;

/// A running harness server.
pub struct RunningServer {
    /// The address the server is bound to.
    pub addr: SocketAddr,
    /// The control plane backing the server (for direct assertions).
    pub control: ControlPlane,
    /// The router used by the server.
    pub router: ControlRouter,
    /// Handle used to stop the outer accept loop.
    pub handle: ServerHandle,
}

/// Start a crabscale control server on localhost with the harness config.
///
/// The server is spawned as a background tokio task and returns once it is
/// listening. The caller is responsible for keeping the runtime alive and for
/// calling [`RunningServer::shutdown`] when done.
pub async fn start_server(config: &HarnessConfig) -> Result<RunningServer, String> {
    let control = ControlPlane::new(ControlConfig {
        auth_key: config.auth_key.clone(),
        tailnet_domain: config.tailnet.clone(),
        ..Default::default()
    });
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let router = ControlRouter::with_control(machine_key, control.clone());
    router.spawn_reaper();

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("static addr");
    let (addr, handle) = serve_on_addr(bind, router.clone(), server_key)
        .await
        .map_err(|e| format!("failed to start server: {e}"))?;

    Ok(RunningServer {
        addr,
        control,
        router,
        handle,
    })
}

impl RunningServer {
    /// Stop the server's accept loop.
    pub fn shutdown(&self) {
        self.handle.shutdown();
    }
}
