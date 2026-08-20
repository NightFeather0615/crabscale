//! UDP STUN Binding server for the embedded relay (Spec-DERP-STUN §6).
//!
//! The relay listens on the configured UDP STUN port and answers RFC 5389
//! Binding requests with a Binding response that copies the transaction ID
//! and reports the sender's public address in `XOR-MAPPED-ADDRESS`.

use std::io;
use std::net::SocketAddr;

use crabscale_derp::stun::{build_binding_response, parse_binding_request};
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// Handle to a running STUN server, used to request shutdown.
#[derive(Clone, Debug)]
pub struct StunServerHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl StunServerHandle {
    /// Ask the STUN accept loop to stop and close the socket.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Bind a UDP socket on `addr` and answer STUN Binding requests.
///
/// Returns the actual bound address (useful when `addr` uses port 0) and a
/// handle that can be used to stop the server. The serving task runs in the
/// background until shutdown is requested.
pub async fn serve_stun(addr: SocketAddr) -> io::Result<(SocketAddr, StunServerHandle)> {
    let socket = UdpSocket::bind(addr).await?;
    let local = socket.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        // Datagrams larger than a normal STUN request are dropped.
        let mut buf = vec![0u8; 1500];
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                res = socket.recv_from(&mut buf) => {
                    let Ok((len, src)) = res else { continue };
                    let packet = &buf[..len];
                    // Only answer well-formed Binding requests; every other
                    // datagram is silently ignored.
                    let Ok(tx_id) = parse_binding_request(packet) else { continue };
                    let response = build_binding_response(tx_id, src.ip(), src.port());
                    let _ = socket.send_to(&response, src).await;
                }
            }
        }
    });
    Ok((local, StunServerHandle { shutdown_tx }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabscale_derp::stun::{TxId, parse_binding_response};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn stun_transaction_id_round_trips_over_udp() {
        let (addr, handle) = serve_stun("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Build a Binding request with an arbitrary transaction ID.
        let tx_id = TxId::from_bytes([0xAB, 0xCD, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut request = Vec::new();
        request.extend_from_slice(&[0x00, 0x01]); // Binding request
        request.extend_from_slice(&[0x00, 0x00]); // no attributes
        request.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        request.extend_from_slice(tx_id.as_bytes());

        socket.send_to(&request, addr).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (len, _from) = socket.recv_from(&mut buf).await.unwrap();

        let (parsed_tx, address, port) = parse_binding_response(&buf[..len]).unwrap();
        assert_eq!(parsed_tx, tx_id, "transaction ID must round-trip over UDP");
        assert_eq!(
            address,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "XOR-MAPPED-ADDRESS must report the observed source address"
        );
        assert_eq!(port, socket.local_addr().unwrap().port());

        handle.shutdown();
    }
}
