# Spec: DERP and STUN

## 1. Frame format

Every DERP frame:

```text
[1 byte frame type][4 byte big-endian payload length][payload]
```

Maximum packet payload: 64 KiB. Maximum frame body accepted from a client: 1 MiB.

Connection magic sent in the first server frame: the 8 UTF-8 bytes `DERP🔑` (`44 45 52 50 F0 9F 94 91`).

Protocol version on the wire: 2.

## 2. Frame types

| Type | Name | Direction | Payload |
| --- | --- | --- | --- |
| 0x01 | ServerKey | server -> client | 8-byte magic + 32-byte server public key |
| 0x02 | ClientInfo | client -> server | 32-byte client key + 24-byte nonce + encrypted JSON |
| 0x03 | ServerInfo | server -> client | 24-byte nonce + encrypted JSON |
| 0x04 | SendPacket | client -> server | 32-byte destination key + packet bytes |
| 0x05 | RecvPacket | server -> client | protocol v2: 32-byte source key + packet bytes |
| 0x06 | KeepAlive | server -> client | none |
| 0x07 | NotePreferred | server -> client | 1 byte: 0 or 1 |
| 0x08 | PeerGone | server -> client | 32-byte peer key + reason byte |
| 0x09 | PeerPresent | mesh/observer | peer key, optional IP/port and flags |
| 0x0A | ForwardPacket | mesh | 32-byte source + 32-byte destination + packet |
| 0x10 | WatchConns | mesh | none |
| 0x12 | Ping | server -> client | 8 bytes, echoed in Pong |
| 0x13 | Pong | client -> server | 8 bytes |
| 0x14 | Health | server -> client | UTF-8 message or empty |
| 0x15 | Restarting | server -> client | two u32 big-endian durations in ms |

## 3. Login flow

1. Server sends `ServerKey`.
2. Client sends `ClientInfo`; encrypted JSON contains at least the client's node key.
3. Server decrypts and validates the client.
4. Server sends `ServerInfo`; encrypted JSON contains `"Version": 2` and token bucket parameters.
5. Connection enters steady state.

Encryption uses the NaCl `crypto_box` construction (Curve25519 + XSalsa20-Poly1305) between client and server keys.

## 4. Steady state

- Server routes `SendPacket` to the destination connection and emits `RecvPacket`.
- Unknown destination emits `PeerGone` with reason `0x01`.
- When a peer disconnects, connected peers receive `PeerGone` reason `0x00`.
- Server sends keepalive roughly every 60 seconds plus jitter.
- Duplicate connections are allowed; the server marks non-preferred connections using `Health` and `NotePreferred`.

## 5. Transports

- `/derp` with `Upgrade: websocket`: DERP frames in binary WebSocket messages.
- `/derp` with `Upgrade: derp`: raw DERP after HTTP 101.
- `Derp-Fast-Start: 1` request header permits skipping the 101 headers for raw DERP.
- `Ideal-Node` request header is advisory only.

## 6. STUN

The server must answer RFC 5389 Binding requests with a Binding response, copying the transaction ID and including `XOR-MAPPED-ADDRESS`.

STUN runs on the configured UDP port and may share the DERP host entry.

## 7. DERP map object

A DERP map is distributed through MapResponse:

```json
{
  "Regions": {
    "900": {
      "RegionID": 900,
      "RegionCode": "crab",
      "RegionName": "Crabscale",
      "Avoid": false,
      "Nodes": [
        {
          "Name": "crab-1",
          "HostName": "derp.example.com",
          "DERPPort": 443,
          "STUNPort": 3478,
          "STUNOnly": false
        }
      ]
    }
  }
}
```

Rules:

- Region and node IDs must be stable across restarts when configured.
- `DERPPort` may equal the control server HTTPS port.
- Map changes are pushed as a MapResponse delta to all connected nodes.

## 8. Verify endpoint

See [Spec-Control-API](Spec-Control-API#post-verify).
