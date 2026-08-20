# Spec: Transport (TS2021 / Noise / HTTP2)

This page is normative. Implement exactly the byte layouts and limits below.

## 1. Outer key endpoint

`GET /key?v=<capability_version>`

Success response, `200` and `Content-Type: application/json`:

```json
{
  "legacyPublicKey": "",
  "publicKey": "mkey:<64 lowercase hex chars>"
}
```

Rules:

- `publicKey` is the long-term server key used by the Noise handshake.
- `legacyPublicKey` may be empty for modern clients.
- Missing or unsupported `v` returns `400` with a plain text body.
- Production must serve this endpoint over TLS. Plain HTTP is allowed only for local tests.

## 2. Connection upgrade

Endpoint:

- `POST /ts2021` for native clients.
- `GET /ts2021` for WebSocket clients.

Native request must contain:

```text
Upgrade: tailscale-control-protocol
Connection: upgrade
X-Tailscale-Handshake: <base64 standard encoding of the 101-byte init message>
```

Server behavior:

1. Reject missing/invalid headers with `400`.
2. Reply `101 Switching Protocols` with:
   - `Upgrade: tailscale-control-protocol`
   - `Connection: upgrade`
3. Switch the connection to the Noise responder handshake.

WebSocket behavior:

- Accept only subprotocol `tailscale-control-protocol`.
- The handshake bytes arrive in the `X-Tailscale-Handshake` query/form parameter, base64 encoded.
- Each binary WebSocket message is treated as a continuous byte stream for Noise records.

## 3. Noise handshake

Algorithm string: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.

Prologue bytes: `Tailscale Control Protocol v` followed by the decimal protocol version carried in the init message.

Initiation message, client to server, exactly 101 bytes:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 2 | protocol version, big-endian u16 |
| 2 | 1 | message type `0x01` |
| 3 | 2 | payload length, big-endian u16, always 96 |
| 5 | 32 | client ephemeral X25519 public key, cleartext |
| 37 | 48 | client static X25519 public key, encrypted |
| 85 | 16 | authentication tag |

Response message, server to client, exactly 51 bytes:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 | message type `0x02` |
| 1 | 2 | payload length, big-endian u16, always 48 |
| 3 | 32 | server ephemeral X25519 public key, cleartext |
| 35 | 16 | authentication tag |

The handshake follows the Noise IK pattern with the algorithm string above. Record nonces are 12 bytes: first 4 bytes zero, last 8 bytes are a big-endian counter starting at 0.

Limits:

- Init message length: exactly 101 bytes.
- Handshake timeout: 10 seconds.
- Server must reject unsupported capability versions before returning a session.

## 4. Noise record framing

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 | message type `0x04` |
| 1 | 2 | ciphertext length, big-endian u16 |
| 3 | N | ChaCha20-Poly1305 ciphertext |

- Maximum total record frame size is 4096 bytes including the 3-byte header.
- Writers must split plaintext into chunks that fit this limit.
- Readers must reject larger frames and frames with unexpected types.

## 5. Early payload

After the Noise handshake and before the HTTP/2 preface, the server sends:

```text
0xFF 0xFF 0xFF 'T' 'S' | u32 big-endian JSON length | JSON body
```

JSON body:

```json
{ "nodeKeyChallenge": "chalpub:<64 lowercase hex chars>" }
```

- The challenge is a fresh random X25519 public key per connection.
- Maximum JSON length is 1 MiB.
- The server then sends a standard HTTP/2 connection preface on the same byte stream.

## 6. HTTP/2 over Noise

One Noise connection carries one HTTP/2 connection.

- All `/machine/*` endpoints are served inside this HTTP/2 connection.
- The server attaches the machine public key from the Noise handshake to each request context.
- Clients must not be able to override that identity with HTTP headers.
- Unauthenticated request bodies are limited to 1 MiB before any JSON parsing.
