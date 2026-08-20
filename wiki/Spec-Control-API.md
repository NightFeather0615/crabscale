# Spec: Control API

All endpoints below are served inside the Noise-protected HTTP/2 connection unless marked "outer".

## Outer endpoints

### `GET /key?v=<capver>`

See [Spec-Transport](Spec-Transport#1-outer-key-endpoint).

### `POST /verify`

Used by an embedded DERP relay to ask whether a client node key belongs to this tailnet.

Request:

```json
{ "NodePublic": "nodekey:<64 lowercase hex chars>" }
```

Response:

```json
{ "Allow": true }
```

- Reject non-POST with `405`.
- Limit body to 4 KiB.
- Unknown node key returns `Allow: false`, not an error page.

### `HEAD /machine/ping-response?id=<opaque id>`

- `200` when the id is a valid outstanding ping id.
- `404` when unknown or expired.
- Other methods return `405`.

## Inner `/machine/*` endpoints

### `POST /machine/register`

Request body: JSON object defined in [Spec-Registration](Spec-Registration#2-wire-objects).

Response body: JSON object defined in [Spec-Registration](Spec-Registration#2-wire-objects).

Rules:

- Always send `Content-Type: application/json`.
- On success send `200` with the register response object.
- A pending interactive registration also returns `200`; the response contains an `AuthURL`, not an HTTP error.
- Body size limit: 1 MiB.

### `POST /machine/map`

Request body: JSON `MapRequest` object defined in [Spec-NetMap](Spec-NetMap#2-maprequest).

Response behavior:

- Non-streaming lite update (`stream=false`, `omitPeers=true`, `readOnly=false`): send `200` with an empty body.
- Other non-streaming requests: send `200` whose body is one framed MapResponse.
- Streaming requests: send `200`, then a sequence of framed MapResponse objects on the same body.
- Unknown node or machine-key mismatch: send `404`.
- Unsupported capability version: send `400`.

### `GET /machine/ssh/action/{srcNodeId}/to/{dstNodeId}`

Query parameters: `auth_id`, `ssh_user`, `local_user`.

Returns a JSON `SSHAction`:

```json
{
  "Accept": false,
  "Reject": false,
  "HoldAndDelegate": "https://<server>/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?auth_id=<id>",
  "Message": "approval required",
  "AllowAgentForwarding": true,
  "AllowLocalPortForwarding": true,
  "AllowRemotePortForwarding": true
}
```

Rules:

- The Noise machine key must equal the destination node machine key; otherwise `401`.
- Unknown source or destination node: `404`.
- Followup requests block until the auth id resolves or the client cancels.

### Stub endpoints

The following endpoints exist so compatible clients do not retry forever. Initial implementation returns `501 Not Implemented`:

- `POST /machine/set-dns`
- `PATCH /machine/set-device-attr`
- `POST /machine/audit-log`
- `POST /machine/id-token`
- `POST /machine/feature/query`
- `POST /machine/update-health`
- `POST /machine/c2n`
- `GET /machine/whoami` may return `{"machineKey":"mkey:...","protocolVersion":<n>}`.

## Load balancer hint header

Clients may send `Ts-Lb` with the node public key. Treat it as a hint only. The server must never use it for authorization; always use the Noise machine key and the JSON body.
