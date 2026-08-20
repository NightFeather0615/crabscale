# Spec: Registration and auth

## 1. Identities

- Machine key: long-term device identity, verified by the Noise handshake.
- Node key: WireGuard identity that appears in the tailnet.
- Disco key: discovery identity; may rotate.
- A node record is only valid when `machineKey + nodeKey` match the stored pair.

## 2. Wire objects

RegisterRequest, PascalCase JSON:

```json
{
  "Version": 130,
  "NodeKey": "nodekey:<64 hex>",
  "OldNodeKey": "",
  "NLKey": "",
  "Auth": { "AuthKey": "hskey-auth-<prefix>-<secret>" },
  "Expiry": "2026-11-20T00:00:00Z",
  "Followup": "",
  "Hostinfo": { "Hostname": "node1", "RequestTags": [] },
  "Ephemeral": false
}
```

RegisterResponse, PascalCase JSON:

```json
{
  "User": 1,
  "Login": 1,
  "NodeKeyExpired": false,
  "MachineAuthorized": true,
  "AuthURL": "",
  "Error": ""
}
```

## 3. Pre-auth keys

Format: `hskey-auth-{prefix}-{secret}`.

- Store `prefix` and a password hash of the secret. Never store or log the secret.
- Key properties: `reusable`, `ephemeral`, `expiration`, `revoked`, `tags`, `user`.
- Single-use keys are marked used after the first successful registration.

Validation order:

1. Key exists and hashes match.
2. Not revoked.
3. Not expired.
4. If not reusable, not already used.

## 4. Registration flows

### Auth-key registration

1. Parse `RegisterRequest`.
2. Find a node by `NodeKey`.
3. If the node exists and its machine key matches, return the existing registration state without consuming the key.
4. Otherwise validate the auth key and create the node.
5. Tagged keys create tagged nodes; user keys create user-owned nodes.
6. Return `MachineAuthorized: true`, `NodeKeyExpired: false`, and the user/login IDs.

### Interactive registration

1. Request has no valid auth key.
2. Create a random unguessable `authId`.
3. Store pending data: machine key, node key, hostinfo, expiry, created time.
4. Return `MachineAuthorized: false` and `AuthURL: https://<server>/register/<authId>`.
5. The user approves through the web page or admin CLI/API.
6. The client polls with `Followup` set to that URL.
7. On approval, create the node and return the authorized response.
8. If the pending entry expired, tell the client to start a new registration.

TTL defaults: pending registration 15 minutes, cache bounded by an LRU limit.

## 5. Logout and expiry

- A request with `Expiry` in the past is a logout.
- A request with no `Auth` and a zero `Expiry` for an existing node is a restart/relogin check; return current state.
- A future `Expiry` supplied by the client is rejected: clients may not extend their own key.
- Logging out an ephemeral node deletes it.
- Tagged nodes do not gain an expiry from logout; they remain until explicitly deleted or expired administratively.
- Expired nodes receive `NodeKeyExpired: true` and must re-authenticate.

## 6. Interactive auth cache

The cache is keyed by `authId` and stores a bounded verdict:

- `pending`: no decision yet.
- `approved(userId, tags?)`: create/update node.
- `rejected`: return an error response.

Cache operations are authenticated only by the unguessable `authId` and the original machine key. The followup path must verify that the requesting machine key equals the pending machine key.

## 7. OIDC extension

M2 adds OIDC as an approval source:

- `/oidc/callback` completes the browser flow.
- User profile is upserted from claims.
- Approved registration is delivered through the same auth cache as CLI approval.
- OIDC group membership is not used in ACL evaluation in v0.1.
