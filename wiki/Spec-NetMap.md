# Spec: NetMap protocol

## 1. Wire framing

A MapResponse body is framed as:

```text
u32 little-endian payload length | payload
```

Payload is JSON, or a single zstd frame containing JSON when the corresponding MapRequest has `compress: "zstd"`.

The server must flush each frame when streaming.

## 2. MapRequest

JSON uses PascalCase field names. Required fields for M0/M1 handling:

```json
{
  "Version": 130,
  "Compress": "",
  "KeepAlive": true,
  "NodeKey": "nodekey:<64 hex>",
  "DiscoKey": "discokey:<64 hex>",
  "Stream": true,
  "Hostinfo": {
    "Hostname": "node1",
    "RoutableIPs": ["10.0.0.0/24"],
    "RequestTags": [],
    "NetInfo": { "PreferredDERP": 1 }
  },
  "Endpoints": ["198.51.100.10:41641"],
  "EndpointTypes": [2],
  "OmitPeers": false,
  "ReadOnly": false,
  "TKAHead": ""
}
```

Semantics table:

| Condition | Server behavior |
| --- | --- |
| `stream=false`, `omitPeers=true`, `readOnly=false` | Update node state, respond `200` with empty body. |
| `stream=false`, other values | Update node state if allowed, respond with one full framed MapResponse. |
| `stream=true`, `version>=68` | Treat request as read-only; ignore `Hostinfo` and `Endpoints` for state updates. |
| `stream=true` | Register session, send complete first MapResponse, then deltas/keepalives. |
| `MapSessionHandle` and `MapSessionSeq` present | May be ignored in M0/M1; always start a new session. |

## 3. Initial MapResponse (complete frame)

A valid first frame must contain at least:

- `Node`: the requesting node.
- `DERPMap`: available relay regions.
- `Domain`: tailnet domain string.
- `Peers`: complete peer array. Use an explicit empty array `[]` when there are no peers.
- `PacketFilters`: object with at least key `"base"`.
- `UserProfiles`: profiles for the requesting user and peers.
- `ControlTime`: RFC3339Nano timestamp.

Example allow-all first frame:

```json
{
  "Node": {
    "ID": 1,
    "StableID": "n00000000000000000000001",
    "Name": "node1.tailnet.example.",
    "User": 1,
    "Key": "nodekey:<64 hex>",
    "Machine": "mkey:<64 hex>",
    "DiscoKey": "discokey:<64 hex>",
    "Addresses": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
    "AllowedIPs": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
    "Endpoints": ["198.51.100.10:41641"],
    "HomeDERP": 1,
    "Hostinfo": { "Hostname": "node1" },
    "Cap": 130,
    "Created": "2026-08-20T00:00:00Z"
  },
  "DERPMap": {
    "Regions": {
      "1": {
        "RegionID": 1,
        "RegionCode": "test",
        "RegionName": "Test",
        "Nodes": [
          {
            "Name": "test-1",
            "HostName": "derp.example.com",
            "DERPPort": 443,
            "STUNPort": 3478
          }
        ]
      }
    }
  },
  "Domain": "tailnet.example",
  "Peers": [],
  "PacketFilters": {
    "base": [
      {
        "SrcIPs": ["*"],
        "DstPorts": [{ "First": 0, "Last": 65535 }]
      }
    ]
  },
  "UserProfiles": [
    { "ID": 1, "LoginName": "owner@example.com", "DisplayName": "Owner" }
  ],
  "ControlTime": "2026-08-20T00:00:00Z"
}
```

## 4. Delta MapResponse

After the first frame, the server may send:

- `PeersChanged`: full node objects that changed or were added.
- `PeersRemoved`: array of node IDs.
- `PeersChangedPatch`: lightweight patches for endpoint, DERP region, key, disco key, online, last seen, key expiry, capabilities.
- `OnlineChange`: map of node ID to boolean.
- `PeerSeenChange`: map of node ID to boolean.

Rules:

- If `Peers` is present and non-empty, it replaces the peer list; delta fields in the same frame are ignored.
- Never send a delta before the initial complete frame.
- Keep peer arrays sorted by node ID.

## 5. Keepalive

When `KeepAlive` was requested, send:

```json
{ "KeepAlive": true }
```

Interval: 50 seconds plus a random jitter of 0 to 9 seconds.

## 6. Empty-slice rules

These wire fields distinguish "absent" from "explicitly empty":

- `Peers: []` means an authoritative empty peer list.
- `PacketFilter: []` means deny all.
- `PacketFilters: {}` alone means no change.

Serialization code must preserve this distinction; `serde` `skip_serializing_if` on `Option` alone is not sufficient.

## 7. Capability gates

| Capability version | Field/behavior |
| --- | --- |
| >= 68 | Streaming MapRequest is read-only. |
| >= 81 | `PacketFilters` incremental map format is preferred. |
| >= 111 | Node `HomeDERP` integer field is used instead of legacy DERP string. |
| >= 112 | `AllowedIPs: null` on a peer means "same as Addresses". |

The server maintains one minimum supported version. Unsupported versions are rejected at `/key` and `/machine/map`.
