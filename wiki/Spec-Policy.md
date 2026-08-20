# Spec: Policy and packet filters

## 1. Policy file format

Crabscale accepts HUJSON: JSON plus `//` comments, `/* */` comments, and trailing commas.

Top-level keys:

- `groups`: map of group name to user list.
- `hosts`: map of alias to IP, CIDR, or subnet route owner.
- `acls`: ordered rules.
- `grants`: ordered capability grants.
- `tagOwners`: map of tag to list of users allowed to use it.
- `autoApprovers`: object with `routes` and `exitNode` maps.
- `ssh`: SSH check-mode rules.
- `nodeAttrs`: node attribute assignments.
- `tests` and `sshTests`: declarative tests.

Minimal allow-all policy:

```json5
{
  // Accept all node-to-node traffic.
  "acls": [
    { "action": "accept", "src": ["*"], "dst": ["*:*"] }
  ]
}
```

## 2. ACL compilation

Each rule has:

```json5
{
  "action": "accept",
  "src": ["alice@example.com", "tag:server", "group:eng", "100.64.0.1/32"],
  "dst": ["*:22,443"]
}
```

Compile to one or more packet filter rules:

```json
{
  "SrcIPs": ["100.64.0.1/32"],
  "DstPorts": [{ "First": 22, "Last": 22 }]
}
```

Rules:

- Rules are evaluated as allow rules; the default is deny.
- A wildcard source becomes `"*"`.
- Destination ports may be `*`, comma-separated ports, or ranges.
- IPv4 and IPv6 CIDRs are both supported.
- Empty compiled filter is serialized as `[]`, never omitted.

## 3. Peer visibility

A peer `P` appears in node `N`'s map only if at least one of these is true:

- Traffic `N -> P` is allowed.
- Traffic `P -> N` is allowed.

This prevents leaking peer metadata that the node cannot use.

## 4. Tags

- Tag names start with `tag:`.
- Only users listed in `tagOwners` may approve that tag.
- A pre-auth key carrying tags creates a tagged node owned by the tags, not by a user.
- Tagged nodes have no key expiry by default.
- A node requesting tags via `Hostinfo.RequestTags` is not retagged unless a tag owner approves.

## 5. Autogroups

Supported in v0.1:

- `autogroup:self`: matches only the evaluating node.
- `autogroup:member`: matches members of the evaluating user's own groups.
- `autogroup:tagged`: matches all tagged nodes.

Unsupported initially: `autogroup:admin` and `autogroup:internet` for non-exit traffic.

## 6. Node attributes

`nodeAttrs` maps a target to attribute assignments:

```json5
{
  "nodeAttrs": [
    {
      "target": ["tag:server"],
      "attr": ["randomizeClientPort"]
    }
  ]
}
```

Attributes are emitted in the node's `CapMap` object. The full attribute vocabulary is defined by [Spec-Compatibility](Spec-Compatibility#2-capability-gated-fields).

## 7. Tailscale SSH

`ssh` rules have the same shape as ACLs but target users instead of ports:

```json5
{
  "ssh": [
    {
      "action": "check",
      "src": ["tag:client"],
      "dst": ["tag:server"],
      "users": ["root", "ubuntu"],
      "checkPeriod": "12h"
    }
  ]
}
```

- `action: accept` permits immediately.
- `action: check` uses the SSH check-mode endpoint defined in [Spec-Control-API](Spec-Control-API).
- `checkPeriod` is how long one approval is remembered for the same src/dst pair.

## 8. Policy tests

The parser must execute `tests.accept`/`deny` and `sshTests` against compiled policy and report failures. These tests run in CI, not only interactively.
