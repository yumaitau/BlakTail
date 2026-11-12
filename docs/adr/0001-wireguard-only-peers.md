# ADR 0001 — First topology for WireGuard-only peers

- Status: accepted for the first slice of #45
- Date: 2026-08-27

## Decision

The first supported WireGuard-only peer is a **constrained organisation-owned
endpoint whose public key is exported to every managed agent that current
policy already allows to reach it**.

BlakTail stores only the external public key, operator-approved endpoints,
bounded AllowedIPs, organisation, policy selectors, lifecycle, expiry, and
audit metadata. The private key never enters the coordinator, console,
Terraform state, or evidence bundles.

## Why this topology first

| Option | Scaling | Revocation | NAT / relay | Failure isolation |
| --- | --- | --- | --- | --- |
| Direct public-key export to selected managed nodes | Config grows with (managed nodes × WG-only peers) | Remove the peer from the next map; agents drop it on apply | Unmanaged endpoint must be reachable at its configured endpoint. No STUN, hole punch, or BlakTail relay. | A bad AllowedIP affects only nodes that received that peer. |
| Bounded managed gateway subset | Smaller fan-out | Same, plus gateway must stay up | Traffic hairpins through the gateway | Gateway is a blast radius and a new privilege boundary. |
| Route through a managed connector | Similar to gateway | Depends on #29/#49 route withdrawal | Hides the unmanaged endpoint from most nodes | Connector compromise sees that traffic. |

Direct export reuses the existing authenticated peer map. It does not invent a
new hop, does not require connector/app-routing work, and makes revocation the
same operation as removing a managed peer. The cost is honest: this is not a
mesh of unmanaged appliances, and it will not scale to thousands of WG-only
peers without a later gateway design.

## Limits that stay explicit

- Kind is stored as `wireguard_only`. It is never inferred from missing fields.
- Unmanaged peers do not get MagicDNS updates, last-seen/online state, relay
  fallback, posture, re-auth, or automatic key rotation unless a later issue
  implements that path.
- An unmanaged endpoint cannot enforce BlakTail ACL for traffic that originates
  behind it. Policy is applied on the managed side only.
- Default routes, overlapping prefixes, foreign organisation ranges, and
  multicast remain privileged and fail closed in this slice. A new peer's
  AllowedIPs may not overlap another live WireGuard-only peer, a route
  approved on a device or a network resource, and owned tags need the tag
  owner's authority, as they do on devices.
- Configuration export is a versioned public bundle: public keys, endpoints,
  AllowedIPs, revision, checksum. No node tokens, join keys, or private keys.

## Follow-up

The console now lists unmanaged peers separately from managed devices and
creates them with stored kind `wireguard_only`. Homelab
`deploy/homelab/prove-wg-only.sh` enrols one Linux agent and a vanilla
`wg` container (no `blaktaild`) and proves overlay ping both ways, then
revokes the peer. `deploy/homelab/prove-wg-rotate.sh` rotates the public key
with a bounded overlap so both keys stay exported until the window ends.
Kernel WireGuard can only route each AllowedIP to one peer, so the agent
keeps the already-installed key on the interface until overlap expires.
`deploy/homelab/prove-wg-only-services.sh` publishes a TCP 8080 allow next to
an implicit deny of 8081: the vanilla endpoint reaches 8080, 8081 is refused,
and the decision is the managed agent's `BLAKTAIL-ACL` INPUT chain. An
unmanaged endpoint cannot enforce BlakTail policy for traffic it originates.
This record only locks the first topology so later slices do not silently
grow into a gateway product.
