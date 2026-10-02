# Network resources and routes

A **network resource** is a named destination inside one organisation: an IPv4
or IPv6 subnet (for example an office LAN) or an exact DNS name. It lists the
routing peers that may carry it and the devices allowed to receive it. The
console's **Networks** page (`/networks`) lists resources, shows each routing
peer's health and failover order, and shows which devices actually receive the
route. Organisation workspaces are not routed networks; a resource always
belongs to exactly one organisation.

## Approval is separate from advertisement

A Linux agent started with `--advertise-routes` only *offers* subnets. Nothing
is sent to clients until an owner or admin either approves the route on the
device (the existing Devices flow) or creates a resource whose routing peer
advertises a covering subnet. The resource is the approval act, it is audited
(`network_resource.created`, `.updated`, `.deleted`), and it names exactly the
prefix that clients install. A router advertising `10.20.0.0/16` that carries
a `10.20.1.0/24` resource only distributes `10.20.1.0/24`.

## Who receives the route

A device receives a resource prefix only when all of these hold:

1. the resource is enabled and is a CIDR resource;
2. the device matches any selected owner role, device tag or access-policy
   group (a group later removed from policy matches nobody);
3. access policy lets the device reach the selected routing peer;
4. the device is not itself one of the resource's routing peers;
5. for `0.0.0.0/0`, the device has chosen that routing peer as its exit node.

The detail page lists every active device with the reason it does or does not
receive the route.

## Router forwarding enforcement

Receiving a route is not the security boundary: a modified client paired with
a routing peer could send to any destination behind it. Routing peers whose
agent reports the `forward-filter` capability (Linux `blaktaild` from this
release) therefore get a **forward allow-list** in their own peer map and
reject every other packet they would forward from the overlay:

- one entry per authorised client, from that client's overlay addresses to
  each prefix it receives through this router (exactly the rules above);
- the resource's ports and protocols on that entry: none means everything,
  ports without protocols mean TCP and UDP, ICMP takes no ports;
- routes approved on the device (not resources) keep their behaviour: every
  client policy lets reach the router may use the whole prefix;
- policy `hosts` inside a prefix the client receives: matching `deny` rules
  become carve-outs that win over everything, and matching `allow` rules add
  their ports for that host;
- `0.0.0.0/0` only for clients that currently select this router as their exit
  node, and those clients are explicitly denied the router's other subnets
  they were not given.

The coordinator recompiles the list on every control revision (resource,
policy, device or capability change, or a client changing its exit node).
Exit-node selections are held in coordinator memory: after a coordinator
restart, or behind a second coordinator replica, an exit client is denied
until its next poll (at most ~25 seconds), never wrongly allowed.

Routing peers that do **not** report `forward-filter` still receive and
distribute routes, so upgrades never cut off a site, but the risk is shown:
the resource's `port_enforcement` and `status.forwarding` are `not_enforced`,
each routing peer and each device route row carries
`forwarding: not_enforced`, the console shows **Forwarding not enforced —
upgrade agent**, and policy explain reports `not_enforced` for named hosts
behind that router. Upgrade the routing peer's agent to close it.

## Routing peers, metric and failover

Each routing peer has a metric (1–9999, default 100). Clients use the online
peer with the lowest metric (ties break on device ID). A peer is online when it
synced within 90 seconds; agents resync at least every 25 seconds, so failover
reaches clients within roughly two minutes of a primary going quiet. If no peer
is online, the lowest-metric advertising peer is kept so a brief outage does not
withdraw the route. Peers that do not advertise a covering subnet, have an
expired credential, or were revoked are never used.

## Overlap rules

Checks are per organisation; two organisations can use the same private CIDR.

- Overlap with the overlay (`100.64.0.0/10` or the organisation's IPv6 ULA
  `/64`) is refused.
- Overlap with a route approved on a device is refused in both directions;
  withdraw the device approval first, then create the resource.
- Overlap with another resource is refused unless **allow nested overlap** is
  set; exact duplicates are always refused. With nested prefixes, WireGuard on
  each client prefers the most specific prefix.
- Loopback, link-local, multicast and reserved ranges are refused, as are
  addresses with host bits set.

`0.0.0.0/0`, `::/0` and any non-private prefix (outside RFC 1918 or
`fc00::/7`) require `confirm_public_route` from an organisation **owner**.
Admins and automation clients cannot confirm them.

## Current limits

- **Older routing peers forward everything.** Without `forward-filter` the
  routing peer forwards the whole advertised subnet to any paired client (see
  [Router forwarding enforcement](#router-forwarding-enforcement)). Enforcement
  depends on the source overlay address, which WireGuard binds to each peer's
  key; it does not inspect application traffic.
- **Masquerade is always on.** `blaktaild` masquerades overlay sources on the
  routing peer; forwarding without NAT is not supported, so the console shows
  it as fixed rather than offering a toggle.
- **IPv6 resources** are validated and overlap-checked, but Linux agents can
  only advertise IPv4 RFC 1918 subnets and `0.0.0.0/0` today, so an IPv6
  resource shows **No routing peer** until IPv6 advertisement ships.
- **DNS targets** are stored and validated but never resolved or routed; they
  show **DNS not resolved** until domain connectors land.
- Site-to-site, router-loss and packet-capture behaviour has not been proven on
  a two-site lab.

## Upgrade

Migration 19 only adds the `network_resources` table. Routes already approved
on devices keep distributing exactly as before; the Networks page lists them
under **Advertised routes on devices**.

## Automation

`/api/v1/network-resources` supports list, get, create (with
`Idempotency-Key` and `dry_run`), full-replacement `PUT` with the current
`etag`, and `DELETE` with an optional `If-Match`. Reads need `devices:read`;
writes need `routes:write`. See [openapi/admin-v1.yaml](openapi/admin-v1.yaml).
