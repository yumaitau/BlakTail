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

- **Ports and protocols are recorded, not enforced.** The Linux routing peer
  forwards the whole advertised subnet, and its firewall filters only traffic
  addressed to the peer itself. A modified client that policy lets reach the
  routing peer could still send traffic to the subnet. Restrict services with
  access policy on destination devices or the site firewall.
- **Masquerade is always on.** `blaktaild` masquerades overlay sources on the
  routing peer; forwarding without NAT is not supported, so the console shows
  it as fixed rather than offering a toggle.
- **IPv6 resources** are validated and overlap-checked, but Linux agents can
  only advertise IPv4 RFC 1918 subnets and `0.0.0.0/0` today, so an IPv6
  resource shows **No routing peer** until IPv6 advertisement ships.
- **DNS targets** are resolved by a routing peer running
  `blaktaild up --app-connector` (Linux) and routed as exact host routes; see
  [app-connectors.md](app-connectors.md). Without such a peer they show
  **No routing peer**.
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
