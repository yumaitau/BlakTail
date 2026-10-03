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
  become carve-outs that win over everything, and `allow` rules that name the
  host in `dst_hosts` add their ports for that host (a general device-to-device
  allow without `dst_hosts` does not open subnet hosts);
- the default route only for clients that currently select this router as
  their exit node. It is sent as its complement around every prefix the
  router carries or could carry (approved and advertised routes, and every
  CIDR resource that lists it as a routing peer, selected or standby, enabled
  or not), so traffic to such a prefix is governed only by the client's own
  grant for it: a port-limited resource keeps its ports for exit clients, and
  prefixes the client was not given are denied outright.

The coordinator recompiles the list on every control revision (resource,
policy, device or capability change, or a client changing its exit node).
Exit-node selections are stored in `nodes.exit_node_id`, so a restarted
coordinator or another replica compiles the same exit allow-list.

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
contacted the coordinator within 90 seconds; every control long-poll (at least
every 25 seconds) counts. Long-polls re-check, every 2 seconds per
organisation, which route-advertising devices are online and bump the control
revision when that set changes, so idle clients receive the new routing peer
at once. Failover therefore reaches clients at most about 92 seconds after a
primary goes quiet (90 s window; measured 82 s and 89 s in two lab runs below), and a
returning primary takes over again the same way. If no peer is online, the
lowest-metric advertising peer is kept so a brief outage does not withdraw the
route. Peers that do not advertise a covering subnet, have an expired
credential, or were revoked are never used.

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
- **DNS targets** are resolved by a routing peer running
  `blaktaild up --app-connector` (Linux) and routed as exact host routes; see
  [app-connectors.md](app-connectors.md). Without such a peer they show
  **No routing peer**.
- **Site-to-site is router-to-router only.** Routers forward overlay sources
  and masquerade them; a host behind site A cannot reach a host behind site B
  without NAT (its LAN address is neither in WireGuard's allowed IPs nor in
  the far router's allow-list). Routers themselves reach each other's sites.

## Live lab (3 October 2026)

`deploy/homelab/prove-routing.sh` (Docker context `m3-max`, resources named
`labs-routing-*`, removed on exit; about 5 minutes) builds two sites, an
exit node and two clients on internal Docker networks: site A with routers
`ra1` (metric 10, iptables-nft) and `ra2` (metric 20, iptables-legacy), site B
with `rb` (iptables-legacy), exit node `ex` (iptables-nft) with the only path
to an "Internet" host, client `c1` (authorised) and guest `c2`, both
default-routing to a home gateway that forwards nothing. Resources: site A TCP
8080, site B TCP 9090. Result of the passing run:

| Check | Result |
| --- | --- |
| Distribution | `c1` reached site A :8080 and site B :9090 1 s after the resources were created; `port_enforcement: enforced`, `ra1` primary, `ra2` standby |
| Adjacent port | site A :8081 and site B :9091 refused; `ra1` (nft) default-reject 3 → 4 packets, `rb` (legacy) 3 → 4 |
| Allowed counter | `ra1` `-s 100.64.0.5 -d 10.231.1.0/24 tcp dpt:8080` ACCEPT 4 → 5 packets |
| Modified guest | `c2` forced `10.231.1.0/24` into `ra1`'s allowed IPs and route: refused, `ra1` default-reject 4 → 5 |
| Router to router | `rb` → site A :8080 and `ra1` → site B :9090 work; `rb` → :8081 refused |
| Live chain swap | 6 resource edits (each rebuilds `BLAKTAIL-FWD-NEW` and renames it over the live chain on all four routers) while `c1` connected 150 times to both sites: 150 ok, 0 failed; afterwards exactly one `FORWARD` jump and no staging chain on nft (`ra1`, `ex`) and legacy (`ra2`, `rb`); the removed port closed again |
| Exit node | `c1` (`--exit-node routing-ex`) reached the Internet host 1 s after resuming; `c2` could not, and its default route stayed on its own gateway; `c1` kept site A :8080 and still could not reach :8081 |
| Forced exit | `c2` forcing the Internet prefix into `ex`'s allowed IPs: refused, `ex` default-reject 0 → 2 |
| Leak captures | `ex` Internet uplink: 0 packets during `c2`'s attempts, 8 during `c1`'s (2 DNS), all from `ex`'s own address; `c1` uplink (excluding WireGuard UDP 51820 and coordinator TCP 8443): 0 packets while it used DNS and HTTP through the exit |
| Router loss | `docker kill` of `ra1`: `c1` reached site A through `ra2` after 82 s (89 s in an earlier run); `rb` immediately after; detail shows `ra1` offline, `ra2` primary; `ra2` (legacy) counted the traffic |

The lab found and fixed two coordinator bugs: an agent resumed with a new
`--exit-node` only long-polls with its current revision, so the selection was
never recorded and no default route arrived until an unrelated change; and
routing-peer liveness never bumped the revision, so clients kept a dead
router's routes indefinitely (both now handled in the long-poll, with tests
`exit_selection_on_a_long_poll_returns_a_fresh_snapshot` and
`routing_peer_failover_reaches_idle_long_polls`). Not covered: IPv6, NAT
between real sites, physical routers, and anything beyond one Docker host.

## Upgrade

Migration 19 only adds the `network_resources` table. Routes already approved
on devices keep distributing exactly as before; the Networks page lists them
under **Advertised routes on devices**.

## Automation

`/api/v1/network-resources` supports list, get, create (with
`Idempotency-Key` and `dry_run`), full-replacement `PUT` with the current
`etag`, and `DELETE` with an optional `If-Match`. Reads need `devices:read`;
writes need `routes:write`. See [openapi/admin-v1.yaml](openapi/admin-v1.yaml).
