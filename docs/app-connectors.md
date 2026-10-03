# App connectors for DNS network resources

A network resource can name an exact host (for example
`files.example.org.au`) instead of a subnet. An **app connector** makes it
reachable: a Linux routing peer resolves the name from its own network and
BlakTail routes exactly the addresses it found, only to the devices the
resource's access selection allows.

## Set one up

1. On a Linux device inside the network that can resolve and reach the
   application, run `blaktaild up --app-connector` (or add the flag to an
   existing enrolment; `--app-connector=false` turns it off). The agent then
   reports the `app-connector` capability. macOS and Windows agents refuse
   the flag.
2. In **Networks**, create a resource with a DNS target and pick that device
   as a routing peer. Several connectors may be listed; the lowest-metric
   online one is selected, the others are standbys. A routing peer without
   the capability is shown as **Not running an app connector** and is never
   selected.
3. The resource page shows the current answers, their TTLs and lease expiry,
   every connector's last report, and the state: **Distributing**,
   **DNS not resolved**, **Blocked: unsafe DNS answer**, **Routing peer
   offline** or **No routing peer**.

## How it works

- Every 30 seconds the connector fetches its assignments
  (`GET /v1/nodes/{id}/connector/assignments`) and resolves each exact FQDN's
  A and AAAA records using the nameservers in its `/etc/resolv.conf` (so
  systemd-resolved, split DNS and internal resolvers on that site apply),
  falling back to the libc resolver. It reports the answers and TTLs with
  `POST /v1/nodes/{id}/connector/resolutions`, authenticated by its node token.
- The coordinator accepts a report only from an active, unexpired,
  unsuspended node that has the `app-connector` capability and is a routing
  peer of that resource in its own organisation. A report naming another
  organisation's resource is not found; another node's token is refused.
- Each accepted answer becomes a host route lease (`/32` or `/128`) that
  expires after the DNS TTL clamped to **90 seconds minimum and 5 minutes
  maximum**. The floor outlives the connector's report cadence (about every
  25-30 seconds) with room for a missed report, so very short TTLs do not
  flap routes; the cap bounds how long a silent connector's answer lives.
- Each report replaces the previous answer set: changed answers withdraw the
  old addresses at once, an empty answer (NXDOMAIN or no records) withdraws
  everything, and leases that expire without a fresh report stop being
  distributed: the coordinator bumps the control revision when a lease
  expires, so clients and the connector drop the route within a second or
  two. A resolver failure (timeout, SERVFAIL) keeps current leases until they
  expire.
- Clients receive the selected connector's leases through that connector's
  WireGuard peer, exactly like a CIDR resource: only devices matching the
  access selection whose policy lets them reach the connector. The connector
  forwards (with masquerade) only the host routes the coordinator accepted.
- Only route changes are audited (`connector.routes_changed`), plus every
  blocked report (`connector.resolution_blocked`).

## Rebinding and unsafe answers fail closed

If **any** answer in a report is one of the following, the whole report is
rejected, every lease for that resource from that connector is withdrawn, the
resource shows **Blocked** with the reason, and the event is audited (marked
"possible DNS rebinding" when the name previously resolved safely):

- loopback, unspecified (`0.0.0.0/8`, `::`), link-local, multicast,
  reserved/broadcast (`240.0.0.0/4`);
- cloud metadata (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`),
  including IPv4-mapped and NAT64-embedded forms;
- BlakTail's own overlay (`100.64.0.0/10` and the organisation's IPv6 `/64`);
- any device's WireGuard endpoint address in the organisation (it would
  route the tunnel through itself);
- an address inside an enabled CIDR network resource or a device's approved
  route (default routes aside): the host would otherwise be reachable with the
  DNS resource's access and ports instead of that prefix's own. Leases already
  stored inside such a prefix are not distributed either;
- anything that is not a single host address (a prefix wider than `/32` or
  `/128`).

The next clean report resumes routing.

## Limits

- **Shared IP addresses.** Authorising a DNS resource authorises the resolved
  *addresses*. If other services or virtual hosts share an address (CDNs, load
  balancers, shared hosting), clients can reach them too.
- **Ports and protocols are enforced only on connectors that report
  `forward-filter`** (current Linux agents). Their router allow-list limits
  each authorised client to the resource's ports at each leased address.
  Older connectors forward every port and show "Forwarding not enforced —
  upgrade agent"; restrict services at the application or site firewall there.
- **Same address in two resources.** WireGuard cannot route one host address
  through two peers, so when two resources (or a resource and an approved
  route) resolve to the same address on different connectors, the first one
  keeps it and the other does not receive that address.
- **Exact names only.** Wildcards and single-label names are rejected. CNAME
  chains are followed by the connector's resolver; only the final addresses
  are routed.
- **Split horizon.** Each organisation's connector resolves from its own site,
  so two organisations can resolve the same name to different addresses; their
  leases never mix. Clients still resolve the name with their own DNS; publish
  the name in organisation DNS if clients cannot resolve it themselves.
- **Static routes.** A host route inside a subnet already routed by another
  resource or approved route is more specific and wins for that address.
- Linux only. A changed DNS answer takes effect at the connector's next
  report (up to ~30 seconds); a silent or crashed connector's routes are
  withdrawn when its leases expire (90 seconds to 5 minutes, by TTL).

## Live lab (3 October 2026)

`deploy/homelab/prove-app-connector.sh` (Docker, default context `m3-max`;
`LABS_IMAGE=<tag>` reuses an image built from `deploy/homelab/labs.Dockerfile`)
runs a coordinator, a Linux connector on a WAN and a site network, a Linux
client on the WAN only, a lab authoritative DNS server (TTL 5) and three site
hosts serving HTTP on TCP 8080 and 8081. The DNS resource
`app.connector-lab.example` allows tag `office` on TCP 8080; a CIDR resource
`10.77.2.0/24` (nobody) stands for a protected network. Result of the passing
run (about 6 minutes, kernel WireGuard, SQLite coordinator):

| Step | Result |
| --- | --- |
| Answer `10.77.1.10` | Client reached `10.77.1.10:8080` 25 s after the resource was created; `:8081` and the unresolved `10.77.1.20:8080` refused; `BLAKTAIL-FWD` held one accept, client overlay address to `10.77.1.10/32` TCP 8080; detail `distributing`, ports `enforced` |
| Answer changed to `10.77.1.20` | New address reachable after 23 s; old host route gone from the client in the same second; old address and `:8081` refused |
| Answer moved to `10.77.2.10` (inside the protected CIDR) | Resource `dns_blocked` after 25 s with reason "possible DNS rebinding: … resolved to 10.77.2.10 (inside a network resource or approved device route)"; every route withdrawn, protected host unreachable |
| Answer back to `10.77.1.10` | Reachable again after 24 s |
| Connector container restarted, agent down | Client route withdrawn after 86 s (lease floor), detail `dns_not_resolved` with no answers |
| `blaktaild run` started again | `10.77.1.10:8080` reachable within 1 s of the agent starting; `:8081` still refused |

The lab found and fixed three defects: control-update long-polls did not
refresh `last_seen_at`, so idle connected routing peers showed offline after
90 seconds (and resources `stale`); expired leases were not pushed to agents
until an unrelated change; and the 30-second lease floor was shorter than the
real report cadence (~50 s), so routes were re-added on every report.

Not covered: IPv6 answers, failover between two connectors, CNAME chains
through a real recursive resolver, clients other than Linux, and two
organisations on live connectors (covered by coordinator tests only).
