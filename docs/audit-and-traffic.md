# Audit log and traffic diagnostics

BlakTail keeps two separate records. The **audit log** records administrative
changes: who changed what, and when. **Traffic diagnostics** are optional
per-connection events and aggregate counters about network use. One never stands in for the other: an
empty traffic view says nothing about admin activity, and the audit log never
contains traffic.

## Audit log

### What is recorded

Every coordinator mutation (devices, keys, policy, posture, DNS, routes,
resources, services, webhooks, automation clients, traffic settings, audit
exports) writes one row in the same database transaction as the change. Rows
hold the actor (user id, name, email, role; automation clients appear as
`api:<client id>` with role `api_client`), action, target type and id, a
details object and a UTC timestamp. Console-side actions (sign-in policy,
memberships, invitations, identity links) are stored in the console database
and merged into the same timeline on `/audit`.

### Reading, filtering and paging

- Console: `/audit`, every role (`view_audit`). Filters: actor (user id,
  email or name), action (`node.*` or `node.` for a prefix), target type,
  target id, and a UTC date range. Pages of 50, newest first, with an
  **Older events** link; the cursor spans both stores, so no event is skipped
  or repeated across pages.
- API: `GET /api/v1/audit` (`audit:read`) with the same filters,
  `limit` up to 200 and `before=<created_at>:<id>` from `next_cursor`.
  Console-side events are not in the API.

### Redaction

Details are redacted when read, on every path (console, API, export,
webhook payloads): any key whose name contains `secret`, `password`,
`token`, `private_key`, `api_key`, `authorization`, `cookie`, `signature` or
`psk` (except identifiers such as `token_prefix` or `*_id`) and any string
shaped like a BlakTail credential (`btk_…`, `bta_…`), a JWT or a PEM block is
shown as `[redacted]`. Writers already avoid putting secrets in details;
redaction is the second line of defence.

### Export

People with `export_audit` (owner, admin, auditor) can download CSV or JSON
from `/audit`; automation needs the `audit:export` scope
(`GET /api/v1/audit/export?format=csv`). Members and network admins cannot
export. Each export is itself audited as `audit.exported` with its format,
filters and row count. One export returns at most 10,000 coordinator events
(`X-BlakTail-Export-Truncated: true` when capped); narrow the date range for
more. CSV cells that start with `=`, `+`, `-` or `@` are prefixed with `'` so
spreadsheets do not evaluate them.

### Retention and deletion

Coordinator audit rows older than the organisation's audit retention
(`audit_retention_seconds`, 1–365 days, default 90) are deleted whenever the
audit log is read. There is no per-row deletion. Console audit rows follow
the operator's console database procedures ([privacy.md](privacy.md)).
Backups keep deleted rows until the backups expire; operators must set and
publish backup retention for their onshore environment.

### Integrity chain

Since schema 27 each coordinator audit row stores its per-organisation
sequence number, the previous row's hash and its own SHA-256 hash over every
field. `/audit` shows the chain status; `GET /v1/orgs/{org}/audit/verify` and
`GET /api/v1/audit/verify` return `intact`, the verified range and any
problems: an edited row, missing rows inside the window, or a removed or
altered tail (the organisation keeps the latest sequence and hash).

Limits, stated plainly:

- The oldest retained row anchors the chain; rows aged out by retention are
  expected to be gone.
- Rows written before schema 27, the bootstrap row and console-side events
  are not chained (reported as `unchained_events`).
- Someone with write access to the database can rewrite every later row and
  the head consistently. The chain detects casual or partial tampering, not a
  determined database administrator. For stronger assurance, forward events
  to an independent store (signed webhooks, below) or export regularly.
- Writes that audit serialise per organisation on the organisation row.

## Traffic diagnostics

### Off by default, owner opt-in

Traffic diagnostics are off for every organisation until an **owner**
turns them on at `/traffic` (Events group) and chooses a sampling rate
(1–100 %) and retention (1–30 days). Admins, network admins, auditors and
members can view the page but not change it. Every change and every
deletion of stored records is audited (`traffic.settings_updated`,
`traffic.records_deleted`) and raises the `traffic.settings_changed` event.

### What is accepted

Devices upload aggregate counters to `POST /v1/nodes/{node_id}/flows` with
their own node token. Each record is: organisation and device id (must be
the uploading device's own), a service class label (`ssh`, `https`, …; at
most 32 lowercase letters, digits, `-`, `_` — never a host name), a time
bucket of at most one hour, protocol and port, byte and packet counts,
transport (`direct`, `udp_relay`, `https_relay`) and decision (`allowed`,
`denied`). Optional: `peer_id` (the other device, which must belong to the
same organisation) and `direction` (`inbound`: a peer started the flow;
`outbound`: this device did). Protocol is `tcp`, `udp`, `icmp`, `other`
(another IP protocol) or `all` (counters not split by protocol); the last
three carry port 0.

Refused outright: uploads while the organisation is opted out (`409`,
checked again inside the write so turning it off stops the very next
upload), records for another organisation or device (`403`), unknown fields,
and any key such as `url`, `uri`, `path`, `payload`, `body`, `headers`,
`cookie`, `query`, `dns_query`, `qname`, `host`, `hostname` or `sni` (`400`).
Batches are capped at 500 records and 256 KiB, uploads at 12 a minute per
device, and storage at 200,000 records per organisation (`409` beyond it).
The coordinator samples deterministically at the configured rate and deletes
records past retention on upload and every 15 minutes.

### What the page shows

Allowed and denied bytes, packets and records; totals by transport and
service class; hourly buckets for the last 6 hours to 7 days; the time of
the last report; and a confidence note (device-reported, sampling rate,
reporting devices out of active devices). States: **disabled**, **no data**
(on but nothing received), **stale** (newest record older than two hours) and
**current**.

### How agents report

While diagnostics are on, the peer map carries `traffic`
(`enabled`, `sampling_rate`, `org_id`). Turning them on or off, or changing
the sampling rate, bumps the control revision, so long-polling agents start
or stop within seconds; turning off discards the agent's counters at once,
and a `409 … turned off` answer also stops it. Agents upload one aggregate
bucket roughly every minute, built by the shared
`blaktail-ios-wg/src/flow_report.rs`: one record per peer, direction,
protocol, port class and decision. Ports at or above 49152 are reported as
49152 (`dynamic`). Agents apply the coordinator's own deterministic sampling
draw before upload, so sampled-out records are never sent.

A record's `transport` comes from the relay's own state, not a guess: a
peer currently reached through the Australian relay reports `udp_relay`, or
`https_relay` while the relay link is the WebSocket-over-443 fallback;
other peers report `direct`. On iOS (and the shared userspace dataplane) the
mobile relay state inside `blaktail-ios-wg` decides this; the Linux agent
uses its relay mesh's current link. Relayed packets are decrypted and pass
the same inbound filter as direct ones before they reach the device.

Counter sources (all counters the kernel or dataplane keeps anyway):

| Platform | Source | What it measures |
| --- | --- | --- |
| Linux | `iptables -L BLAKTAIL-ACL -v -x` per-rule counters, `wg show <if> transfer` | Allowed/denied **new inbound flow attempts** by peer, protocol and port (accept/reject rules sit after the established rule, so they count first packets); per-peer tunnel bytes as service `tunnel`, proto `all`, direction = byte direction |
| macOS | per-rule counters of the pf anchor (`pfctl -a com.apple/blaktail -v -s rules`) | Whole flows (pf counts state traffic to the rule that created it): inbound by peer/protocol/port and decision, outbound per peer |
| Windows, iOS | shared userspace filter counters | Whole flows by peer, initiator direction, protocol, service port and decision |
| Android | — | Not reported (the app refreshes the peer map, policy and relay every 5 minutes, but its native bridge does not expose the traffic counters yet) |

Counts are lower bounds: Linux rule counters reset when the chain is
rebuilt, counter keys are capped (1,024 on userspace platforms; extra keys
are counted as overflow and dropped) and uploads that fail are not retried.
The aggregate counters are not exported; per-flow events are (below).

### Per-flow traffic events

While diagnostics are on, agents also report **one event per connection
start, end and drop** they see, like a flow log. The same owner switch,
sampling rate and retention apply; there is no separate opt-in.

**What an event holds** (`POST /v1/nodes/{node_id}/flow-events`, node
token, `blaktail-coord/src/flow_events.rs`): the reporter's flow id;
`start`, `end` or `drop`; the time the device saw it and the upload's
aggregation window (at most an hour); direction from the reporter's view
(`inbound`, `outbound`); protocol (`tcp`, `udp`, `icmp`, `icmpv6`, or
`other` with its number) with ICMP type and code; overlay source and
destination address and port; the WireGuard peer that carried it;
received and sent bytes and packets (on `end` and `drop`); connection type
(`p2p`, `relay`, `routed`); an optional short label for the local filter
rule that decided (`acl:deny-rule`, `acl:default`, `fwd:deny-rule`,
`fwd:default`); and `aggregated` when the device can only see rule counters
(below). Unknown fields and URL/DNS/host/payload-shaped keys are refused,
as for aggregates.

**What the coordinator adds** at ingest: the identity behind each address
(the device, network resource or approved route of the same organisation,
or *unknown*), the device owner, the routing peer (the reporter when it
forwarded the connection, otherwise the peer that carried a connection to a
resource or route), and the **matched rule**, evaluated with the same
policy engine the peer maps are compiled from, against the policy published
when the batch arrived: the first deny rule or allow rule that matches
(`Rule 3: deny tag:office → tag:store (tcp port 3389)`), the policy default,
or the network resource that grants it (`Network resource Billing DB`, or
*default deny* when the resource does not grant that port). A drop the
current policy would allow is labelled as such (the device enforced an
older policy) instead of claiming an allow rule.

**Checks and bounds.** Uploads are refused while the organisation is opted
out (re-checked inside the write), for another organisation, for an address
that is not the reporter's own (outbound source or inbound destination)
unless the reporter is a routing peer reporting forwarded traffic, and for a
peer outside the organisation. Batches are capped at 1,000 events and 1 MiB,
uploads at 6 a minute per device, storage at 500,000 events per organisation;
windows older than two days or in the future are refused. Sampling is per
flow (a hash of organisation, reporter and flow id), so a flow's start and
end are kept or dropped together; agents apply the same draw before upload.
Events past retention are deleted on upload and every 15 minutes, and
**Delete stored records** removes events too. Migration 41
(`0041_flow_events.sql`, SQLite and PostgreSQL) adds the table.

**Reading them.** `GET /v1/orgs/{org}/traffic/flows` groups events by
reporter and flow (newest activity first, each flow with all of its events
oldest first) and `GET /v1/orgs/{org}/traffic/events` lists them flat; both
page with a cursor and filter by time range (default 24 hours), source or
destination (device id, resource id or route), user, reporter, IP, port,
protocol, direction, event type, connection type and free text (names,
addresses, rule labels; a number also matches ports). Both need
`view_audit`. `GET /v1/orgs/{org}/traffic/events/export?format=csv|json`
needs `export_audit`, takes the same filters, stops at 50,000 rows (header
`x-blaktail-export-truncated`) and is audited as `traffic.events_exported`.
API clients with `audit:read` can list events at `GET /api/v1/traffic/events`.

**Console.** `/traffic` (**Traffic events**) shows one row per flow: time;
an event sentence ("Device **alice-laptop** requested a direct connection to
device **server**", "Routing peer **router-1** blocked a connection to
resource **Billing DB** (10.242.1.10:8080) from **alice-laptop** – blocked by
default deny"); source and destination with OS or resource icon, name and
address:port; protocol and port (or ICMP type) chips; received and sent
bytes; and the routing peer. Expanding a row shows the flow's timeline:
start, the policy step (linked to the rule in `/acls` or the resource in
`/networks`), then end or drop, each with its time, plus path, reporter,
packets and flow id. The toolbar has search, time range (1 h, 24 h, 2 days,
7 days, custom), source and destination pickers, a filter popover (protocol,
port, IP, direction, event, connection type), rows per page, refresh and
**Export CSV** (shown only with `export_audit`). The aggregate summary stays
as a small header card. Off, no-data and stale states are shown as such.

**Where events come from:**

| Platform | Connections (start/end) | Drops |
| --- | --- | --- |
| Linux | `conntrack -E -e NEW,DESTROY -o timestamp,extended` (conntrack-tools, one process per address family) while reporting is on; `end` carries the conntrack entry's counters (`net.netfilter.nf_conntrack_acct` is turned on while reporting and restored afterwards). Kept: connections from or to the device's overlay addresses, and connections a routing peer forwards for an overlay peer; everything else (underlay, LAN, the coordinator) is ignored. Ends are reported only for connections whose start was seen | A rate-limited (50/s, burst 100) `NFLOG` rule (group 7841) before every `REJECT` in `BLAKTAIL-ACL` and `BLAKTAIL-FWD`, installed best-effort after the chain so a kernel without NFLOG keeps full enforcement; the agent binds the group only while reporting and reads the first 128 bytes (IP and transport headers) of each rejected packet. Repeats of one connection in a window are merged into one drop with packet counts |
| Windows, iOS | The shared userspace filter's connection table (`blaktail-ios-wg/src/filter.rs`): start when a flow is created, end with per-flow counters when it expires, is evicted or a policy change ends it | Every packet the filter drops, merged per connection per window, with `acl:deny-rule` or `acl:default` |
| macOS | pf counts per rule only, so the agent uploads honest **aggregated** events: one per peer, protocol, port and verdict per minute, from the peer's overlay address (source port unknown) | Same, as aggregated drops |
| Android | Not reported (its native bridge does not expose the filter yet) | — |

Agents buffer at most 4,096 events (Linux: 8,192 raw records per source,
16,384 open connections, 1,024 distinct drops per window; userspace: 512
pending drops), upload about every 30 seconds, drop rather than retry a
failed upload, and stop and discard everything as soon as the peer map
drops `traffic` or the coordinator answers `409 … turned off`. The Linux
agent needs the `conntrack` package (a `Recommends` of the deb and rpm, and
present in the BlakTail agent images); without it, drops are still reported.
Matched rules are named only for device-to-device and device-to-resource
flows; the coordinator cannot name a rule for traffic from an unknown
source.

### Lab proof: per-flow events (3 October 2026)

`deploy/homelab/prove-traffic-events.sh` (Docker context `m3-max`):
PostgreSQL 16, a coordinator on PostgreSQL (migrated to schema 41), and
three privileged Linux agents on kernel WireGuard: `alice-laptop` (tag
office), `server` (store) and `router-1` (store, routing peer for
10.242.1.0/24, carrying the network resource **Billing DB** 10.242.1.10/32,
TCP 5432, for office). Policy: office → store TCP 22/443/8080 and ICMP,
an explicit deny for TCP 3389, everything else default deny. With
diagnostics on, every expected event arrived (208 s, bounded by TCP
TIME_WAIT before conntrack destroys a closed connection):

- allowed TCP alice → server:8080: start from both ends and an end with
  bytes both ways, source `alice-laptop 100.64.0.1:<port>`, rule
  `Rule 1: allow tag:office → tag:store (tcp port 22,443,8080)`, `p2p`;
- allowed ping: `icmp` type Echo, rule 2, start and end with packets;
- denied ports: drops reported by `server` for 3389 (rule 3, hint
  `acl:deny-rule`) and 9000 (`Default deny`, hint `acl:default`);
- routed: alice's request and router-1's forwarded connection to
  **Billing DB** 10.242.1.10:5432, connection type `routed`, router
  `router-1`, rule `Network resource Billing DB`; alice → 10.242.1.10:8080
  was a drop on router-1 (`fwd:default`) and alice's own start/end for it
  said `Default deny: network resource Billing DB does not grant this port`;
- no Docker bridge (underlay) address was stored; CSV export returned 172
  rows;
- off: no event arrived in the next 90 s of traffic; every agent logged the
  stop and no `conntrack` process remained.

Not covered live: Windows, iOS and macOS event reporting (unit-tested only;
the iOS host change was not built in this lab), Android, IPv6 conntrack
events, load or throughput with capture on.

### Lab proof (3 October 2026)

`deploy/homelab/prove-traffic.sh` (Docker context `m3-max`): a coordinator on
SQLite and two privileged Linux agents on kernel WireGuard, tagged `office`
and `store`. The policy lets office reach store only on TCP 8080 and ICMP.
Result:

- Enforcement: 8080 office → store connects; 8081 office → store and 9000
  store → office are rejected.
- Off: after 70 s of traffic, 0 rows were stored and the summary state was
  `disabled`.
- On: rows arrived 108 s after opt-in. The summary was `current`, with one
  hourly bucket (6 allowed records / 12 packets, 2 denied records / 18
  packets), `by_service` `http-alt` 1, `icmp` 1, `tunnel` 4, `any` 2,
  `by_direction` inbound 6 / outbound 2, and confidence `high` (2 of 2
  devices).
- Stored rows had only ids, classes and counters: no `100.64.*`, `172.*`
  or `fd7a` address anywhere. Denials carried the peer's device id (service
  `any`, proto `all`, port 0: Linux attributes a denied attempt to a peer but
  not to the port it tried, unless a deny rule names that port).
- Off again: no row arrived in the next 90 s, and both agents logged
  "traffic diagnostics off".

Not covered: macOS, Windows or iOS reporting, Android, throughput impact
or storage-bound load.

### Privacy

Aggregate records never contain IP addresses. **Per-flow events do**: while
diagnostics are on, each event stores the overlay (and, for routed
traffic, the destination's private or public) source and destination
address and port, the resolved device, resource and owner, and byte
counts. That shows who connected to what and when, which is personal
information about the device's user. Neither ever contains payloads, URLs,
DNS questions or names, TLS SNI or HTTP data. Any role with `view_audit`
(including members) can read events, and `export_audit` roles can export
them; exports are audited.
Aggregate records reveal which device moved how much data over which
service class and port in which hour.
Turn collection on only with a stated purpose, keep retention short, and
include it in the organisation's privacy notice. To answer an access or
deletion request, an owner can delete all stored records from `/traffic`;
records are otherwise only deleted by retention.
