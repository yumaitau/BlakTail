# Audit log and traffic diagnostics

BlakTail keeps two separate records. The **audit log** records administrative
changes: who changed what, and when. **Traffic diagnostics** are optional
aggregate counters about network use. One never stands in for the other: an
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
Traffic export is not offered.

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

Records never contain payloads, URLs, DNS questions, host names or IP
addresses; agent tests check the serialised upload for addresses, keys and
names. They do
reveal which device moved how much data over which service class and port in
which hour, which is still personal information about the device's user.
Turn collection on only with a stated purpose, keep retention short, and
include it in the organisation's privacy notice. To answer an access or
deletion request, an owner can delete all stored records from `/traffic`;
records are otherwise only deleted by retention.
