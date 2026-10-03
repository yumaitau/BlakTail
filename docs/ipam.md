# Overlay address management (IPAM)

Every enrolled device gets two overlay addresses:

- one IPv4 host from the organisation's device pool inside the CGNAT range
  `100.64.0.0/10`. The pool starts as `100.64.0.0/24` (hosts `.1` to `.254`)
  and an operator can grow it up to a `/20` (4,094 hosts) or move it, see
  [Renumbering](#renumbering-and-pool-growth); and
- the matching host in the organisation's unique local IPv6 `/64`, derived
  from the organisation ID. The IPv6 interface ID is the IPv4 address's offset
  inside `100.64.0.0/10`, so the two addresses are always allocated and freed
  together. For `100.64.0.x` the offset is `x`, so every IPv6 address handed
  out before pools could grow is unchanged.

Every organisation uses the same IPv4 range. That is safe because peer maps
are per organisation: a device only ever receives peers from its own
organisation, so the same address in two organisations never meets. A device
that is a member of two BlakTail organisations on one machine is not
supported.

## Console

**Networks → Addresses** (`/networks/addresses`) shows:

- both pools with **In use**, **Reserved**, **In grace period** and
  **Available** counts and the next address automatic allocation would use;
- every address with its IPv6 twin, owning device and state (in use, revoked
  device, deleted and in grace period, released and in grace period) and the
  earliest time it can be reused;
- reservations with their binding, state and reason; and
- conflicts: two active devices with one address, a reserved address in use
  by another device, device addresses outside the pool, and WireGuard-only
  peers whose AllowedIPs overlap the device IPv6 pool; and
- **Renumbering**: a plan form (preview impact, then start), the staged plan's
  dual-address window with a progress bar, **Complete now** and **Roll back**,
  and the last ten finished plans.

Anyone who can view the network can read the page. Owners, admins and network
admins (`ManageNetworks`) can reserve and release addresses and plan, complete
or roll back renumbers; the coordinator
enforces this, the console only mirrors it.

## Reservations

A reservation names one IPv4 host inside the current pool (the network and
broadcast addresses are refused) and optionally binds it to a device name
and/or WireGuard public key.

- **Unbound** reservations are never handed out automatically.
- **Bound** reservations go to the device that enrols with that exact name or
  key. If a deleted or revoked device still holds the address, the bound
  device takes it over immediately (the operator chose it). If an *active*
  device holds it, enrolment fails with a conflict rather than silently
  giving the device another address.
- A reservation for an address an active device already uses is accepted
  only when it is bound to that device, which pins its current address.
- Reserving the identical reservation again is a no-op (safe to retry).
  Release needs the reservation's current etag in `If-Match`; releasing an
  already-released reservation succeeds.
- Both actions are audited (`ipam.reservation_created`,
  `ipam.reservation_released`). WireGuard keys appear in the console and audit
  only as an 8-character prefix.

A reservation created at the same moment a concurrent enrolment picks the same
address cannot be fully prevented without serialising all enrolments; when it
happens the page reports it under **Conflicts** and the device keeps its
address until it is revoked or deleted.

## Allocation and concurrency

`ipam_leases` holds one row per handed-out IPv4 address with primary key
`(org_id, address)`. Enrolment computes the lowest free host (skipping every
device row, held lease and reservation) and inserts the lease with
`ON CONFLICT DO UPDATE … WHERE released and past grace`. If a concurrent
enrolment already holds the address, PostgreSQL waits for it to commit, the
insert affects no rows, and the allocator moves to the next host. Two
coordinators can therefore never hand out the same address; this is tested
with 40 parallel enrolments through two coordinator pools on PostgreSQL 16.

## Reuse grace period

An address is not reused for **7 days** (`ADDRESS_REUSE_GRACE_SECS`, equal to
the tombstone retention) after its device is revoked, deleted or purged. The
grace starts at the device's deletion or revocation time; for a device row that
was already purged it starts when the allocator first notices, which is never
earlier. A revoked device keeps its address for as long as its row exists.

Migration 20 backfills a lease for every existing device address, so upgraded
coordinators keep current assignments and grace periods.

## Renumbering and pool growth

A device's identity (node ID, WireGuard key, MagicDNS name) never changes;
only its overlay address does. Changes go through a **plan**, created on
**Networks → Addresses** or with `POST /v1/orgs/:org/ipam/renumber`. A plan
either changes the IPv4 pool (`{"pool": "100.64.0.0/22"}`) or moves up to 64
chosen devices (`{"devices": [{"node_id": "…", "address": "100.64.0.40"}]}`;
without `address` a device gets its bound reservation, else the lowest free
host). `…/renumber/preview` returns the same plan without changing anything.

- **Growing the pool** to a larger CIDR that contains the current one (a `/24`
  to a `/22`, say) moves nobody and is recorded as completed at once
  (`ipam.pool_resized`). Pools are `/24` to `/20`, network-aligned and inside
  `100.64.0.0/10`. Reservations outside a target pool block the change.
- **Moving devices**, or a pool change that no longer covers some devices,
  stages a **dual-address window** (default 24 hours, 10 minutes to 30 days):
  1. **Stage.** Each moved device's AllowedIPs become *new + old* (IPv4 and the
     matching IPv6). Peers route and accept both, policy and routing-peer
     forward allow-lists include both, and the agent adds the new addresses to
     its interface and uses the new IPv4 as its primary. Peer maps list the
     old ones as `retiring_ips`, so MagicDNS answers only the new addresses
     straight away.
  2. **Complete** (**Complete now**, or automatically when the window ends; the
     coordinator completes a due plan on the next device check-in): AllowedIPs
     become the new addresses only, agents remove the old ones, and the old
     IPv4 lease enters the normal 7-day reuse grace period.
  3. **Roll back** (only while staged): every moved device returns to its old
     addresses and the new leases enter the grace period. A pool rollback is
     refused if a device enrolled from the new pool during the window.
- **Blockers.** A literal mention of an old address in access policy or DNS
  settings (a host address, or a CIDR that covers the old address but not the
  new one) blocks the plan until it is edited. The preview lists blockers and
  the impact: devices moving, peer maps and routing-peer allow lists carrying
  both addresses, and MagicDNS names that switch.
- **Safety.** One plan per organisation can be staged at a time (a unique index
  plus a per-organisation row lock). Complete and roll back need the plan's
  `etag` in `If-Match` (412 when stale). New addresses are leased with the same
  insert-or-skip rule as enrolment, so a concurrent enrolment cannot take one.
  Every step is audited (`ipam.renumber_staged`, `ipam.renumber_completed`,
  `ipam.renumber_rolled_back`, `ipam.pool_resized`; automatic completion is
  recorded with `"automatic": true`).

Renumbering has only been tested with agents from this release, which adopt
and withdraw addresses from the peer map. Upgrade agents before starting a plan
that moves them; an older agent may not add its new address, so roll the plan
back rather than completing it if such a device stops answering on the new
address.

Migration 39 adds `orgs.ipv4_pool_cidr` (default `100.64.0.0/24`, so no
existing address changes) and `ipam_renumber_plans`.

## Live lab

`deploy/homelab/prove-ipv6-renumber.sh` (Docker host `m3-max`, one host,
kernel WireGuard, SQLite coordinator) stages a pool move from `100.64.0.0/24`
to `100.64.8.0/24` while a client pings the router's old address every 200 ms,
checks old and new IPv4 and IPv6 addresses both answer during the window,
completes the plan and checks only the new ones answer, then stages one
device and rolls it back.

Result on 3 October 2026: passed. Staging reached both agents within one
poll (about 1 second with long-polling); the continuous ping to the router's
old IPv4 address lost 0 of 74 packets across staging; during the window
`100.64.0.2`/`fd78:…::2` and `100.64.8.2`/`fd78:…::802` all answered and the
IPv6 subnet route kept working; after **Complete** only the new addresses
answered; the rollback drill left the router on its original address only.
The ping deliberately targets the old address, which stops answering at
completion by design; connections must move to the new address (or a MagicDNS
name) within the window.

## Not yet proven

- IPv6-only operation. The same lab's fourth step put a coordinator and two
  agents on a Docker network with no IPv4 at all (`--ipv4=false`): enrolment
  over IPv6, WireGuard endpoints `[fd42:b1a:c0de:2::…]:51820`, and an overlay
  ping passed on 3 October 2026. That proves an IPv6-only *underlay* on one
  host. Devices still get an overlay IPv4 address, and no real IPv6-only ISP,
  NAT64/DNS64 network or mobile carrier has been tested, so BlakTail does not
  claim IPv6-only operation.
- The pool-growth and renumber flows have been run only against SQLite in the
  lab; PostgreSQL behaviour is covered by the shared lease logic and tests,
  not a live drill.
- Reservation survival across a real coordinator failover is covered by the
  database design (reservations and leases live in PostgreSQL) but has not been
  drilled on a live HA pair.
