# Overlay address management (IPAM)

Every enrolled device gets two overlay addresses:

- one IPv4 host from `100.64.0.0/24`, the per-organisation device pool inside
  the CGNAT range `100.64.0.0/10` (hosts `.1` to `.254`); and
- the matching host in the organisation's unique local IPv6 `/64`, derived
  from the organisation ID. The IPv6 host number mirrors the IPv4 host number,
  so the two addresses are always allocated and freed together.

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
  peers whose AllowedIPs overlap the device IPv6 pool.

Anyone who can view the network can read the page. Owners, admins and network
admins (`ManageNetworks`) can reserve and release addresses; the coordinator
enforces this, the console only mirrors it.

## Reservations

A reservation names one IPv4 host in `100.64.0.1`–`100.64.0.254` (the network
and broadcast addresses are refused) and optionally binds it to a device name
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

## Renumbering (design only, not shipped)

There is no renumber or pool-expansion action. Changing a working device's
address can silently break pinned firewall rules, DNS caches and long-lived
sessions, so it will only ship as a staged, reversible process:

1. **Identity stays fixed.** Node ID, WireGuard key and MagicDNS name never
   change; only the address is mutable.
2. **Stage.** The operator previews the new address (or pool); the coordinator
   checks it is free, outside every resource, approved route and WireGuard-only
   peer prefix, and lists the policy rules, DNS records and routes that name
   the old address. Literal references block the change until they are edited.
3. **Dual address window.** The device gets the new address as a second
   AllowedIP and interface address; peers accept both. MagicDNS answers the new
   address only. The window lasts at least one peer-map sync cycle plus the DNS
   TTL, and is shown in the console with its deadline.
4. **Withdraw.** After the window (or on operator confirmation) the old address
   leaves AllowedIPs and enters the normal 7-day reuse grace period.
5. **Rollback.** Until step 4, cancelling removes the new address and leaves the
   old one untouched.

Pool expansion (a `/23` or larger) also needs the IPv6 derivation to stop
mirroring an 8-bit host number; that change is part of the same work.

## Not yet proven

- IPv6-only operation: an independent drill that removes every BlakTail IPv4
  address has not been run, so no IPv6-only claim is made.
- Reservation survival across a real coordinator failover is covered by the
  database design (reservations and leases live in PostgreSQL) but has not been
  drilled on a live HA pair.
