# Organisation DNS settings

Owners and admins publish a versioned DNS snapshot for their organisation.
MagicDNS peer names stay coordinator-authoritative: agents never forward
`*.blaktail` to an upstream.

## Document

```json
{
  "managed": true,
  "global_resolvers": ["1.1.1.1"],
  "split": [{"suffix": "internal.example", "resolvers": ["10.0.0.53"]}],
  "search_domains": ["internal.example"],
  "records": [
    {"name": "wiki.internal.example", "type": "A", "value": "10.0.0.10"}
  ]
}
```

Two optional arrays extend the same document. They are omitted from the stored
JSON when empty, so documents published before they existed keep the same bytes,
etag and agent snapshot after an upgrade:

```json
{
  "nameserver_groups": [
    {"name": "Office AD", "resolvers": ["10.0.0.53", "10.0.0.54"],
     "match_domains": ["corp.example"], "enabled": true, "tags": ["office"]}
  ],
  "zones": [
    {"name": "apps.example", "enabled": true, "records": [
      {"name": "wiki", "type": "A", "value": "10.0.0.10", "ttl": 300},
      {"name": "docs", "type": "CNAME", "value": "wiki.apps.example"},
      {"name": "@", "type": "TXT", "value": "v=example"}
    ]}
  ]
}
```

- **Nameserver groups** forward their match domains to up to four resolvers, tried
  in the listed order. A group targets either `"all_devices": true` or one or more
  device tags (`office`, `ranger`, `store`), never both. Groups need at least one
  match domain: BlakTail never replaces a device's default resolver. When two
  groups that apply to the same device share a match domain, the first group in
  the document wins, and the coordinator warns about the shadowed group. A match
  domain cannot also be a legacy `split` suffix.
- **Zones** are answered by each device's local stub without asking any other
  resolver. Record names may be `@` (the zone apex), a single relative label, or a
  full name inside the zone; they are stored as full names. Types are A, AAAA,
  CNAME and TXT. TTL is 30-86400 seconds (default 300). A CNAME name has no other
  records, the apex cannot be a CNAME, and CNAME loops are rejected. TXT is
  printable ASCII up to 1024 bytes. Zones cannot use `.blaktail`, nest inside
  another zone, equal a forwarded suffix, or contain a legacy extra record. A/AAAA
  values cannot be unspecified, multicast or broadcast addresses. At most 16 zones,
  256 records per zone and 16 groups.
- **Precedence** for a name on a device: an exact legacy extra record answers
  first; otherwise the longest matching suffix among enabled zones, groups that
  apply to that device, and legacy split routes wins. Unknown names inside a zone
  are NXDOMAIN. MagicDNS names under `.blaktail` are never forwarded.

Validate offline without a database:

```sh
blaktail-coord check-dns docs/dns/v1-example.json
```

Publish through the console `/dns` workspace or `PUT /api/v1/dns` with `dns:write`.
Each successful publish increments `revision`, stores the previous document for
one-step rollback, and requires the current `etag` when `If-Match` or `etag` is
sent. Members are read-only (the coordinator enforces `ManageDns`).

The coordinator also keeps the last 50 published documents. Console routes:

- `GET /v1/orgs/:org/dns/revisions` and `/revisions/:revision` list and read
  them (only revisions published after this upgrade are kept);
- `PUT /v1/orgs/:org/dns` with `{"rollback_to": N}` republishes revision N as a
  new revision (audited as `dns.rolled_back`);
- `POST /v1/orgs/:org/dns/validate` canonicalises a draft and returns warnings
  without publishing;
- `GET /v1/orgs/:org/dns/preview?name=…&node_id=…` (or `&tags=office,ranger`)
  explains which zone, nameserver group, split route or MagicDNS answers a name
  for that device.

Warnings never block publishing. They cover loopback or link-local targets and
resolvers, shadowed groups, empty zones, CNAMEs that leave BlakTail names, and
private addresses that no device address or approved subnet route covers.

## Limits

- Domains are lower-cased, trailing dots stripped, and passed through IDNA.
- Root, wildcard, empty-label, and mixed-script names are rejected.
- Split suffixes, search domains, and extra records cannot use `.blaktail`.
- Extra A/AAAA records must sit under a configured split suffix or search domain.
- Resolvers are IPv4 or IPv6 addresses only. Encrypted transport is not in this slice.
- `global_resolvers` are stored and used when probing a new snapshot. They are
  not a public recursive forwarder; names outside MagicDNS, extra records, and
  split suffixes stay REFUSED.
- Longest matching split suffix wins. Duplicate suffixes after canonicalisation fail closed.

## Agent apply

Peer poll responses include a per-device snapshot as `dns`. The coordinator
resolves group assignment from the device's tags and flattens the result into the
legacy keys so agents released before groups and zones keep working: applying
groups become `split` routes, each enabled zone becomes a `split` entry with no
resolvers (which routes the zone to the local stub), and zone A/AAAA records are
added to `records`. Current agents also read the new `zones` key and answer
CNAME and TXT records, per-record TTLs, and NXDOMAIN for unknown names in a
zone. Older agents answer only zone A/AAAA records; other names in a zone get
REFUSED from their stub (or forwarded by a broader split route), so upgrade
agents before relying on CNAME or TXT records.

Agents persist the
snapshot, report the applied revision on the next poll, and keep the last
successful copy when a later poll omits `dns` or fails. Extra A/AAAA records
are answered locally by full name only. Published search domains are prepended
after the MagicDNS domain (six suffixes total). The console `/dns` page shows
which extra records match a split suffix and how many enrolled devices have
applied the current revision.
Names under a split suffix without a local extra record are forwarded to that
suffix's resolvers. MagicDNS peer names stay coordinator-authoritative:
`*.blaktail` is never forwarded, unknown `*.blaktail` names stay NXDOMAIN, and
public names without an extra record or split match stay REFUSED.

When a newer snapshot adds resolvers, the agent probes those addresses with a
short UDP query for a published extra-record or split name. If every new
resolver is silent and a previous snapshot exists, the agent keeps that
last-known-good copy, leaves extra records and split forwards unchanged, and
reports `dns health: degraded` from `blaktaild status`. A first snapshot is
still adopted even if its resolvers are unreachable so local extra records can
answer. Record-only or search-only updates do not probe.

Publishing `managed: false` is adopted without probing. Extra records, search
domains, and split forwards stop answering immediately. The MagicDNS stub keeps
serving `*.blaktail` peer names on the overlay address, and any host resolver
files BlakTail wrote (`resolvectl`, `resolvconf`, `/etc/resolv.conf`, or
`/etc/resolver`) are restored to the pre-BlakTail copy. `blaktaild status`
reports `dns managed: no`. `blaktaild down` still restores the same files.

A two-agent extra A and AAAA proof is `deploy/homelab/prove-org-dns.sh`.
Homelab `deploy/homelab/prove-dns-noleak.sh` captures eth0/lo while querying an
extra record, an unknown `*.blaktail` name, a public name, and a split suffix:
only the published sink sees the split query.
Homelab `deploy/homelab/prove-dns-lastgood.sh` publishes a working extra A,
then a rewritten extra A plus an unreachable split resolver, and checks the
agent keeps the first revision and answers the original address.
Homelab `deploy/homelab/prove-dns-restore.sh` then publishes `managed: false`
and checks the extra A is refused while the node MagicDNS name still answers.
