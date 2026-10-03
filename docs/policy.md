# Organisation policy

BlakTail policy is a versioned JSON document stored per organisation. The
coordinator compiles it once on publish. `deny` wins over `allow`. New
organisations start with `"defaults": "deny"`. Existing documents without
`defaults` keep the legacy same-tag and untagged allow; GET shows that as a
visible `generated` rule. `PUT` requires the current `etag` when the caller
sends `If-Match`. Admin `PUT /api/v1/policy` always requires `etag`.
Publishes serialise on the organisation row and compare-and-swap the policy
revision, so of two concurrent writes made against the same `etag` exactly one
succeeds and the other gets 412 (on SQLite and Postgres alike).
`{"rollback":true}` restores the previous document.

```sh
blaktail-coord check-policy policy.json
```

That command does not open a database or listener. A failing test or an
unknown field rejects the document.

## Schema version 1

```json
{
  "version": 1,
  "defaults": "deny",
  "groups": {
    "rangers": ["alice@example.test", "alice-user"]
  },
  "tag_owners": {
    "office": ["owner-1", "admin"]
  },
  "hosts": {
    "wiki": "10.0.0.10"
  },
  "rules": [
    {
      "action": "allow",
      "src_groups": ["rangers"],
      "dst_tags": ["store"],
      "dst_ports": ["22", "80-443"],
      "protocols": ["tcp"]
    }
  ],
  "ssh": [
    {
      "action": "allow",
      "src_groups": ["rangers"],
      "dst_tags": ["store"],
      "users": ["ubuntu", "deploy"]
    }
  ],
  "tests": [
    {
      "name": "ranger reaches store ssh",
      "src_user": "alice-user",
      "dst_tags": ["store"],
      "dst_port": 22,
      "protocol": "tcp",
      "allow": true
    },
    {
      "name": "office stays isolated",
      "src_tags": ["office"],
      "dst_tags": ["store"],
      "allow": false
    },
    {
      "name": "ranger ssh deploy",
      "src_user": "alice-user",
      "dst_tags": ["store"],
      "ssh_user": "deploy",
      "allow": true
    }
  ]
}
```

- `defaults` is `same_tag` or `deny`. Missing `defaults` is `same_tag` so
  existing meshes keep working. New organisations write `deny`.
- `groups` are named sets of people, identified by user id or email.
- `tag_owners` lists who may assign that tag on a join key or browser
  approval. An unlisted tag keeps the previous owner/admin behaviour. The
  organisation owner remains a break-glass assigner.
- `hosts` names private IPv4 or unique-local IPv6 addresses and CIDRs.
  `.blaktail` and default routes are rejected.
- `rules` select roles, tags, groups, optional `dst_hosts`, `dst_ports`
  (`22`, `80-443`, or `*`), and `protocols` (`tcp`, `udp`, `icmp`). ICMP
  cannot name ports. Peer-map evaluation still includes a peer when any
  port on that path is allowed. Linux agents install an INPUT filter on
  the overlay from each peer's compiled `ingress` grant (destination
  enforcement). Legacy snapshots without `ingress` stay unfiltered.
  Routing peers reporting `forward-filter` also enforce `hosts` rules on
  forwarded traffic: host `deny` rules always win, host `allow` rules add
  ports inside prefixes the client already receives. See
  [Router forwarding enforcement](network-resources.md#router-forwarding-enforcement).
- `ssh` selects the same source and destination roles, tags, and groups,
  plus operating-system `users` (`ubuntu` or `*`) and `allow` / `deny` /
  `check`. SSH evaluation has no same-tag default. See
  [SSH enforcement](#ssh-enforcement).
- `posture` on an `allow` rule, or an SSH `allow`/`check` rule, names up
  to eight [posture checks](#posture-checks) the **source** device must
  pass. Deny rules cannot name posture. A device failing a check loses
  only the grants of the rules that name it.
- `tests` can name `dst_host`, `dst_port`, and `protocol`, or `ssh_user`
  for an SSH decision, and `src_posture` for the checks the simulated
  source passes (none by default, so posture-gated rules do not match). A mismatch fails closed. Host-only rules never
  become the implicit same-tag default.

Existing documents without `version` deserialize as v1.

## SSH enforcement

SSH rules are authoritative for TCP 22 on every destination they select
(any `allow`/`check` rule naming the destination, or a `deny` naming both
sides). For each source/destination pair the coordinator compiles:

- `ssh_users`: allowed logins, or `*`;
- `ssh_deny_users`: logins denied while `*` is allowed;
- TCP 22 open only when the grant is non-empty **and** either the grant is
  plain `*` or the destination agent reported the `ssh-users` capability.
  Otherwise `22` is added to `deny_tcp`, even when a port rule or the
  same-tag default would allow it.

`check` rules additionally require the source device's credential to have
been issued (enrolment or `blaktaild reauth`) within `check_period_secs`
(default 43200). This is device credential renewal, not an interactive
person re-authentication. When the period lapses the coordinator bumps the
control revision so agents recompile without waiting for another change.

Destination capabilities, reported by the agent on every poll:

| Capability | Meaning | Reported by |
| --- | --- | --- |
| `acl-filter` | Installs the inbound overlay filter from `ingress` | Linux `blaktaild` |
| `ssh-users` | Verified sshd per-source `AllowUsers`/`DenyUsers` | Linux `blaktaild` with `BLAKTAIL_SSHD_DROPIN` set and verified |
| `forward-filter` | Routing peer forwards only its compiled `forward_filter` allow-list | Linux `blaktaild` |

An agent that predates these capabilities reports neither, so user-limited
SSH stays closed at port level (fail closed); it never widens access. The
Linux agent also closes TCP 22 itself for user-limited sources whenever its
own sshd verification has not succeeded. macOS, iOS, Android and Windows
clients do not install an inbound filter: SSH and port rules are **not
enforced** on those destinations, and Explain access says so.

`sshd_blaktail.conf` in the state directory is still written for
inspection. To enforce per-user limits, see
[Linux agent: SSH user policy](linux-agent.md#ssh-user-policy). Homelab proof
is `deploy/homelab/prove-acl-services.sh`.

## Posture checks

Posture checks are named, versioned definitions per organisation
(`/v1/orgs/:org/posture-checks`, owner/admin to change, members to read).
A definition sets one or more of:

```json
{
  "description": "Supported agents on managed Linux",
  "min_agent_version": "0.2.0",
  "os_families": ["linux", "macos"],
  "min_os_versions": {"macos": "14.0"},
  "max_credential_age_secs": 604800,
  "max_report_age_secs": 86400,
  "require_approved_peer": true,
  "on_missing_data": "fail"
}
```

- OS family, OS version and agent version are **reported by the device
  itself** on each poll. They are hygiene signals, not attestation, and are
  not evidence of compliance. Values are format-checked; a node can only
  report for itself, and only the owning organisation's devices and checks
  are ever consulted.
- Credential age and `require_approved_peer` (active, not revoked, credential
  unexpired) are observed by the coordinator.
- Missing, unparseable or stale (`max_report_age_secs`) data fails the check
  unless `on_missing_data` is `pass`. Unknown check names in policy never
  pass.
- Checks are evaluated when peer maps compile. Changes to a check, a
  device's reported inventory, or a credential renewal bump the control
  revision; time-based lapses (credential age, report age, SSH `check`
  periods) bump it once when the earliest one passes.
- `GET /v1/orgs/:org/posture-assessments` and
  `GET /v1/orgs/:org/nodes/:node/posture` return each device's current
  result, reasons with their source, the next lapse time, and the policy
  locations it affects. A check referenced by the published policy cannot
  be deleted.

MDM/EDR integrations are design-only; see
[ADR 0005](adr/0005-posture-integrations.md).

## Explain access

`POST /v1/orgs/:org/policy/explain` (any member of the organisation; it
reads only) takes a `source_node_id` or a `source` selector
(`{"user","role","tags"}`), a `destination_node_id` or `dst_host`, and a
`protocol`/`port` or an `ssh_user`. It returns the decision, the basis
(matched rule, deny precedence, default), every rule considered including
rules skipped for posture or a lapsed `check`, group and tag membership,
the source's posture, whether each side's peer map includes the other,
the compiled grant, and where enforcement happens:

- `device_enforced`: the destination agent reported `acl-filter` (for a
  named `dst_host`: every routing peer carrying it reported `forward-filter`);
- `peer_map`: no tunnel exists, which every client honours;
- `not_enforced`: the destination does not filter inbound traffic, or a
  routing peer carrying the named host does not report `forward-filter`
  ("forwarding not enforced — upgrade agent");
- `unknown`: a Linux agent that has not reported filter support.

For a named host and a source device, `reasons` also says whether each
enforcing routing peer would forward or drop the flow according to its compiled
allow-list, which can differ from the policy decision: a network resource or a
device-approved route can grant the subnet without a host rule. Only `allow`
rules that list the host in `dst_hosts` widen a routing peer's allow-list for
that host. `peer_map`
means no routing peer carries the host at all.

Results are simulations against the published revision; no packet is sent.
Device ids from another organisation return 404.
