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
| `acl-filter` | Installs the inbound overlay filter from `ingress` | Linux `blaktaild`; macOS `blaktaild` once its pf anchor is verified; Windows `blaktaild`; the iOS packet tunnel; the Android app |
| `ssh-users` | Verified sshd per-source `AllowUsers`/`DenyUsers` | Linux `blaktaild` with `BLAKTAIL_SSHD_DROPIN` set and verified |
| `forward-filter` | Routing peer forwards only its compiled `forward_filter` allow-list | Linux `blaktaild` |
| `remote-ssh-ca` | Trusts the organisation SSH user CA, from the remote-access gateway only, verified with `sshd -T` | Linux `blaktaild` with `BLAKTAIL_SSHD_DROPIN` and `BLAKTAIL_SSH_USER_CA` ([remote-access.md](remote-access.md)) |
| `remote-jobs` | Runs owner-approved, signed job templates | `blaktaild --allow-remote-jobs` |

An agent that predates these capabilities reports neither, so user-limited
SSH stays closed at port level (fail closed); it never widens access. The
Linux agent also closes TCP 22 itself for user-limited sources whenever its
own sshd verification has not succeeded.

### Inbound filtering outside Linux

The same `ingress` grants are enforced on every client, in the Linux chain's
order (replies to the device's own flows, per-source rejects, accepts, reject
the rest):

- **iOS, Android, Windows**: the shared userspace filter in
  `blaktail-ios-wg/src/filter.rs` runs inside the boringtun dataplane,
  between decrypt and the tunnel write. It tracks connections (bounded at
  16,384 flows, oldest evicted; TCP 2 h established, UDP 60/180 s, ICMP
  30 s), lets ICMP errors through only when they quote one of the device's
  own flows, follows a fragment's first fragment (orphan fragments are
  dropped), walks at most 8 IPv6 extension headers and drops malformed
  packets. Denied packets are dropped silently rather than answered with a
  reset. Unlike Linux, a policy change also ends inbound flows the new policy
  no longer allows. Invalid policy input installs deny-all.
- **macOS**: boringtun's device writes decrypted packets straight to the
  utun interface with no hook, so the agent compiles the grants into a `pf`
  anchor (`com.apple/blaktail`, evaluated by the stock `/etc/pf.conf`) on
  that interface and takes a `pfctl -E` reference. `acl-filter` is reported
  only after the agent verifies pf is enabled, the main ruleset still
  evaluates `com.apple/*` and the anchor holds every rule; otherwise the Mac
  is reported unfiltered. `blaktaild down` flushes the anchor and releases
  the reference.

Shared test vectors (`blaktail-ios-wg/src/filter_vectors.json`) drive both
the userspace filter tests and a walk of the generated Linux chain, so the
two decide every vector the same way; the pf ruleset is syntax-checked with
`pfctl -n`.

Per-user SSH limits stay **Linux-only**: only the Linux agent can verify an
sshd drop-in and report `ssh-users`. Every other client closes TCP 22 to
sources whose SSH grant is user-limited (the coordinator does too), so a
user-limited SSH rule never widens access there.

Linux lab (`deploy/homelab/prove-traffic.sh`, 3 October 2026, `m3-max`): with
office granted only TCP 8080 and ICMP to store, 8080 connects while 8081
(office → store) and 9000 (store → office) are rejected. The chain also ends
each source's rules with a per-source reject, which takes the same action as
the final rejects, so denied attempts are counted per peer.

Limits: Android takes its peer map (and so its policy) only at enrolment;
the iOS tunnel refreshes every 30 seconds. Neither has been proven on a
physical device in this change.

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

### MDM/EDR integrations

A check may also require a healthy record from one of the organisation's
device-health integrations (Microsoft Intune, CrowdStrike Falcon,
SentinelOne, FleetDM or Huntress; [ADR 0005](adr/0005-posture-integrations.md)):

```json
{"integration": {
  "integration_id": "<uuid>",
  "max_age_secs": 3600,
  "max_last_seen_secs": 86400,
  "on_outage": "fail"
}}
```

- **Connecting** (`/v1/orgs/:org/posture-integrations`) is owner-only
  (`manage_security`): the owner enters the provider settings and a
  write-only secret, and must acknowledge the provider's data notice first.
  Secrets are sealed with the coordinator key and are never returned,
  audited or logged; the API shows only a short fingerprint. Changing a
  provider's settings requires re-entering the secret, so a stored
  credential is never redirected to a new endpoint. Referencing an
  integration from a check needs `manage_policy`, and only integrations in
  the same organisation can be referenced.
- **Reconcile** is by polling: every 15 minutes by default (5 minutes to 24
  hours), jittered, at most four providers at once per coordinator, with a
  lease so replicas never poll the same integration twice. Failures back off
  exponentially (1 minute doubling, capped at the larger of the interval and
  one hour, and never sooner than a provider's `Retry-After`). A 429 whose
  `Retry-After` is 30 seconds or less is retried in place up to three times.
  `POST .../posture-integrations/:id/sync` runs a reconcile now ("Test
  connection").
- **Outage state** is per integration: the first failed reconcile records
  `outage_since`, a fixed error category and a consecutive-failure count;
  stored device records are never changed by a failure. The next success
  clears the outage and bumps the control revision once.
- **Matching** happens only inside the organisation. A device's
  agent-reported serial number wins, then its physical MAC addresses;
  hostname is used only if the owner opts in for that integration.
  Placeholder serials and randomised or multicast MACs never match. A device
  matches only when exactly one provider record matches its strongest key
  and no other device in the organisation claims the same record; anything
  else is ambiguous and fails. Serials and MACs are self-reported by the
  node token holder, so a copied serial makes both devices fail rather than
  passing the signal on.
- **Evaluation**: a matched record must be passing for that provider (see
  the provider list in the console), confirmed by a successful reconcile
  within `max_age_secs` (default 3600, 60 s to 30 days), and — if set —
  seen by the provider within `max_last_seen_secs`. Unmatched, ambiguous,
  disabled or deleted integrations fail. When data is stale *and* the
  provider is in outage, `on_outage: "fail"` (default) fails the check;
  `"pass"` keeps devices whose last known record was passing, until the
  provider recovers. Stale data without an outage always fails.
- The device assessment lists every integration's view of the device
  (match state, key, provider status, sync time, outage) with source
  `provider_reported`.
- An integration referenced by a check cannot be deleted.

No live vendor tenant was available while building this; each adapter is
tested against a local mock of the vendor's documented responses.

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
