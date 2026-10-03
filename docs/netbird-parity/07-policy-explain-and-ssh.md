# Explain effective access and finish policy-to-agent SSH enforcement

**Priority:** P0 for enforcement correctness, P1 for UX. **Depends on:** existing #38 and agent ACL filter; draft 04 for named resources. **Area:** coordinator compiler, Linux/macOS/iOS agents, console.

## Gap and outcome

BlakTail has versioned deny/allow rules, people groups, tags, host/port/protocol selectors, tests, and a visual editor. The SSH section in `acl-editor.tsx` explicitly says agents do not yet enforce those rules. NetBird's policy/group/access pages expose resource reachability and policy effects. Close the gap between editor promise and actual transport enforcement, rather than adding a second policy engine.

## Scope

- For a selected actor/source/destination/service, show matched rule, defaults, denied precedence, group/tag membership, policy revision and where enforcement happens. Expose precise limitations by OS and route type; no misleading green “allowed” when agent lacks filter support.
- Define fail-closed compatibility and minimum agent version for SSH checks/re-auth. Implement and prove enforcement at destination, including Linux sshd integration and realistic macOS/iOS boundary. Remove unsupported editor claims or gate controls until enforceable.
- Add drafts, policy diff/tests, conflict warnings and actor-attributed publish audit; preserve etag concurrency and legacy same-tag semantics during migration.

## Acceptance / proof

Allow, deny, stale membership, service port, tag owner and SSH-user tests align with actual packet/SSH outcomes on two nodes. Old agent cannot silently widen access. Cross-org resource probes fail; editor clearly distinguishes simulated, published and device-enforced state.

**Evidence:** `docs/policy.md`, `apps/console/src/components/acl-editor.tsx`, `blaktaild/src/acl_filter.rs`; https://docs.netbird.io/manage/access-control, https://docs.netbird.io/manage/network-routes/access-control.

## Status (2 October 2026)

**Done:**
- `POST /v1/orgs/:org/policy/explain` (`blaktail-coord/src/policy_explain.rs`): device or person/role/tag source, device or named-host destination, protocol/port or SSH login. Returns decision and basis, every rule considered (matched, skipped for posture, skipped for a lapsed `check`), deny precedence, group/tag membership, source posture, both peer-map directions, the compiled grant, and enforcement state (`device_enforced`, `peer_map`, `not_enforced`, `unknown`) derived from the destination's reported OS and capabilities. Members may explain; nothing mutates. Other organisations' node ids return 404.
- Console **Explain access** panel on `/acls` with separate "Simulated", "Published policy, revision N" and "Device: …" labels. Green only when allowed **and** enforced by the destination.
- SSH enforcement: SSH rules govern TCP 22 on destinations they select; `*` plus denied users now compiles to `ssh_deny_users` (previously the deny was silently dropped from the compiled grant). Capabilities `acl-filter` and `ssh-users` are reported by `blaktaild` on every poll (and at registration). Without `ssh-users` the coordinator keeps TCP 22 closed for user-limited grants, so old agents fail closed. `check` rules require the source device credential to have been renewed within the period (default 12 h); lapses bump the control revision.
- `blaktaild`: local fail-closed backstop (`acl_filter::fail_closed_ssh`), `DenyUsers`, `Match all` terminator, login validation (`DenyUsers *` on anything odd), and opt-in verified sshd drop-in (`blaktaild/src/sshd.rs`, `BLAKTAIL_SSHD_DROPIN`): `sshd -t`, `sshd -T -C` per limited source plus an unrelated-address leak probe, reload, and restore of the previous file on any failure.
- Editor: SSH section states where rules are and are not enforced (Linux vs macOS/iOS), `check` relabelled as credential renewal, posture selectors on allow and SSH allow/check rules.
- Policy tests (`allows_flow`) now reflect SSH governance of port 22, so a test cannot pass while enforcement denies.

**Proven by tests:** coordinator unit/integration tests in `blaktail-coord/src/tests/policy_posture.rs` (fail-closed SSH without capability, capability report on long-poll reopening 22, `*`+deny, lapsed and unknown `check`, explain decision/basis/posture/enforcement labels, member read-only, cross-org 404/401) and updated existing ingress tests; agent tests in `acl_filter.rs` (reject precedes accept, injection, `Match all`) and `sshd.rs` (verify, restore on reject/ineffective/leaking config, reload via pidfile).

**Still needs live/field proof or a decision:**
- Two-node packet/SSH outcomes on real hosts: `deploy/homelab/prove-acl-services.sh` was updated for the drop-in flow but not run in this change. Real OpenSSH behaviour of `Match` scoping inside an end-of-file `Include` is relied on through runtime verification, not assumed.
- macOS, iOS, Android and Windows destinations do not filter inbound traffic; SSH and port rules remain unenforced there (explained honestly). Closing that gap needs a platform filter design (e.g. macOS pf anchor, NetworkExtension) and a decision on whether to drop pairings for unfilterable destinations.
- Custom SSH ports, interactive person re-authentication for `check`, policy drafts/diff/conflict warnings (draft 03) and named resources (draft 04) are not covered here. Subnet-route (`dst_host`) destinations are explained but not enforced at packet level.

### Router forwarding enforcement (2 October 2026, security follow-up)

- **Done:** `blaktail-coord/src/forwarding.rs` compiles, for a routing peer reporting `forward-filter`, a `forward_filter` field in its peer map/update response: per authorised client, overlay source addresses x each prefix it receives through that router (device-approved routes, resource routes via `resources::Distribution::grants_via`) x resource ports/protocols, plus policy `hosts` rules inside those prefixes (deny carve-outs win, allow rules add ports). `0.0.0.0/0` only for clients currently selecting that exit node (selection persisted in `nodes.exit_node_id`, migration slot 28; a change bumps the control revision), with the router's other ungranted prefixes denied to them. `blaktaild` (`blaktaild/src/forward_filter.rs`) enforces it in `BLAKTAIL-FWD` (iptables/ip6tables, default reject, atomic staging-chain swap, cleaned on `down`/`pause`/route withdrawal) and reports `forward-filter`. Routers without the capability keep distributing, but resources, device routes and routing peers show `forwarding: not_enforced` ("Forwarding not enforced — upgrade agent" in `/networks`), and policy explain returns `not_enforced` for hosts behind them.
- **Proven by tests:** `blaktail-coord/src/tests/forwarding.rs` (authorised client present with exact ports, unauthorised client and other organisation absent, host deny/allow entries, disabled resource removes entries, exit node only for selecting clients and withdrawn on deselect, capability-driven status and explain enforcement); `blaktaild/src/forward_filter.rs` tests (deterministic rules, IPv4/IPv6 split, default reject, malformed entries never widen access, atomic swap order, failed install keeps previous chain, idempotent cleanup) with a fake command runner.
- **Still needs live/field proof or a decision:** no packet test on a real Linux router (iptables-legacy and iptables-nft `-E` rename with a live jump is relied on, not proven here). A router joining for the first time, with no stored list, forwards legacy-style until its first peer map (seconds).
