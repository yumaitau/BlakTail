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

### Inbound filtering on macOS, iOS, Android and Windows (3 October 2026)

**Done:**
- One shared userspace filter, `blaktail-ios-wg/src/filter.rs`, consuming the same `ingress` grants as the Linux `BLAKTAIL-ACL` chain in the same order (established/related, per-source rejects, accepts, reject the rest), including the agent's fail-closed SSH backstop and the PQ exchange port where requested. It parses decrypted IPv4/IPv6 TCP/UDP/ICMP, tracks connections (16,384-flow table, FIFO eviction, per-protocol timeouts), admits ICMP errors only when they quote a tracked flow, follows first fragments (orphans dropped), walks at most 8 IPv6 extension headers, drops malformed packets, and on a policy change ends inbound flows no longer allowed. Invalid policy JSON installs deny-all.
- Hooked between decrypt and tunnel write in the shared dataplane (`decapsulate`), so iOS (`TunnelSession` → `blaktail_tunnel_set_policy`), Android (`NativeTunnel.setPolicy`) and Windows (`WindowsNetwork::apply_ingress`) all use it. They report `acl-filter`: the iOS tunnel and Android on their peer fetches, Windows from `agent_capabilities`.
- macOS: boringtun's `DeviceHandle` writes decrypted packets straight to utun with no callback, so a hook there would mean forking boringtun. Instead `blaktaild/src/pf_filter.rs` compiles the grants into a pf anchor (`com.apple/blaktail`) on the utun interface; `acl-filter` is reported only after pf is verified enabled, `com.apple/*` evaluated and every rule loaded.
- Policy explain and posture already key on the `acl-filter` capability, not the OS. The detail text now says per-user SSH limits are Linux-only, and the editor's SSH note was updated.

**Proven by tests:** `blaktail-ios-wg` filter tests (shared vectors `filter_vectors.json`, replies to outbound TCP/UDP/ICMP under deny-all, related ICMP errors including truncated quotes, IPv4/IPv6 fragments, extension-header bound and truncation, malformed packets, table bound and eviction, expiry, policy change, PQ port, and an end-to-end C ABI test where Bob's tunnel drops a denied packet between decrypt and the tunnel write). `blaktaild` `acl_filter::shared_vectors_decide_like_the_userspace_filter` walks the generated Linux chain over the same vectors. `pf_filter` tests cover order, legacy maps, interface validation, verification and counters, and `pfctl -n` accepts the generated ruleset on macOS. `posture::enforcement_profile_is_honest_about_clients` covers iOS, Android, Windows and macOS with `acl-filter`. Builds: `cargo check --target aarch64-apple-ios-sim -p blaktail-ios-wg` passes, and the iOS `BlakTailTunnel` target builds for the simulator with Xcode. `cargo check --target x86_64-pc-windows-gnu -p blaktaild` is blocked by Unix-only code already at the base (`std::os::unix` in `lib.rs`, `dns.rs`, `share.rs`, `sshd.rs`, `pq.rs`); `windows.rs` reports no errors.

**Still needs live/field proof or a decision:** no physical iPhone, Android phone, Windows host or root macOS pf run in this change. Android takes its policy only at enrolment (the app has no peer-map polling). Per-user SSH limits remain Linux-only by design.

### Live lab (3 October 2026)

**Proven live:** `deploy/homelab/prove-sshd-limits.sh` (Docker context `m3-max`, 69 s with a cached image build) runs real OpenSSH 9.2 on a Debian bookworm store agent with `Include /var/lib/blaktail/sshd_policy.conf` at the end of `sshd_config` and `BLAKTAIL_SSHD_DROPIN` set; key auth only; users `deploy` and `intruder` both trust the office and guest keys, so every refusal comes from policy. With an SSH rule `office -> store users [deploy]` and a guest (tag `ranger`) allowed only TCP 8080: the agent wrote `Match Address <office v4>,<office v6> / AllowUsers deploy / Match all`, verified it and reported `ssh-users` about 2 s after the first peer map; office logged in as `deploy` (`id -un` = `deploy`); office as `intruder` got `Permission denied (publickey)` and sshd logged `User intruder from 100.64.0.2 not allowed because not listed in AllowUsers`; guest TCP 8080 connected while TCP 22 was reset (`BLAKTAIL-ACL` counter on the guest's `tcp dpt:22 reject-with tcp-reset` rule rose to 2). After killing and restarting the agent with `blaktaild run`, all three outcomes held 10 s later.
**Still unproven:** the systemd `reload ssh` path (the lab reloads through `/run/sshd.pid`), other OpenSSH builds, and a two-host network (all containers share one Docker bridge).

### Live lab: PostgreSQL policy PUT race (3 October 2026)

- **Proven live:** `deploy/homelab/prove-pg-races.sh`: `PUT /v1/orgs/{org}/acl` with the same `If-Match` etag from 8 concurrent writers across two coordinator replicas on one PostgreSQL 16 database, 50 rounds: exactly one 204 per round, 350 × 412, stored policy and revision always the winner's, 0 lost updates.

### Live lab: two-site routing (3 October 2026)

`deploy/homelab/prove-routing.sh` on Docker context `m3-max` (about 5 minutes;
everything `labs-routing-*`, removed on exit; results table in
`docs/network-resources.md#live-lab-3-october-2026`). Two sites (site A: `ra1`
metric 10 on iptables-nft, `ra2` metric 20 on iptables-legacy; site B: `rb` on
iptables-legacy), an exit node on iptables-nft, an authorised client and a
guest, all on internal Docker networks.

- **Passed:** allowed port behind each router reachable 1 s after resource
  creation; adjacent ports refused with the `BLAKTAIL-FWD` default reject
  counting them on nft and legacy (3 → 4 packets each); a guest that forced
  the site prefix into WireGuard was refused by `BLAKTAIL-FWD` (4 → 5);
  router-to-router traffic both ways. Six resource edits rebuilt and renamed
  `BLAKTAIL-FWD-NEW` over the live, jumped-to chain on all four routers while
  the client connected 150 times: 0 failures, one jump and no staging chain
  left on both backends.
- **Exit node:** only the selecting client reached the Internet host; the
  guest's forced exit traffic was rejected (0 → 2); captures showed 0 packets
  on the exit's Internet uplink from non-exit attempts and 0 non-WireGuard
  packets on the exit client's uplink while it used DNS and HTTP through the
  exit (no DNS or default-route leak).
- **Router loss:** `docker kill` of the primary; the client reached site A
  through the standby after **82 s** (89 s in an earlier run; bound now about 92 s).
- **Bugs found and fixed:** (1) `/updates` ignored a changed `exit_node` when
  the revision was unchanged, so an agent resumed with `--exit-node` never got
  its default route; the long-poll now records the selection and bumps the
  revision (`exit_selection_on_a_long_poll_returns_a_fresh_snapshot`).
  (2) Routing-peer liveness never bumped the revision, so idle clients kept a
  dead router's routes indefinitely; long-polls now re-check online
  route-advertising devices every 2 s per organisation
  (`resources::bump_on_router_liveness_change`,
  `routing_peer_failover_reaches_idle_long_polls`). The long-poll
  `last_seen_at` refresh from the app-connector lab is also required.
- **Still unproven:** IPv6 routing, host-to-host site-to-site without NAT
  (unsupported), physical routers and real WAN links, other Linux
  distributions' iptables builds.
