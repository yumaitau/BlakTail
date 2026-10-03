# NetBird feature comparison and BlakTail issue drafts

Research snapshot: 2 October 2026. These are **issue-ready drafts, not GitHub issues**. No issues were posted: the configured `gh` login for `jusso-dev` reports an invalid token, and the browser connector reports `Codex auth token is unavailable`. Publish only after checking duplicates again and explicitly approving the exact batch. Each numbered file is a standalone GitHub issue body; use its first heading as the title. Proposed priorities are planning aids, not existing repository labels.

## Evidence and interpretation

- NetBird upstream source: https://github.com/netbirdio/netbird and its separately maintained dashboard https://github.com/netbirdio/dashboard. The dashboard's `src/app/(dashboard)` routes and e2e tests were inspected alongside https://docs.netbird.io/sitemap.xml and feature documentation. A source route does **not** prove feature availability in every self-hosted edition.
- BlakTail source of truth: `README.md`, `PRODUCT.md`, `docs/project-status.md`, `docs/console.md`, `docs/policy.md`, `docs/identity.md`, `docs/org-dns.md`, `docs/admin-api.md`, actual `apps/console/src/app` routes/components, coordinator/agent modules, and the public issue history (all returned issues were closed at research time). A closed issue or pure helper module does **not** prove the user journey end to end.
- Do not clone NetBird's brand, UI, copy, proprietary implementation, pricing, MSP billing, or hosted-service positioning. Adopt capabilities only where they fit BlakTail's open, self-hosted, Indigenous-organisation-first and onshore design. Verify NetBird licensing/edition on each implementation decision; comparison is not permission to copy source.
- Priority: **P0** security/release correctness; **P1** core product workflow; **P2** optional breadth; **decision** architecture/product gate before implementation. Dependencies describe sequencing, not a commitment to ship all items.

## Coverage map

| NetBird surface | Current BlakTail evidence | Drafts / disposition |
| --- | --- | --- |
| Peer inventory, names, approval, groups, setup keys | Devices, Access, Join keys, audited rename/revoke and tags exist; no equivalent peer detail/troubleshooting workspace | [01](01-console-information-architecture.md), [12](12-peer-lifecycle-and-diagnostics.md), [16](16-setup-keys-and-onboarding.md) |
| Control Center live topology, route and policy view, draft changes | No topology/graph or staged publish flow; existing policy/DNS publish use etags and one-step rollback | [02](02-control-center-topology.md), [03](03-safe-change-planning.md) |
| Networks/resources, network routes/site-to-site, IPAM | Subnet and exit routes, approval and IPAM engine exist; network resources and purpose-built management UI do not | [04](04-network-resources.md), [05](05-routing-workspace.md), [26](26-ipam-console.md) |
| Access policies, groups, posture and EDR | Versioned policy editor and tests, group selection, OS/version inventory; no proven policy-enforced posture/EDR; SSH editor itself warns agent enforcement incomplete | [07](07-policy-explain-and-ssh.md), [08](08-posture-and-edr.md) |
| DNS nameservers, settings, custom zones | Organisation DNS JSON, split DNS, search domains and A/AAAA records in Settings; no dedicated zone/nameserver lifecycle UI | [09](09-dns-workspace.md) |
| Private services, reverse proxy, app access | `https_services` and `connectors` contain contract/helpers; issue #47/#49 closed, but no equivalent console route or proved live end-to-end service | [06](06-domain-app-connectors.md), [10](10-private-service-publishing.md), [11](11-public-reverse-proxy.md) |
| Browser client, SSH/RDP, remote jobs | Agent/CLI SSH and policy scaffolding; no browser remote-access session or bounded jobs UX | [13](13-browser-remote-access.md) |
| Team roles, directory sync, SSO, permissions, MFA | Invite/member/owner/admin, one OIDC issuer per organisation, SCIM and linked identities exist; least-privilege roles/MFA/sign-in controls need separate design | [14](14-roles-and-permissions.md), [15](15-authentication-and-directory.md) |
| Audit, traffic events, notifications, event streaming | 100 most recent admin changes and optional flow contract; webhooks for selected mutations; no traffic/event operations workspace | [17](17-audit-and-traffic.md), [18](18-notifications-and-event-streaming.md) |
| Client platforms and profiles | Linux/macOS agents, macOS UI, direct-UDP iPhone; Android source and Windows/Linux shells are not verified shipped products | [19](19-platform-clients.md), [20](20-client-profiles-and-connectivity.md) |
| REST API, automation, operations, relay | Versioned scoped API and OpenAPI, metrics, Postgres HA, Australian UDP relay; release artifacts absent and multi-relay paths unproven | [21](21-relay-and-connectivity-proof.md), [22](22-api-iac-integrations.md), [23](23-self-hosted-lifecycle.md) |
| Agent Network / AI model gateway | NetBird has distinct Agent Network dashboard/docs; outside present private-network purpose | [24](24-agent-network-decision.md) **decision**, not assumed parity |
| Post-quantum / client cryptography | Existing WireGuard cryptography; no evidenced hybrid post-quantum tunnel | [25](25-post-quantum-threat-review.md) **decision** |
| MSP/tenant billing, customer portal | Linked login identities and organisation separation exist; hosted billing and distributor mechanics conflict with self-hosted scope | Explicitly **not** cloned; tenant-delegation requirements can be scoped separately if requested |

## Existing issue overlap and proof limits

Do not reopen or duplicate #5, #11, #12, #24, #27, #29, #31, #32, #36–#40, #43, or #47–#51 without checking their completed acceptance criteria and actual current code. Drafts explicitly target missing UI, live path, platform validation, or extension beyond those tickets. `docs/project-status.md` reports an August 2026 Sydney source-commit smoke, **not** public-release, independent-NAT forced-relay, Windows, or iPhone-relay proof. Existing `blaktail-coord/src/{flows,connectors,https_fallback,https_services}.rs` are not evidence that those services are deployed or reachable. In particular, preserve the current onshore-by-deployment responsibility rather than promising automatic data residency.

## Publication checklist

1. Refresh upstream docs/dashboard and the BlakTail checkout; source pages may change. Recheck open **and closed** GitHub issues by title and body.
2. Review each issue for scope, dependencies, priority, cultural/product fit, edition/licensing, owner, and external exposure. Decide whether decision-gate issues should be posted.
3. Fix GitHub authentication, then obtain immediate approval for the exact issue batch before submitting. Post bodies individually, verify every returned URL/title/body, and link dependencies using actual issue numbers. Do not apply labels or milestones that do not exist.

## Implementation status (3 October 2026, branch `netbird-parity`)

Each draft ends with its own **Status** section listing what is done, what tests prove, and what still needs live or field proof. Summary:

| Draft | State |
| --- | --- |
| 01 navigation, 02 topology, 03 change drafts | Built and tested; browser/accessibility tests and Postgres-specific publish races not yet run |
| 04 resources, 05 routing, 26 IPAM, 06 connectors | Built and tested, including router-side forwarding enforcement and persisted exit-node choice; no two-site, router or connector field run yet |
| 07 explain and SSH, 08 posture | Built and tested; Linux only enforces port/SSH rules, real sshd and two-node checks not run; MDM/EDR adapters are design only (ADR 0005) |
| 09 DNS, 10 private services | DNS built and tested; services reach certificate issuance, but no serving-agent listener exists yet |
| 12 peer lifecycle, 16 enrolment | Built and tested; `--join-key` argument removed (stdin or `BLAKTAIL_JOIN_KEY` only) |
| 13 browser access, 11 public ingress, 24 agent network, 25 post-quantum | Decision records only (ADRs 0006–0009); proposed, awaiting owner sign-off |
| 14 roles, 15 sign-in | Built and tested, including Postgres; SCIM group-to-role mapping not built |
| 17 audit and traffic, 18 notifications, 22 API and IaC | Built and tested; no agent sends traffic data yet; Terraform example validated, not applied |
| 19 clients, 20 profiles, 21 relay, 23 operations | Operator health, signed-release path, multi-relay failover, tray, WSS relay fallback and mobile relay (iPhone UDP+WSS, Android UDP) built; single-host relay, failover and WSS labs passed; no device, independent-NAT or release drill run |

Three independent security reviews (coordinator authorisation, data-plane enforcement, console sign-in) ran after merging; every confirmed finding was fixed with a regression test.
