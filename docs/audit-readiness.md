# Independent assessment readiness

This is the public control matrix for [#52](https://github.com/jusso-dev/BlakTail/issues/52).
It is not an independent audit, IRAP package, or certification. `SECURITY.md`
remains the reporting contract.

Use this table when commissioning an assessor. Every row names the threat-model
control, the current automated evidence, and the residual gap an independent
review still has to cover.

| Control | Threat-model / product rule | Automated evidence today | Residual for an assessor |
| --- | --- | --- | --- |
| Region pin | Australian allow-list; public health is status-only | `scripts/config-contract-test.sh`, coordinator/relay startup validation | Live deployment region and proxy headers |
| Key file modes | `0600` private key and state; refuse group/world readable keys | Agent tests in `blaktaild` | Stolen-laptop / unlocked-disk exercise |
| Bootstrap lock | Public signup disabled; one first-owner ceremony | Console bootstrap/auth HTTP e2e | Host-level recovery and invitation abuse |
| Session / HMAC | Console issues sessions; coordinator verifies HMAC | Console tests, coordinator assertion tests | Clock skew, replay, and secret rotation drill |
| Join keys / node tokens | Shown once, hashed at rest, single-use | Coordinator join/reauth/revoke tests | Operator copy/paste and log-leak review |
| Admin API | Scoped `bta_` tokens, OpenAPI, body/rate bounds | `scripts/admin-openapi-drift.sh`, admin API tests | Webhook/event delivery and operator-held secrets |
| ACL / policy | Deny wins; explicit defaults; groups; tag owners; offline tests; etag rollback | `blaktail-coord check-policy`, coordinator policy tests, homelab ACL prove | Packet-level ports/SSH and two-agent allowed-service proof |
| MagicDNS | Authoritative-only; no public forward of the suffix | DNS unit/wire tests; Linux AWS smoke | Fresh macOS join and no-leak capture |
| Routes / exit | Advertisement ≠ approval ≠ distribution | Coordinator route tests; `ADVERTISE_SUBNET` drill flag | Live subnet and DNS-while-exit packets |
| Relay / NAT | Authenticated AU relay; hole punch; fallback | Relay tests; `FORCE_RELAY=1` two-VM flag | Forced-relay metric delta on two NATs |
| Metrics / audit | Private scrape, bounded labels, actor-attributed audit | `scripts/conformance/prove-observability.sh`, homelab Compose scrape | Retention/tamper and public-listener re-check |
| Supply chain | gitleaks, cargo-deny, unsigned CI packages never published | Security workflow, package inspect jobs | Signed release, SBOM, hosted APT/RPM |
| Diagnostics | Redacted config and support bundles | `blaktail-config` contract tests | Assessor bundle against a disposable lab |
| Teardown | Guarded AWS destroy; no production SaaS | `scripts/aws-e2e/destroy.sh` static checks | Fresh tagged-resource absence after a live run |

## Freeze for an assessor

Do not start an independent review against a moving `main` commit. Freeze:

1. A git tag and its lockfiles (`Cargo.lock`, `bun.lock`).
2. Schema versions (coordinator and console migrations).
3. The exact Compose/AWS topology and region pin.
4. `SECURITY.md` reporting channel and response targets.

## Explicitly not ready

- No signed/notarized agent release (#33).
- No independent assessor engaged.
- No public residual-risk report.
- Coordinator-compromise admission (#46) has a first slice: HMAC admission
  statements with epoch monotonicity plus rotation-state tables (schema v18);
  specialist cryptographic review is still required before production use.
- Windows and Linux desktop agents are out of scope.

Re-run this matrix before each major protocol, auth, or release change.
