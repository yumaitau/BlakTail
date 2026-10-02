# Release-ready self-hosted control plane: upgrades, backup, observability and documented HA

**Priority:** P0 release, P1 operations UI. **Depends on:** existing #27/#33/#34 and #41 configuration. **Area:** deployment, packaging, operator diagnostics.

## Gap and outcome

NetBird documents self-hosting versus managed operation and provides client installation paths. BlakTail is source-build pre-release: its Sydney AWS smoke proved a particular commit, Postgres coordinator HA and backup restore, not published release or generic self-hosted upgrade safety. A Status page reports coordinator availability, not operational readiness.

## Scope

- Publish reproducible signed releases and clean-host installs; version compatibility matrix for console/coordinator/relay/agents, staged migration, expand/contract schema, rollback constraints and disaster recovery. Prove on Linux and macOS Compose and guarded Sydney production-shaped environment separately.
- Onshore backup/restore for console identity plus coordinator state, logs and object stores; verify encryption, PITR, secrets rotation, RPO/RTO and data export/deletion. No automatic residency claim for operator-selected DNS, telemetry, IdP or support.
- Protected operator health view for component version, DB migration, queue/outbox, relay capacity, cert expiry, DNS/SSO and last backup proof, with role-safe redaction and no key material. Keep public `/status` narrow.

## Acceptance / proof

Version N to N+1 and failed migration rollback in disposable clone preserve devices, memberships and policy. Restore into new private environment and prove login plus two-node reachability, not just SQL counts. Signed package downloaded and installed on clean hosts; support bundle contains no secrets. Failure injection validates HA and recovery documentation.

**Evidence:** `docs/releases.md`, `docs/project-status.md`, `docs/e2e/aws-fargate-run.md`, `apps/console/src/app/status/page.tsx`; https://docs.netbird.io/about-netbird/self-hosted-vs-cloud.
