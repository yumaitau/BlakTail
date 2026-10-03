# Fine-grained organisation roles and service users without cross-network escalation

**Priority:** P1. **Depends on:** existing owner/admin/member lifecycle and scoped API credentials. **Area:** authorisation model, console, audit.

## Gap and outcome

NetBird separates owner, admin, network admin, auditor, regular user and service users. BlakTail has owner/admin/member and per-token scopes; administrative capabilities often depend on a broad `canMutateTailnet` check. Add role granularity only where it resolves real delegation needs, keeping the last password owner protected.

## Scope

- Define permission matrix for peer lifecycle, join keys, routes, DNS, policy, people, SSO/SCIM, event export and API clients. Owner-only security and billing-like operations remain separate; no implicit escalation by linked identities or multiple organisation roles.
- Server-side enforcement across console actions, coordinator API and automation tokens; a role's UI affordances reflect server permissions but do not define them. Service users have scoped non-interactive identity, secret rotation, expiry and audit attribution; cannot log into human UI.
- Provide role editor with impact preview, explicit organisation/target and last-owner safety. Plan migrations from three roles without changing existing access unexpectedly. Show permission reason on disabled controls.

## Acceptance / proof

Matrix-driven tests exercise each permission for human browser, direct API and service client; cross-org role combination never grants higher role in another org. Owner demotion refuses last-owner loss. Suspended service identity cannot mint new tokens; already-issued credentials are invalidated within declared limit. Every role change is audited.

**Evidence:** `apps/console/src/lib/roles.ts`, `apps/console/src/components/membership-manager.tsx`, `blaktail-coord/src/admin.rs`; https://docs.netbird.io/manage/team/user-roles, https://github.com/netbirdio/dashboard/tree/main/src/app/%28dashboard%29/team/service-users.

## Status (2 October 2026)

**Done:** `network_admin` and `auditor` roles in the coordinator (`Role`, `permissions.rs`) and console (`OrgRole`, table-driven `lib/roles.ts`), both pinned to `docs/permission-matrix.json`. Every former `Role::Member`/`Role::Owner` handler check in `lib.rs`, `admin.rs`, `webhooks.rs` and `wg_only.rs` now calls `require(&session, Permission::…)`; human `/api/v1` calls map each scope to a permission. All console `canMutateTailnet` and `ctx.role === …` checks use `can`/`permissionReason`, and API denials state which roles can act. Membership editor (Settings, Members) assigns any role with impact text, shows the organisation and actor role, explains disabled controls, refuses losing the last active owner or last active password owner in a serialisable transaction, and audits allowed and refused changes with previous/requested role. Invitations can grant every non-owner role; ACL selectors accept the new roles. Service users: rotate, suspend and resume (`blaktail-coord/src/service_users.rs`, migration slot 26 adds `suspended_at`/`rotated_at`, console actions in `app/settings/actions.ts`), audit actor role `api_client` with `api:<id>`. Owner, admin and member behaviour is unchanged except that the coordinator's service-user list is owner-only, as the console already presented it. Docs: `docs/roles.md`.
**Proven by tests:** Rust `permissions::tests` (fixture parity, least privilege, unknown roles), `console_permission_matrix_is_enforced_per_role` (every role × 15 representative coordinator routes), `api_client_scope_matrix_and_no_console_login` (every scope × route, service secrets rejected by console routes), `role_assertions_fail_closed_and_stay_in_their_organisation` (unknown role 401, one person network admin in A and auditor in B cannot carry either role across), `service_users_rotate_suspend_and_attribute_audit` (suspension blocks token minting and invalidates issued access tokens immediately, rotation kills old secret and tokens, admin/cross-org denied, audit attribution). Also run against Postgres 16. Bun `scripts/roles.test.mjs` (fixture parity, cross-org role resolution and stale/escalating conflict decisions, last-owner and break-glass rules). HTTP `scripts/roles-auth-e2e.mjs` against Postgres and a production build: last-owner demotion refused and audited, role change audited, network admin cannot change people, unknown role rejected.
**Still needs live/field proof or a decision:** a reviewer's sign-off on the matrix (in particular admin without service-user management, network admin without audit export); policy-selector migration guidance for orgs that start using network admin; SCIM/IdP group→role mapping; revoking other sessions on demotion (roles are resolved live, sessions are not ended).
