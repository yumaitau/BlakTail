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
