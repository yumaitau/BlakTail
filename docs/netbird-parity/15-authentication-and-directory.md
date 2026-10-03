# Harden login policy: MFA, session re-authentication, sign-in domains and directory sync

**Priority:** P1. **Depends on:** draft 14 permissions; preserve existing OIDC/SCIM and break-glass owner. **Area:** auth, directory, console.

## Gap and outcome

BlakTail supports one OIDC issuer per organisation, invitations, SCIM, membership state and explicit identity linking. NetBird documents MFA, sign-in domains, periodic user authentication, IdP sync and user approval. BlakTail's linked-login promise demands clear per-organisation security boundaries; never merge identities solely because email matches.

## Scope

- Threat-model MFA/step-up for password owner and privileged writes, session age, provider assurance claims, inactivity and revocation. Keep at least one recoverable password owner with protected MFA recovery; provider outages cannot lock all owners out.
- Domain verification and invitation/user-approval lifecycle, with safe Just-in-Time membership defaults. Specify how one human linked to several orgs meets the strongest required assurance for each action.
- Reconcile SCIM/IdP group changes with explicit group mappings, deprovision grace, tombstones, drift preview and rate limits; choose limited supported provider adapters rather than implying every vendor works. Document encrypted secret storage and onshore IdP data flow.

## Acceptance / proof

Cross-org login tests prove a weaker org's session cannot bypass stronger org's step-up. Suspended user loses new API and agent access as specified, while already-enrolled devices follow documented device-owner policy. Recovery owner can sign in during IdP outage. Domain proof cannot claim another organisation's verified namespace.

**Evidence:** `docs/identity.md`, `apps/console/src/components/{oidc-provider-manager,scim-manager,identity-settings}.tsx`; https://docs.netbird.io/manage/settings/multi-factor-authentication, https://docs.netbird.io/manage/settings/enforce-periodic-user-authentication, https://docs.netbird.io/manage/team/idp-sync.

## Status (2 October 2026)

**Done:** Per-organisation sign-in policy (`organisation_sign_in_policy`, console migration `0008_roles_and_sign_in_policy.sql`, `lib/auth-policy{,-core}.ts`, Settings, Sign-in policy). Step-up: a re-authentication window of 5–1440 minutes enforced on membership/role changes, invitations by owners, OIDC provider changes, SCIM token minting, sign-in domains, the policy itself and service-user create/rotate/suspend/revoke; refusals are audited. TOTP via Better Auth 1.7.1 `twoFactor` (encrypted secret, ten encrypted single-use recovery codes, account lockout, no trusted-device bypass) with enrolment in Settings, Account security and a code step on the web and desktop sign-in pages. Policy "require two-step verification for owners and admins" gates every coordinator write (in `coordFetch`) and every security change for password identities while sign-in and enrolment stay open; an owner cannot enable it without enrolling first. Password-only linking of a TOTP-protected identity is refused. Verified sign-in domains via DNS TXT at `_blaktail-challenge.<domain>`; a partial unique index makes a verified domain belong to one organisation; JIT SSO membership is limited to verified domains once any exist and never accepts another organisation's verified domain. Break-glass: last active password owner cannot be demoted, suspended or removed. Docs: `docs/roles.md`, `docs/identity.md`.
**Proven by tests:** Bun `scripts/roles.test.mjs` (step-up window per organisation incl. lax-vs-strict cross-org case, MFA applicability by role and identity type, domain normalisation, exact TXT proof, JIT refusal for another organisation's domain). HTTP `scripts/roles-auth-e2e.mjs` (added to CI) against Postgres 16 and `next start`: stale session refused and audited then fresh sign-in allowed; TOTP enrolment stores no plaintext secret or recovery code; enrolled password sign-in returns no session until a valid code, wrong code rejected; recovery code works once; MFA policy blocks an admin's coordinator write without reaching the coordinator while the admin can still sign in, and the enrolled owner's write proceeds. Existing `http-auth-e2e.mjs` still passes with the plugin enabled.
**Still needs live/field proof or a decision:** SCIM/IdP group→role mapping with drift preview, deprovision grace and tombstones (not built; SCIM still only (de)activates); MFA for SSO via `amr`/`acr` claims; inactivity timeout and session revocation on suspension/demotion; DNS verification against real public DNS and periodic re-checks; a recovery-owner sign-in drill during a real IdP outage; audit entries for TOTP enrol/disable; threat-model review by someone other than the implementer.
