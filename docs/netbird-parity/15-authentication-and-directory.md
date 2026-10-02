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
