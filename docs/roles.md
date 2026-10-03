# Roles, service users and sign-in assurance

Roles are per organisation. A person linked to several organisations holds a
separate role in each, and a role in one never carries into another. The
coordinator enforces the matrix below on every request; the console uses the
same table only to label controls and to fail early.

## Permission matrix

The source of truth is [`permission-matrix.json`](permission-matrix.json).
`blaktail-coord/src/permissions.rs` and `apps/console/src/lib/roles.ts` are both
tested against it, so the two cannot drift silently.

| Permission | Owner | Admin | Network admin | Auditor | Member |
| --- | :-: | :-: | :-: | :-: | :-: |
| View network inventory | ✓ | ✓ | ✓ | ✓ | ✓ |
| Read audit log | ✓ | ✓ | ✓ | ✓ | ✓ |
| Export audit records | ✓ | ✓ | | ✓ | |
| Devices: rename, revoke, delete, tag, node-key lifetime | ✓ | ✓ | ✓ | | |
| Join keys | ✓ | ✓ | ✓ | | |
| Routes and network resources | ✓ | ✓ | ✓ | | |
| Access policy | ✓ | ✓ | ✓ | | |
| DNS | ✓ | ✓ | ✓ | | |
| Private services | ✓ | ✓ | ✓ | | |
| Public ingress: enable, publish, change, re-enable, delete | ✓ | | | | |
| Public ingress: emergency-disable a route | ✓ | ✓ | ✓ | | |
| Webhooks and integrations | ✓ | ✓ | | | |
| Automation credentials (service users) | ✓ | | | | |
| People, roles, SSO, SCIM, sign-in policy and domains | ✓ | | | | |

Everyone in an organisation can approve enrolment of their own untagged device.
Owner, admin and member access is exactly what it was before network admin and
auditor existed. Two narrow points: the coordinator's service-user list now
needs the owner-only permission (the console only ever showed it to owners),
and route approval needs the routes permission rather than the devices one
(both held by the same roles today).

A device keeps the role of the person who enrolled it for policy selectors.
Policies that select `admin` do not match a network admin's devices; add
`network_admin` to the selector if they should. Tag ownership lists are also
literal: listing `admin` as a tag owner does not let a network admin assign it.

The console signs the role into each 60-second coordinator assertion. A
coordinator that does not know a role string rejects the assertion with `401`,
so an older coordinator fails closed rather than guessing.

## Changing roles

Owners change roles in Settings, Members. Each option shows what the role can
do before it is applied. The console refuses a change that would leave the
organisation without an active owner, or without an active password owner when
it has one (the break-glass path if SSO is down). The check and the update run
in one serialisable transaction, so two owners cannot demote each other at
once. Allowed and refused changes are both written to the audit log with the
previous and requested role.

Invitations can grant any role except owner. Promote an invited person to owner
afterwards. Linked identities that hold different roles in one organisation
stay blocked until an owner picks one of those roles; the decision can never
name a role neither membership has.

## Service users

Automation clients are service users. Each has a name, scopes, an expiry
(default 90 days, at most 365) and a `bta_` secret shown once. They have no
console login: their secrets are only accepted by `/api/v1` and `/oauth/token`,
and a console route given one returns `401`. Their writes are audited as
`api:<client id>` with actor role `api_client`.

Owners can, from Settings, Automation:

- **Rotate** — issues a new secret and expiry; the old secret and every OAuth
  access token minted from it stop working in the same transaction.
- **Suspend / resume** — a suspended client cannot mint OAuth tokens, its
  `bta_` secret is rejected, and access tokens already issued are rejected on
  their next request (checked per call, so the bound is immediate).
- **Revoke** — permanent.

## Sign-in policy

Settings, Sign-in policy is per organisation and owner-only.

- **Re-authentication window (step-up).** When set (5–1440 minutes), changes
  to people, roles, SSO, SCIM tokens, sign-in domains, the policy itself and
  service users require a console session created within that window. Older
  sessions get a clear refusal (audited as `auth.step_up_required`); sign out
  and in again. The window is read for the organisation being changed, so a
  session that satisfies a lax organisation never satisfies a stricter one.
- **Require two-step verification for owners and admins.** Applies to password
  sign-ins. Affected people can still sign in and enrol; every coordinator
  write and every security change is refused until they do. An owner signed in
  with a password must have two-step verification on before turning this on. SSO identities rely on the
  identity provider's own MFA policy; BlakTail does not see or add a second
  factor to SSO. Because a person's role is merged across linked identities,
  an SSO sign-in is exempt only while none of their identities with a
  membership in that organisation has a password; otherwise privileged writes
  need the password sign-in with two-step verification.

## Two-step verification (TOTP)

Password identities can turn on an authenticator app in Settings, Account
security (Better Auth `twoFactor`). The TOTP secret and ten single-use recovery
codes are stored encrypted with `BETTER_AUTH_SECRET`. Every password sign-in of
an enrolled identity asks for a code; there is no "trust this device". Ten
failed codes lock that identity's second step for 15 minutes. A password alone
cannot link a TOTP-protected identity into another person.

Lost both the authenticator and the recovery codes? An operator with database
access can reset one identity after verifying the person out of band:

```sql
UPDATE "user" SET two_factor_enabled = false WHERE email = 'owner@example.org.au';
DELETE FROM two_factor WHERE user_id = (SELECT id FROM "user" WHERE email = 'owner@example.org.au');
```

Record why in your own change log; the console cannot audit a direct database
change.

## Verified sign-in domains

Owners add a domain and publish the shown TXT record at
`_blaktail-challenge.<domain>` with value `blaktail-domain-verification=<token>`,
then select Check. A domain can be verified by only one organisation (enforced
by a unique index); once it is, no other organisation can add or verify it.
After an organisation verifies any domain, just-in-time SSO membership accepts
only provider-verified (`email_verified: true`) email addresses in its verified domains, and never an address in a domain
another organisation verified. Organisations with no verified domains keep the
provider allow-list behaviour they had before. Lookups use the console host's
resolver with a 5-second timeout; nothing is re-checked automatically.

## Not yet built

- SCIM or IdP group to role mapping with a drift preview. SCIM still only
  activates and deactivates memberships; roles are set in the console.
- Session inactivity timeout and revoking other sessions on role change. A
  demoted person's next request uses the new role because roles are resolved
  live, but their session stays signed in.
- Reading IdP assurance claims (`amr`, `acr`) to require MFA for SSO.
- Console audit entries for TOTP enrolment and removal.
