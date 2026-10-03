# Identity federation and break-glass access

Organisation SSO is optional. Password accounts created at bootstrap or invitation
remain the on-host recovery path.

## Provider model

Each organisation may enable one HTTPS OpenID Connect issuer. The console:

- discovers `/.well-known/openid-configuration` and pins the issuer exactly
- uses Authorization Code + PKCE S256, `state`, `nonce`, and a 10-minute callback
- verifies the ID token signature against the provider JWKS (`RS256` or `ES256`)
- binds `issuer` + `subject` in `external_identity`; email is never the durable key
- encrypts the client secret with `BETTER_AUTH_SECRET` and never renders it again

Just-in-time membership is off unless an owner enables it. Domain allow-lists
require a verified email. Once the organisation verifies a sign-in domain by
DNS TXT, just-in-time membership only accepts that organisation's verified
domains with `email_verified: true`, and a domain verified by another organisation is never accepted; see
[roles.md](roles.md#verified-sign-in-domains). Two providers that return the same email do not merge
accounts; an already-signed-in person can explicitly link an issuer+subject from
the callback if their session was created within the last 15 minutes (or the
organisation's tighter re-authentication window).

## Membership

Membership states are `invited`, `active`, `suspended`, and `removed`. Session
resolution only includes `active` rows, so a suspend or remove blocks console and
management actions immediately without deleting devices. Roles are owner,
admin, network admin, auditor and member ([roles.md](roles.md)). The last active
owner cannot be demoted, suspended or removed, and neither can the last active
password owner while one exists.

## Directory provisioning (SCIM)

Settings → Directory mints an organisation SCIM bearer token (stored only as
a SHA-256 hash). The identity provider points at `/api/scim/v2`:

- `Users`: create (`POST`), list with `userName eq` filter, get, `PATCH`
  `active`, and `DELETE` (same as deactivate).
- `Groups` (RFC 7643 Group, RFC 7644 operations): `GET /Groups` with
  `displayName eq` filter and `startIndex`/`count`, `POST`, `GET`, `PUT`,
  `DELETE`, and `PATCH` with `add`/`remove`/`replace` of `members`,
  `remove` of `members[value eq "id"]` (Okta), value-list removes (Entra ID),
  and `replace` of `displayName`/`externalId`. Other operations and filters get
  a SCIM 400. Members must already be users provisioned in the same
  organisation; display names are unique per organisation (409).

A token only ever sees its own organisation: another organisation's groups
and users are 404, and a missing or unknown token is 401. Group writes are
audited in the console audit log (`scim.group_created`, `.group_updated`,
`.group_deleted`).

## Directory groups and roles

Owners map identity-provider groups to roles in Settings → Directory group
roles. A mapping names a source, `scim` (a SCIM Group's `displayName`) or
`oidc` (a value in the ID token or userinfo `groups` claim, recorded for
each member at their latest sign-in), a group name (matched without regard to
case) and a role.

- **Precedence:** a member in several mapped groups gets the highest role
  (owner > admin > network admin > auditor > member).
- **No match:** a role set earlier by a mapping falls back to member; a role
  an owner set by hand is left alone. Changing a role by hand marks it manual
  again.
- **Owner:** no mapping can grant owner, and mapped changes never touch an
  existing owner, unless an owner turns on *Allow a directory group to grant
  owner*. Even then a change that would remove the last active owner or the
  last active password owner is shown as blocked and never applied.
- **Drift preview, then apply:** group pushes and sign-ins never change roles
  on their own. *Preview role changes* lists each person, current and new
  role, the groups responsible and any block. *Apply* re-plans inside a
  serializable transaction and refuses if anything changed since the preview.
  Each change is audited (`membership.role_mapped`) and raises the
  `membership.role_changed` webhook event; the run is audited as
  `directory.mapping_applied`. Mapping and setting changes need the
  organisation's step-up and MFA rules (`directory.mapping_added`,
  `.mapping_removed`, `.settings_updated`).

**Deprovisioning.** When the provider deactivates (or deletes) a user, the
membership is suspended at once, so access stops immediately, and a deadline
is set from the organisation's grace period (default 7 days, 0–90). Inside
the grace period, reactivation restores the membership with its role. After
it, the next SCIM request or preview turns the membership into a
**tombstone**: status `removed`, `tombstoned_at` set, row kept for audit
(`membership.tombstoned`). Reactivating a tombstone starts again as a
member. A grace period of 0 tombstones immediately. SCIM never deactivates an
owner.

## Break-glass

Keep at least one password owner; the console refuses changes that would remove
the last active one. That account is independently rate-limited, audited, and
scoped to its organisation. Provider outage, JWKS rotation failure, or a disabled
provider must not prevent that owner from signing in. If it uses two-step
verification, keep its recovery codes offline; an organisation's MFA rule never
blocks sign-in or enrolment, only changes.

## Claims retained

The console stores issuer, subject, optional email snapshot, last successful
authentication time, and membership role/status. Access tokens from the IdP are
not persisted. See [privacy.md](privacy.md).
