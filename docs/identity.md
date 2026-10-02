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
domains, and a domain verified by another organisation is never accepted; see
[roles.md](roles.md#verified-sign-in-domains). Two providers that return the same email do not merge
accounts; an already-signed-in person can explicitly link an issuer+subject from
the callback.

## Membership

Membership states are `invited`, `active`, `suspended`, and `removed`. Session
resolution only includes `active` rows, so a suspend or remove blocks console and
management actions immediately without deleting devices. Roles are owner,
admin, network admin, auditor and member ([roles.md](roles.md)). The last active
owner cannot be demoted, suspended or removed, and neither can the last active
password owner while one exists.

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
