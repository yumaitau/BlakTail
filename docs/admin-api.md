# Admin API versioning

The public automation contract is `/api/v1`. It is distinct from node protocol
routes and from console HMAC assertions.

## Compatibility

- Additive fields, endpoints, and optional headers stay inside `/api/v1`.
- Breaking changes get a new major path (`/api/v2`) and a documented deprecation
  window on the previous version.
- OpenAPI lives at [openapi/admin-v1.yaml](openapi/admin-v1.yaml).

## Credentials

Owners mint `bta_` tokens in Settings. Secrets are shown once and stored as
SHA-256 hashes. Send `Authorization: Bearer bta_…` and
`X-BlakTail-Organisation`. Node tokens, join keys, and anonymous callers are
rejected.

`POST /oauth/token` accepts the OAuth 2.0 `client_credentials` grant. The
client id is the automation client UUID; the client secret is the shown-once
`bta_` token. Credentials may be sent as HTTP Basic or form fields. A
successful exchange mints a distinct hashed `bto_` access token that expires
in at most one hour, plus `organisation_id` so callers can set
`X-BlakTail-Organisation`. The static `bta_` secret remains a bootstrap
Bearer option. Requested `scope` must be empty or a subset of the registered
scopes; the access token still carries the registered set. Revoking the
client rejects later access tokens. Webhook destinations are minted separately
and their signing secrets are not OAuth credentials.

Clients are service users: they cannot sign in to the console, and their writes
are audited as `api:<client id>` with actor role `api_client`. Owners can rotate
a client (`POST /v1/orgs/{org}/api-clients/{id}/rotate`, optional
`{"expires_in_seconds": n}`), which returns a new shown-once secret and
invalidates the old secret and all its access tokens at once, or suspend and
resume it (`…/suspend`, `…/resume`). Suspension blocks token minting and
rejects already-issued access tokens on their next request. These are console
routes authorised by the signed console assertion, not `/api/v1` operations.
Human console sessions calling `/api/v1` need the role permission matching
each write scope ([roles.md](roles.md)).

## Writes

- Policy PUT requires the current `etag`. `{"rollback": true}` restores the
  previous document. GET includes `defaults`, a visible `generated` legacy
  same-tag rule when that default is active, `revision`, and `has_previous`.
- `GET`/`PUT /api/v1/dns` publishes organisation DNS settings. Writes need
  `dns:write` and the current `etag`. `{"rollback": true}` restores the previous
  revision.
- `POST /api/v1/keys` honours `Idempotency-Key` (8–128 characters). Reusing a
  key with a different body returns `409`.
- Request bodies are rejected above 64 KiB (`413`).
- Each `bta_` client is limited to 120 requests per 60-second window (`429`).
- Errors use `{ error, code, message, request_id }`.
- CI runs `scripts/admin-openapi-drift.sh` so `docs/openapi/admin-v1.yaml`
  stays aligned with `api_routes()` in `blaktail-coord`.

A disposable smoke against a running coordinator:

```sh
scripts/admin-api-smoke.sh https://coord.example ORG_UUID bta_token
```

CI also runs an in-process Terraform/provider-style contract
(`admin_api_provider_contract_manages_device_lifecycle`) that mints a `bta_`
client, enrols a device from a minted key, renames it without changing the
WireGuard identity, publishes policy and DNS with etags, tombstones the device,
and proves a read-only token cannot write. `POST /oauth/token` mints a
short-lived `bto_` access token for the `client_credentials` grant. Webhook
delivery is HTTPS-only: owners create destinations at `/api/v1/webhooks`,
policy and DNS publishes write a transactional outbox, and the coordinator
signs `t={unix},v1={hmac}` over `{timestamp}.{body}`. The destination
signing secret is shown once and stored as `bte1.` ChaCha20-Poly1305
sealed with a key derived from the coordinator HMAC secret. Legacy
plaintext `btw_` rows still open. Loopback, private, link-local, and
metadata targets are rejected. Owners and admins can also create and
disable destinations from Settings. Device enrol, rename, revoke, and
delete write the same outbox. Console owners enqueue `membership.updated`
after a membership change. Timeout, 429, and redirect failures increment
attempts and stay in the outbox; metadata and private destinations are
rejected at create time.
