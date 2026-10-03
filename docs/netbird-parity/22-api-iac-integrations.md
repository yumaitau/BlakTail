# Extend scoped automation API and provide tested infrastructure-as-code examples

**Priority:** P2. **Depends on:** draft 04 resource and draft 14 permission models; existing #37 API contract. **Area:** coordinator OpenAPI, clients, examples.

## Gap and outcome

NetBird exposes public API resources for networks, groups, routes, policies, peers, setup keys, DNS, events and more. BlakTail already has versioned `/api/v1`, hashed scoped tokens, OAuth client credentials, etags, OpenAPI drift checks and one provider-style contract. Target missing resource lifecycle and ergonomic, safe automation—not another unversioned admin channel.

## Scope

- Gap-audit published OpenAPI against new UI objects, then add only the operations necessary for peer, resource, route, DNS zone, policy test/diff, audit pagination and key metadata. Stable IDs, list pagination, filters, request IDs, idempotency, optimistic concurrency and error semantics required.
- Publish copyable curl and Terraform/provider-style examples on disposable orgs, with read-only by default, scoped credential rotation, import, drift and destroy semantics. Never embed live tokens or state in repo; support Australian self-hosted endpoints, not hard-coded cloud API.
- Ensure every UI operation invokes the same permission and validation layer as API; service clients have separate attribution and bounded rate limits. Generated client/SDK only after contract/e2e proves value.

## Acceptance / proof

Disposable automation creates resource/route/policy/key, reads it, imports/reconciles then removes safely; a read-only client cannot mutate, and wrong-org header fails. Concurrent update produces 409/412 with actionable retry, no lost update. OpenAPI drift and API/console parity tests pass.

**Evidence:** `docs/admin-api.md`, `docs/openapi/admin-v1.yaml`, `blaktail-coord/src/admin.rs`; https://docs.netbird.io/api/introduction, https://docs.netbird.io/api/resources/networks.

## Status (2 October 2026)

**Done:**
- Gap audit of `docs/openapi/admin-v1.yaml` against wave-1 objects. Added (in `admin::api_routes`, handlers in `blaktail-coord/src/automation.rs`, `audit_log.rs`, `notifications.rs`): posture checks list/create/update (version → `412`)/delete; join-key metadata list (`keys:read`) and revoke; audit filters, export (`audit:export`) and chain verify; DNS draft validate; event catalogue; webhook subscriptions. New scopes `keys:read` and `audit:export` (console scope picker updated). Deliberately not exposed: traffic settings/data (owner console only), DNS revision history/preview, private services, service-user lifecycle.
- Console and API share one function per operation (`create_check_as`, `list_join_keys_as`, `revoke_join_key_as`, `validate_draft`, `audit_log::export`, `set_subscriptions`), so the role check and validator are identical; API writes are attributed to `api_client`.
- `examples/automation/`: copyable curl walkthrough and a Terraform example (generic `http` provider read-only by default; opt-in `Mastercard/restapi` posture check with import and destroy), no tokens or state; `terraform validate` passes.
- OpenAPI and `docs/admin-api.md` updated; drift check passes (39 operations).

**Proven by tests:** `tests::events_audit::automation_api_shares_console_permissions_and_validation` (same invalid posture definition and DNS draft give the same status and error on both paths; auditor refused on both; read-only token cannot write; wrong-org header `401`; create/list/update/stale-update `412`/delete lifecycle; join-key list never contains the secret; `keys:read` cannot revoke; unknown key `404` on both paths); export scope tests in `audit_export_is_permissioned_audited_and_org_scoped`.

**Still needs live/field proof or a decision:**
- Terraform example not applied against a live coordinator; drift is only detected for fields it sends.
- No resource/route/policy `/api/v1` beyond what already existed; DNS zone CRUD and policy test/diff over the API remain open.
- Per-client rate limit is the existing 120/min; no separate limit per operation class. A generated SDK/provider is not justified yet.
