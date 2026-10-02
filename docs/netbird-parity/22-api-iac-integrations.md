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
