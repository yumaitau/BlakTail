# Plan, validate and publish multi-surface network changes safely

**Priority:** P1. **Depends on:** drafts 02 (read model), 04 (resources), 07 (policy) and 09 (DNS). **Area:** coordinator transactions plus console.

## Gap and outcome

NetBird offers Control Center draft mode. BlakTail has etag-aware policy/DNS writes and one-step rollback, but no coherent way to preview a linked resource, route and policy change before activation. One-page client-side drafts must not claim atomicity across coordinator objects.

## Scope

- Design versioned, organisation-bound server-side draft containing proposed resource/route/policy/DNS changes. Define validation, actor ownership, expiry, revision preconditions and a single audited publish boundary; if atomic publish cannot be guaranteed, display exact partial-commit/rollback semantics before implementation.
- Preview diff and effective reachability for named test identities, nodes, ports and both IPv4/IPv6. Flag lockout of last owner, exposed default routes, route overlap, deletion impacts and DNS conflicts; require explicit confirmation for risky scope changes.
- Allow safe discard, rebase after etag conflict and rollback to known version without storing secrets in draft payloads. Members may view only authorised summaries, never publish. Do not make an offline browser cache source of truth.

## Acceptance / proof

Concurrent editors cannot overwrite one another; failed validation leaves live policy unchanged; publish records who/when/before-after revision. Integration test verifies resource and access are never temporarily broadly exposed, including coordinator restart, partial failure and cross-org attempts. Browser test verifies preview text matches activated policy. No claim of transactional safety before proof.

**Evidence:** `docs/policy.md`, `docs/org-dns.md`, `docs/admin-api.md`; https://docs.netbird.io/manage/control-center/draft-mode.
