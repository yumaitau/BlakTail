# ADR 0008 — AI "agent network" model gateway (draft 24)

- Status: **Accepted** — 3 October 2026, product owner
- Supersedes: the 2 October 2026 recommendation to reject (kept below as context)

## Context

Another private-networking product added a separate "Agent Network" area for
AI providers, model policies, usage accounting and prompt/response logs.
BlakTail's purpose (`PRODUCT.md`) is an open, self-hosted private path between
an organisation's devices with identity, policy, keys and operational data
under organisational control. An AI model gateway touches a different class
of data: provider credentials, prompt and response content, token accounting
and cultural/IP consent over what is sent to a model.

The earlier draft recommended rejecting the feature because routing prompts
through a BlakTail component could imply onshore guarantees BlakTail cannot
make, and because prompts may contain Indigenous Cultural and Intellectual
Property (ICIP). The product owner approved building it on 3 October 2026 on
the condition that those concerns become hard requirements rather than
reasons to stop.

## Decision

Build an organisation-run gateway, `blaktail-agentgw`, that runs on an
enrolled node and is reached only over the BlakTail overlay. The coordinator
holds providers, per-agent keys and their policies and authorises every
request; the gateway forwards to OpenAI-compatible upstreams (self-hosted
Ollama or vLLM first) and reports token usage back. The console gets its own
**Agents** navigation group (`/agents`). Network policy (who can reach the
gateway) and model policy (what a key may do) stay separate.

## Hard requirements (sovereignty and ICIP)

These are release conditions, enforced in code and covered by tests:

1. **Never public.** The gateway refuses the unspecified address and any
   non-overlay, non-loopback address; RFC 1918 binds need an explicit lab
   flag. Reachability is governed by existing BlakTail access policy.
2. **Declared data location on every provider.** Each provider must declare a
   free-text location and an explicit `onshore`/`offshore` residency (no
   default). The console shows it wherever the provider appears and labels it
   as *declared* — BlakTail cannot verify where a third party processes data.
3. **Offshore forbidden by default.** Requests that would reach an offshore
   provider are refused until an **owner** changes the organisation policy,
   with a confirmation naming ICIP. Offshore providers must use HTTPS.
4. **Prompt logging off by default.** `metadata` keeps timestamps, model and
   token counts (90 days). `full` stores prompts and responses and needs an
   **owner**, an explicit ICIP acknowledgement and a retention of at most
   30 days; stored content is sealed with the coordinator secret, purged at
   expiry, dropped immediately when the key leaves full logging or is
   revoked, and reading it is owner-only and audited.
5. **Secrets.** Provider credentials are sealed at rest with the coordinator
   secret (the same sealing helper as private-service CA keys), are never
   returned after creation, never written to audit details and never logged.
   They leave the coordinator only inside an authorisation grant to an
   authenticated gateway node. Agent keys are shown once and stored as
   SHA-256 hashes.
6. **Fail closed.** If the coordinator is unreachable, a redaction pattern
   cannot be compiled, or a quota cannot be reserved, the request is refused.
7. **Organisation isolation and least privilege.** Keys, providers, usage
   and gateways are organisation-scoped; `ManageAgentGateway` is owner and
   admin, `ViewAgentUsage` adds auditor; members and network admins have
   neither.
8. **No residency over-claims.** Copy never says "onshore AI". It says where
   the provider is declared to process data.

## Consequences

- The coordinator now stores high-value secrets (provider credentials) and,
  when an owner opts in, prompt content. Both are sealed; key rotation of the
  coordinator secret would need a re-seal migration (not built).
- Quotas are per UTC day and checked before a request; a single request can
  overshoot the token quota by its own size.
- Anthropic Messages API translation is not built; Claude models can be used
  only through an OpenAI-compatible endpoint.
- Usage is metered from the upstream's `usage` object; when an upstream sends
  none, the gateway estimates (characters / 4) and marks the record estimated.

## Original considerations (2 October 2026)

- No concrete user story had been recorded that a network product must solve
  rather than an application-layer gateway.
- Most hosted model providers process data offshore.
- Consent, retention and redaction rules belong to the organisation and the
  holders of the knowledge in the prompt, not to network control-plane policy.
- Provider keys, prompt logging and per-agent identity add high-value secrets
  to the coordinator and console.

Each is now addressed by a hard requirement above rather than by rejection.
