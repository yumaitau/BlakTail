# Decide whether NetBird-style Agent Network belongs in BlakTail at all

**Priority:** decision only. **Depends on:** product owner approval; no implementation before separate charter. **Area:** product scope, AI gateway security.

## Gap and outcome

As of research snapshot, NetBird has a distinct Agent Network section for AI providers, policies, usage and logs, plus dashboard Connect/Providers/Policies/Usage/Configuration routes. BlakTail is a self-hosted private-network product; an AI model gateway, token accounting and prompt/response governance are a separate product domain. Record explicit adopt/defer/reject choice rather than slipping AI into network parity.

## Decision work

- Identify concrete Indigenous-organisation user need and overlap with existing Yuma ecosystem, not competitor feature count. Decide whether gateway runs onshore and whether model providers, prompts or metadata leave Australia; map cultural/IP consent, retention and contractual boundaries.
- If approved, independently threat-model provider credentials, prompt/data redaction, tenant quotas, per-agent identity, allowlisted tools, usage logs, billing/cost and incident controls. Keep control-plane auth and network policy separate from model policy.
- Scope smallest proof (one self-hosted provider, one policy, explicit audit) with opt-in install; no claims of NetBird feature parity or copying its interface.

## Acceptance / proof

Written decision with owner, user evidence, architecture, sovereignty review and go/no-go criteria. If deferred/rejected, close with rationale; do not create empty Agent Network nav. If adopted, follow-up technical issues specify source and retention of every sensitive data field before any inference traffic.

**Evidence:** `PRODUCT.md`, `README.md`; https://docs.netbird.io/agent-network, https://github.com/netbirdio/dashboard/tree/main/src/app/%28dashboard%29/agent-network.

## Status (2 October 2026)

**Decision:** owner-approved 3 October 2026; [ADR 0008](../adr/0008-agent-network.md) is Accepted and its sovereignty/ICIP concerns are hard requirements.

**Done:** new crate `blaktail-agentgw` (OpenAI-compatible `/v1/chat/completions` with SSE passthrough, `/v1/models`, overlay-only bind, redaction, usage reporting, secrets wrapped and never logged); coordinator module `blaktail-coord/src/agent_gateway.rs` (providers with declared location and sealed credentials, per-agent hashed keys with optional device binding, per-key policies, atomic daily quotas, offshore forbidden by default, metadata/full logging with owner + ICIP acknowledgement + ≤30-day retention, usage ingest with node-token auth and the `agent-gateway` capability, audit of every mutation and of stored-prompt reads); migration slot 31; permissions `manage_agent_gateway` (owner, admin) and `view_agent_usage` (owner, admin, auditor); `blaktaild up --agent-gateway`; console `/agents` in its own "Agents" nav group; docs in `docs/agent-gateway.md`; lab script `deploy/homelab/prove-agent-gateway.sh`.

**Proven by tests:** 13 coordinator tests (key auth/revocation, quotas incl. 20 concurrent vs quota 5, offshore enforcement, model allowlist, request size, node binding, credential never returned/stored in clear/audited, full-logging gates and purge, single-use usage ingest, cross-org isolation, member/network-admin/auditor rejection, URL validation) and 9 gateway tests (unit + end-to-end with a real in-memory coordinator and a local axum mock upstream: byte-exact SSE passthrough, metering, redaction, bad key/quota never reach upstream, captured logs free of secrets). Live container lab with a real Ollama: see `docs/agent-gateway.md`.

**Still needs live/field proof or a decision:** a run over a real WireGuard overlay (the lab used a private Docker network with `--allow-private-listen`); a hosted offshore provider with an owner's explicit approval; Anthropic Messages translation, tool/MCP allowlists and billing are not built; coordinator-secret rotation would need a re-seal; a named organisation's written user need and ICIP consent process remain the owner's to record.
