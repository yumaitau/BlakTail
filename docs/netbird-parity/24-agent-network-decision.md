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
