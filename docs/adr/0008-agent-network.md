# ADR 0008 — AI "agent network" model gateway (draft 24)

- Status: proposed — recommendation **reject for this product**; owner decision required
- Date: 2026-10-02

## Context

Another private-networking product added a separate "Agent Network" area for
AI providers, model policies, usage accounting and prompt/response logs.
BlakTail's purpose (`PRODUCT.md`) is an open, self-hosted private path between
an organisation's devices with identity, policy, keys and operational data
under organisational control. An AI model gateway is a different product
domain: provider credentials, prompt and response content, token accounting
and cultural/IP consent over what is sent to a model.

## Considerations

- **User need.** No concrete BlakTail user story has been recorded that a
  network product must solve here rather than an application-layer gateway.
  Competitor feature count is not a need.
- **Sovereignty.** Most hosted model providers process data offshore. Routing
  prompts through a "BlakTail" component would let copy imply an onshore
  guarantee BlakTail cannot make for third-party inference.
- **Cultural and intellectual property.** Prompts may contain Indigenous
  Cultural and Intellectual Property. Consent, retention and redaction rules
  belong to the organisation and the application that holds that content, not
  to network control-plane policy.
- **Security surface.** Provider keys, prompt logging and per-agent identity
  would add high-value secrets to the coordinator and console.
- **What BlakTail already offers.** An organisation can run an onshore,
  self-hosted model or gateway on an enrolled server and control who reaches
  it with existing access policy (and private services, draft 10). That keeps
  network policy and model policy separate.

## Decision (recommended)

Reject an AI gateway inside BlakTail. Do not add an empty "Agent Network"
navigation entry. Document the supported pattern: publish a self-hosted model
endpoint as a private service and govern reachability with BlakTail policy.

## Revisit criteria

A written user need from a named organisation, an onshore inference provider
with contractual residency, and a separate charter with its own threat model
and retention map for every sensitive field before any inference traffic.
