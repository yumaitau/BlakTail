# Turn private HTTPS service contracts into a working, audited service workspace

**Priority:** P1. **Depends on:** drafts 04 (resources), 07 (policy), 09 (DNS) and closed #47 design. **Area:** coordinator, serving agent, cert trust, console.

## Gap and outcome

Closed #47 describes organisation-owned private HTTPS services; `blaktail-coord/src/https_services.rs` has binding helpers. No `Services` page or demonstrated certificate issuance, reverse proxying and authorised browser request is evident. NetBird's Services/Reverse Proxy UI shows why certificate, route, policy, health and logs need one coherent operator flow. First milestone remains **private-only**; no public DNS or Internet ingress.

## Scope

- Model stable service ID/name, owner organisation, target node, local socket, protocol, target health, access groups, revision and lifecycle. Reserve namespace separate from peer MagicDNS, with collisions and transfer rules.
- Choose organisation CA or DNS-01 with documented trust installation, renewal, revocation, outage and onshore dependencies. Generate private key on serving node; coordinator authorises short-lived certificate bound to exact service/node/org, never holds service key.
- Ship authenticated agent proxy/listener, effective policy enforcement, direct/relay route behaviour, console create/preview/disable/delete, certificate status, bounded health and audit. Explicitly mark whether old clients can validate the service.

## Acceptance / proof

Client with grant reaches `https://service` and validates cert; non-member cannot reach endpoint by DNS **or** raw IP; rotated/revoked node cannot obtain or use cert. Exercise renewal, target outage, name collision and two organisations with same service name. Capture no private keys or payload in console, metrics or support bundle.

**Evidence:** closed #47, `blaktail-coord/src/https_services.rs`, `docs/org-dns.md`; https://docs.netbird.io/manage/reverse-proxy/service-configuration.
