# Decide and gate optional public ingress with explicit sovereignty and abuse controls

**Priority:** decision, then P2. **Depends on:** draft 10 private service proof and threat/privacy review. **Area:** public proxy, TLS, policy, console.

## Gap and outcome

NetBird Reverse Proxy exposes private services through HTTPS and other protocols with custom domains, clusters, authentication and access logs. BlakTail explicitly has no hosted service and #47 separated public ingress from private publishing. Public access is **not** automatic parity: get a product/security decision before exposing any organisation device to the Internet.

## Decision gates

- Determine whether self-hosted organisations may run their own onshore ingress, allowed HTTP/TCP/UDP modes, default-deny exposure, abuse response, rate/resource limits, onshore logs/backups/support and who owns certificates/domains. Reject unsupported residency claims.
- If approved: create separate publish model with public FQDN, target, health, TLS mode, optional identity authentication, allowed source/rate/size constraints, access-log retention and emergency disable. Console requires high-signal confirmation and always distinguishes public from private service.
- Enforce proxy isolation, SSRF/metadata protection, bounded connections and tenant-safe logs; never weaken device ACL merely because URL exists. No default public exposure; service private key stays at trusted endpoint or explicit proxy boundary.

## Acceptance / proof

Security ADR and threat model signed off before implementation. Public endpoint off by default, cannot be created by member, denies wrong host/origin and survives certificate rotation safely. Live Internet smoke verifies intended service only; private peer addresses/keys do not leak in response headers/logs. Disable removes external access within specified bound.

**Evidence:** closed #47, `README.md` (self-hosted), `docs/threat-model.md`; https://docs.netbird.io/manage/reverse-proxy, https://docs.netbird.io/manage/reverse-proxy/custom-domains.

## Status (2 October 2026)

**Done:** decision record drafted at [`docs/adr/0007-public-ingress.md`](../adr/0007-public-ingress.md) with gates, constraints and a recommendation: defer until private services (draft 10) are field-proven and a named organisation needs public access.
**Proven by tests:** not applicable — decision only; no code or navigation added.
**Still needs live/field proof or a decision:** product-owner sign-off on the ADR (status stays *proposed* until then) and independent security review.
