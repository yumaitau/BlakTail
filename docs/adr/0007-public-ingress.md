# ADR 0007 — Optional public ingress for private services (draft 11)

- Status: proposed — **not approved**; no implementation until the owner signs off
- Date: 2026-10-02

## Context

Some private-network products publish organisation services to the Internet
through a managed reverse proxy with custom domains, identity-aware access and
access logs. BlakTail has no hosted service. Issue #47 deliberately separated
public ingress from private service publishing, and draft 10 ships the
private-only milestone first. Public exposure changes the threat model: a
device that was reachable only from enrolled peers becomes reachable by anyone.

## Decision gates (all must be answered before any code)

1. **Who runs it.** Only a self-hosted, organisation-operated ingress in an
   Australian environment the organisation selects. BlakTail will not operate
   a shared ingress for organisations.
2. **Modes.** HTTPS only for a first phase. Raw TCP/UDP forwarding is out of
   scope until HTTPS has been operated safely.
3. **Defaults.** Off per organisation. Owner-only to enable. Each published
   service is separately created by an owner with a high-signal confirmation
   that names the public hostname and target device.
4. **Abuse and limits.** Per-service request, body-size and connection limits;
   emergency disable that removes external access within 60 seconds; an abuse
   contact recorded per organisation.
5. **Certificates and domains.** The organisation owns the domain and DNS.
   Private keys stay at the ingress (explicit proxy boundary) or at the serving
   node when TLS is passed through; the coordinator never holds them.
6. **Logs.** Access logs stay onshore in operator storage with a stated
   retention. No private overlay addresses, WireGuard keys or internal
   hostnames in response headers or public logs.
7. **Residency.** Copy must not imply BlakTail guarantees residency for
   operator-selected DNS, CDN, certificate authority or monitoring providers.

## Required controls if approved

- Separate publish model: public FQDN, target service (draft 10 object), TLS
  mode, optional identity authentication, allowed sources, limits, log
  retention and emergency disable. Public and private services are visually
  and structurally distinct.
- Ingress authenticates to the target over the overlay as its own node and is
  subject to the same device ACL; a URL never widens policy.
- SSRF/metadata protection: the ingress connects only to the published target
  address and port; redirects to other hosts are not followed.
- Tenant isolation in config, logs and limits; wrong `Host`/origin rejected.

## Acceptance before release

Threat model and this ADR signed off by the product owner and an independent
reviewer; public endpoint off by default; member cannot create one; live
smoke reaches only the intended service; disable removes access within the
bound; certificate rotation does not interrupt or leak.

## Recommendation

**Defer.** Prove draft 10 (private services) in the field first. Revisit when a
named organisation has a concrete public-service need that cannot be met by
enrolling the people who need access.
