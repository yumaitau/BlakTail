# ADR 0007 — Optional public ingress for private services (draft 11)

- Status: **Accepted** — 3 October 2026 (product owner approved building it;
  the gates below are requirements, not open questions)
- Date: 2026-10-02 (proposed), 2026-10-03 (accepted)

## Context

Some private-network products publish organisation services to the Internet
through a managed reverse proxy with custom domains, identity-aware access and
access logs. BlakTail has no hosted service. Issue #47 deliberately separated
public ingress from private service publishing, and draft 10 ships the
private-only milestone first. Public exposure changes the threat model: a
device that was reachable only from enrolled peers becomes reachable by anyone.

## Requirements (formerly decision gates)

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

## Required controls

- Separate publish model: public FQDN, target service (draft 10 object), TLS
  mode, optional identity authentication, allowed sources, limits, log
  retention and emergency disable. Public and private services are visually
  and structurally distinct.
- Ingress authenticates to the target over the overlay as its own node and is
  subject to the same device ACL; a URL never widens policy.
- SSRF/metadata protection: the ingress connects only to the published target
  address and port; redirects to other hosts are not followed.
- Tenant isolation in config, logs and limits; wrong `Host`/origin rejected.

## How the implementation meets them (3 October 2026)

See [`docs/public-ingress.md`](../public-ingress.md).

1. `blaktail-ingress` runs on the organisation's host next to
   `blaktaild up --public-ingress`; no shared ingress exists.
2. HTTPS/HTTP/1.1 with WebSocket upgrades only.
3. `public_ingress_settings.enabled` defaults off; enabling needs
   `ManagePublicIngress` (owner only), an abuse contact and typing `PUBLIC`;
   each route is created or re-enabled by an owner typing its hostname.
4. Per route per-client rate, body size and connection limits; emergency
   disable propagates through the long-poll in about 2 s in the lab, and the
   ingress serves nothing after 30 s without coordinator contact, so the bound
   is 30 s (tighter than the 60 s required).
5. Operator certificate files or ACME HTTP-01 on the ingress host; the
   coordinator stores only the reported expiry.
6. JSON-lines access logs on the ingress host with per-route retention, no
   target address or query string; response headers scrubbed of overlay
   addresses and `.blaktail` names.
7. Console and docs state the operator chooses DNS, CA and monitoring.

Controls: separate `public_routes` model (FQDN, service or device+port target,
TLS mode, OIDC identity gate, allowed client CIDRs, limits, retention,
emergency flag); delivery requires the access policy to let the ingress device
reach the target port (otherwise *blocked by policy*); the proxy dials only the
published overlay address and port and never follows redirects; SNI/Host must
match (`421` otherwise); routes are delivered only to `public-ingress` nodes of
the same organisation.

## Acceptance still open

Independent security review and threat-model sign-off; a live Internet smoke
against a real public DNS name and public CA; operation over time (certificate
renewal in production, abuse handling).
