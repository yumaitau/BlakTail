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

## Status (2 October 2026)

**Done:**
- `blaktail-coord/src/private_services.rs` + slot 24 (service columns, `service_cas`, `service_certificates`): console list/preview/create/patch (revision-checked)/delete with `Permission::ManageServices`, audit and control-revision bump; namespace `<name>.svc.<org-prefix>.blaktail`, separate from device MagicDNS; collisions with existing services, device labels and reserved names; same name allowed across organisations.
- Organisation CA (rcgen, ECDSA P-256), name-constrained to the organisation's `svc` subtree, key sealed with the coordinator secret. Node-token endpoints list a node's services and issue 24-hour server certificates from a CSR whose public key is the only input used; the coordinator sets the name, subject binding (org, service, node), usages and lifetime. Private key material is rejected; CSR and fingerprint stored; issue audited with actor role `node`. Disabling, retargeting or deleting revokes certificates.
- Console `/services` page (nav group "Services") with honest status (`awaiting_serving_agent`, `certificate_issued` but not verified, `reachable: false` always) and CA download. Docs: `docs/private-services.md`, `docs/console.md`.

**Proven by tests:** two organisations with the same service name stay isolated (different FQDNs, cross-org PATCH/DELETE 404, cross-org session 401, cross-org node 404); member writes 403; validation failures (bad name, port 0, no/unknown tags, bad protocol, device-name and reserved collisions 409); stale revision 412; issued certificate validates in rustls/webpki against the org CA for the exact name and fails for another; non-target node 403, wrong token 401, foreign name, private key and malformed CSR 400; disabled service 409; revoked node 401 and service shows `target_unavailable`; sealed CA key and audit contain no key material.

**Still needs live/field proof or a decision:** the serving agent is not implemented: on-node key generation, CSR submission and renewal, TLS listener/reverse proxy, `access_tags` enforcement at the listener and in peer policy (non-member blocked by DNS **and** raw IP), DNS publication of service names after a health signal, bounded health checks, relay/direct path behaviour, revocation distribution (relies on 24-hour expiry today), CA rotation, client trust installation (manual), and whether old clients can validate the service. Automation API routes for services are not added.
