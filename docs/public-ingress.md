# Public ingress

Public ingress puts a private service on the Internet through an HTTPS reverse
proxy **your organisation runs** on an onshore host it chooses. BlakTail does
not operate a shared ingress. Decision record: [ADR 0007](adr/0007-public-ingress.md).

It is off for every organisation until an owner turns it on, and every route is
published separately by an owner. Anyone who can reach the ingress host can
reach a published route, subject to the route's sign-in setting and limits.

## How it fits together

```
Internet client --HTTPS--> blaktail-ingress (onshore host) --HTTP over WireGuard--> target device:port
                                 |  node token (co-located blaktaild)
                                 v
                           blaktail-coord: /v1/nodes/:id/public-ingress/config (long-poll)
```

- The ingress host is an ordinary enrolled device running
  `blaktaild up --public-ingress`. That flag makes the agent report the
  `public-ingress` capability. `blaktail-ingress` runs next to it, reads the
  agent's `state.json` for the node id, node token and coordinator URL (re-read
  on every poll, so token renewals are picked up), and dials targets over the
  agent's WireGuard interface. The ingress never registers its own node and
  never holds WireGuard keys.
- The coordinator delivers a route only to `public-ingress` devices **in the
  same organisation**, and only when all of these hold: the organisation
  setting is on, the route is enabled and not emergency-disabled, the target is
  an active device (not revoked, deleted, suspended or expired), a service
  target is enabled and uses HTTP, and the **published access policy lets the
  ingress device reach the target's TCP port**. A public URL never widens
  policy: if policy blocks the ingress, the route reports *Blocked by policy*
  and is not served.
- Each delivered route names one target address (the device's overlay IPv4) and
  port. The ingress connects there and nowhere else, and by default refuses any
  target outside the overlay range `100.64.0.0/10` even if a coordinator sends
  one (`--allow-target-cidr` changes this; do not widen it in production).

## Safety behaviour

| Concern | Behaviour |
| --- | --- |
| Wrong host | TLS needs a server name (SNI) that is a live route with a loaded certificate, otherwise the handshake fails (including connections by IP). The `Host` header, and the authority of an absolute-form request, must equal the SNI name: otherwise `421`; two `Host` headers or a non-443 port: `400`. |
| SSRF | The upstream request uses only the path and query; the connection always goes to the route's published `address:port`. `CONNECT` is refused (`405`). Absolute-form URIs naming other hosts (for example `http://169.254.169.254/`) get `421` and are never forwarded. |
| Redirects | The ingress never follows redirects; `3xx` responses go back to the client. A `Location` that points at the target or another internal address/name is rewritten onto the public hostname. |
| Header leaks | Hop-by-hop headers (and any named in `Connection`) are dropped both ways. Client-supplied `Forwarded`, `X-Forwarded-*`, `X-Real-IP` and `X-BlakTail-*` are removed; the ingress sets `X-Forwarded-For`, `X-Forwarded-Proto: https` and `X-Forwarded-Host`. Responses lose `Server`, `X-Powered-By`, `Via` and similar banners, and any header whose value contains the target address, an overlay (100.64.0.0/10) or unique-local IPv6 address, a loopback/link-local address or a `.blaktail` name. Ingress error pages carry no details. |
| Client networks | Optional `allowed_source_cidrs` per route (IPv4/IPv6 CIDRs, at most 64). Other clients get `403` before anything else happens. Removing the restriction is a widening change and needs the typed hostname. |
| Rate | Token bucket per route per client IP: `rate_limit_per_minute`, burst of ten seconds' worth. Over the limit: `429` with `Retry-After: 10`. |
| Body size | `Content-Length` above `max_body_bytes` is refused with `413` before connecting; chunked bodies are cut off at the limit and answered `413`. |
| Connections | `max_connections` in-flight requests and open WebSocket tunnels per route; beyond that `503`. The listener also caps total connections (`--max-connections`, default 4096), TLS handshakes (10 s) and request headers (15 s). |
| Protocols | HTTPS with HTTP/1.1 (ALPN `http/1.1`) and WebSocket upgrades. Port 80 only answers ACME HTTP-01 challenges for the matching host and redirects live routes to HTTPS. No raw TCP/UDP. |

## Disable and loss of contact (the 30-second bound)

- **Emergency disable** (console button or
  `POST /v1/orgs/:org/public-ingress/routes/:id/emergency-disable`) bumps the
  organisation's control revision. The ingress holds a long-poll open; the
  coordinator answers within about 200 ms of the change, and the ingress drops
  the route immediately: new TLS handshakes for the name fail, keep-alive
  connections get `404` on their next request, and open WebSocket tunnels are
  closed. Re-enabling needs an owner, the current revision and the typed
  hostname. Turning the organisation setting off withdraws every route the same
  way.
- **Fail closed**: the ingress serves nothing once it has not had a successful
  answer from the coordinator for 30 seconds (the long-poll waits at most 20 s).
  So even if the coordinator becomes unreachable, a disable cannot be outrun
  for longer than 30 seconds. The trade-off is that a coordinator outage takes
  public routes down after 30 seconds.
- A refused node credential (revoked, suspended, expired, or the capability no
  longer reported) withdraws every route at once.

## Identity gate (optional)

A route with sign-in `oidc` requires the organisation's own OpenID Connect
provider before anything reaches the target. The ingress runs the
authorisation-code flow with PKCE and nonce, verifies the ID token signature
(JWKS, asymmetric algorithms only), issuer, audience and expiry, requires an
email that is not marked unverified, and applies the route's optional email
domain allow-list. It then sets a host-bound, HMAC-signed `__Host-` session
cookie (8 hours, `Secure; HttpOnly; SameSite=Lax`). The ingress strips its own
cookies before forwarding and passes the signed-in email as `X-BlakTail-User`
(clients cannot inject that header).

Why this design: a console-session forward-auth check would need the console's
cookie on the public domain and a live dependency on the console. A per-ingress
OIDC client keeps the trust decision at the organisation's IdP and the proxy
boundary. Register one confidential client at your IdP with redirect URI
`https://<route-hostname>/.blaktail-ingress/callback` for each gated route, and
use an organisation-specific issuer (not a multi-tenant "common" endpoint) or
set allowed email domains. Browsers without a session are redirected to sign in;
non-GET requests and WebSockets get `401`. `/.blaktail-ingress/logout` clears
the session.

## Certificates and domains

Your organisation owns the hostname and its DNS: point it at the ingress host.
The coordinator never sees certificate keys.

- **Operator files** (`operator_files`): put `fullchain.pem` and `privkey.pem`
  under `<cert-dir>/<hostname>/` (default `/etc/blaktail-ingress/certs`).
  `chmod 600` the key (the ingress warns otherwise). The leaf must name the
  hostname (or a one-label wildcard) and be within its validity period. Files
  are re-checked every minute; a rotated pair is used for new handshakes
  without dropping connections, and a broken replacement keeps the last good
  pair while the console shows the error.
- **ACME HTTP-01** (`acme_http01`): start the ingress with
  `--acme-directory <url>` (and `--acme-contact`). It issues or renews (30 days
  before expiry) using instant-acme, answering challenges on port 80, and keeps
  the account key and certificate keys under `<data-dir>/acme` (`0600`).
  Failures back off for 15 minutes per name. You choose the certificate
  authority; BlakTail makes no residency claim about it.

The ingress reports, per route, the certificate expiry, source and any error;
the console shows it next to each ingress host.

## Access logs

JSON lines on the ingress host only, under `<data-dir>/access-logs/<hostname>/YYYY-MM-DD.jsonl`
(`--log-dir` to move, `off` to disable). Each entry has time, hostname, client
IP, method, path **without the query string**, status, duration, outcome
(`proxied`, `rejected_host`, `rate_limited`, `too_large`, `connection_limit`,
`login_required`, `upstream_unreachable`, ...) and the signed-in email when
gated. Never the target address or bodies. Requests for unknown hosts share a
`_rejected` bucket. Day files older than the route's `log_retention_days`
(default 30, 1-365) are deleted hourly. Back them up and protect them as your
own onshore records; BlakTail does not collect them.

## Setting it up

1. Owner: Console → Services → Public ingress → record an abuse contact, type
   `PUBLIC`.
2. On the onshore host:
   `blaktaild up --coord https://coord.example --name edge --public-ingress`
   (the host's device must be allowed by policy to reach each target port).
3. Run the ingress as root (it reads the agent state and binds 443/80):
   ```
   blaktail-ingress \
     --coord-ca /etc/blaktail/coord-ca.pem \            # only for a private coordinator CA
     --cert-dir /etc/blaktail-ingress/certs \
     --data-dir /var/lib/blaktail-ingress \
     [--acme-directory https://acme-v02.api.letsencrypt.org/directory --acme-contact ops@example.org.au] \
     [--oidc-issuer https://login.example.org.au --oidc-client-id ingress \
      --oidc-client-secret-file /etc/blaktail-ingress/oidc-secret]
   ```
   Every flag has a `BLAKTAIL_INGRESS_*` environment variable. Secrets are only
   read from files.
4. Owner: publish the route (type the hostname again), point DNS at the host,
   then check the route shows *Live on the Internet* and a certificate expiry.

## API

Console session routes (`/v1/orgs/:org_id/...`):

| Method and path | Permission |
| --- | --- |
| `GET public-ingress` (settings, ingress hosts, routes with per-ingress state) | view network |
| `PUT public-ingress/settings` `{enabled, abuse_contact, confirm: "PUBLIC"}` | owner (`manage_public_ingress`) |
| `POST public-ingress/routes` `{fqdn, confirm_fqdn, target_service_id \| target_node_id+target_port, tls_mode, auth_mode, allowed_email_domains, allowed_source_cidrs, rate_limit_per_minute, max_body_bytes, max_connections, log_retention_days}` | owner |
| `PATCH public-ingress/routes/:id` `{revision, enabled?, confirm_fqdn?, ...}` (enabling, dropping sign-in or removing client-network limits needs `confirm_fqdn`; stale revision `412`) | owner |
| `DELETE public-ingress/routes/:id` | owner |
| `POST public-ingress/routes/:id/emergency-disable` `{reason}` | owner, admin, network admin |

Node-token routes used by `blaktail-ingress`: `GET /v1/nodes/:id/public-ingress/config?since=&wait=`
(long-poll, `204` when unchanged) and `POST /v1/nodes/:id/public-ingress/report`.
Every mutation is in the audit log (`public_ingress.enabled|disabled|updated`,
`public_route.created|updated|enabled|disabled|emergency_disabled|deleted`).
Routes are not yet in the `/api/v1` automation API.

## Limits of this release

- HTTPS/HTTP/1.1 and WebSockets only; no HTTP/2 to clients, no TCP/UDP.
- Upstream traffic is plain HTTP inside the WireGuard overlay; private services
  with protocol `https` cannot be targets yet.
- Rate limits are per ingress process; several ingress hosts each apply them.
- Every live route is served by every ingress host in the organisation.
- Not yet proven: a live Internet smoke against a real public DNS name and a
  public CA, independent security review, and long-running operation.

## Lab proof (3 October 2026, m3-max)

`DOCKER_CONTEXT=m3-max deploy/homelab/prove-public-ingress.sh` builds the
coordinator, `blaktaild` and `blaktail-ingress` from tracked sources and runs a
coordinator, an ingress host (kernel WireGuard), a target agent serving HTTP
only on its overlay address (`python3 -m http.server --bind 100.64.0.2`), a
Pebble ACME server and an "Internet" client on one Docker network. Result:
`public_ingress_proof passed`.

| Check | Result |
| --- | --- |
| Client cannot reach the app directly | refused |
| Member, admin, network admin create route | `403` each |
| Owner create while the organisation is off | `409` |
| `https://app.example.org.au/` through the ingress (lab CA verified) | `200`, app body |
| Response headers | no `Server`, overlay address or `.blaktail` name |
| Wrong `Host` on the published connection | `421` |
| `GET http://169.254.169.254/latest/meta-data/` (absolute form) | `421`, not forwarded |
| Unpublished server name; connect by IP without SNI | TLS handshake fails |
| Policy set to deny-by-default | route withdrawn, console `blocked_by_policy`; restored when policy restored |
| ACME HTTP-01 route `auto.example.org.au` against Pebble | certificate issued, served and verified against Pebble's root |
| Console workspace | ingress online, certificate expiry reported |
| Emergency disable (admin) to first failed public request | 1.60 s (bound 30 s; 1.85 s on an earlier run) |
| Access log on the ingress host | entries present, no target address |
| Owner re-enable with typed hostname | served again |
| Coordinator stopped | ingress stopped serving after 29.6 s (bound 30 s; 28.9 s earlier) |
