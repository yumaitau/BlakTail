# Private services

Status: **served by Linux and macOS agents that opt in.** Owners and admins
define a private service in the console; the target device runs
`blaktaild up --serve-services`, generates the service key itself, obtains a
24-hour certificate from the organisation CA, and serves the name on its
overlay address(es) only. The name is published to allowed devices' MagicDNS
only while the target reports a current certificate and a healthy local
target. Services are private-only: nothing is published to public DNS or
exposed to the Internet.

## Names

A service named `wiki` in an organisation whose MagicDNS suffix is
`12345678.blaktail` is `wiki.svc.12345678.blaktail`. Device names are a single
label under the organisation suffix, so the `svc` subtree cannot collide with a
device. Names are 3-63 lowercase letters, digits and hyphens. `svc`,
`localhost` and any existing device label in the organisation are refused, so a
short name never means two things. Two organisations can each have `wiki`; their
names, certificates and records never mix. Service names have no short
(single-label) alias, so they never shadow a device name.

## Console and API

`/services` in the console (see `docs/console.md`) uses these console routes,
authenticated by the console assertion. Any member can list; creating, changing
and deleting need `ManageServices` (owner or admin), enforced by the coordinator.

- `GET /v1/orgs/:org/services`: services, namespace and the organisation CA.
- `POST /v1/orgs/:org/services/preview`: full name, problems and warnings
  without saving.
- `POST /v1/orgs/:org/services`: create (`name`, `target_node_id`, `port`,
  `protocol` `http`|`https` for the local upstream, `access_tags`,
  `description`). 409 on a name collision.
- `PATCH /v1/orgs/:org/services/:id`: change fields; `revision` is required and
  a stale value returns 412. Changing the target device or disabling revokes
  issued certificates and clears the last health report.
- `DELETE /v1/orgs/:org/services/:id`: delete and revoke certificates.

Every change is audited (`service.created`, `service.updated`,
`service.enabled`, `service.disabled`, `service.deleted`) and bumps the
organisation control revision. There are no `/api/v1` automation routes for
services yet.

### Status

| Status | Meaning |
| --- | --- |
| `disabled` | Disabled; certificates revoked, the target stops serving on its next update. |
| `target_unavailable` | The target device was revoked or removed. |
| `awaiting_certificate` | No live certificate: the target has not run `--serve-services`, is suspended, or its request failed. |
| `certificate_issued` | A live certificate exists but no report in the last 120 seconds names it with a running listener. Not published. |
| `target_unhealthy` | The listener is up with the live certificate but the local target failed its check. Not published. |
| `serving` | Fresh report: listener up, live certificate, healthy target. Published to allowed devices. `reachable: true`. |

`serving` is the target device's own report plus coordinator-side certificate
checks, not a probe from a client device.

## Serving a service (target device)

```sh
sudo blaktaild up --coord https://coord.example --serve-services
# optional: --service-listen-port 8443 (default 443)
```

The choice is recorded in the agent state (`serve_services`), reported as the
`service-serving` capability, and survives `blaktaild run`.
`--serve-services=false` stops serving and deletes the service keys.

On every control update (at most ~25 seconds apart) the agent:

1. Fetches `GET /v1/nodes/:node/services` (enabled services targeting it).
2. For a service without a certificate, or once two thirds of the 24-hour
   lifetime (16 hours) has passed, generates a **new** ECDSA P-256 key on the
   node and sends only a PKCS#10 CSR to
   `POST /v1/nodes/:node/services/:service/certificate`. Each renewal rotates
   the key. Key, certificate and metadata are written under
   `<state dir>/services/` (directory 0700, files 0600). Keys are never sent,
   logged or reported.
3. Runs one TLS listener on the node's overlay address(es) only, on 443 (or
   `--service-listen-port`), routing by SNI to `127.0.0.1:<port>`. TLS is
   terminated and bytes are proxied unchanged, so HTTP/1.1 and WebSocket
   upgrades work; ALPN offers `http/1.1` only. The upstream is always loopback.
4. Probes each local target (TCP connect plus an HTTP `HEAD /` that must answer
   `HTTP/`, 2-second bound) and reports `{listening, healthy, detail, serial}`
   to `POST /v1/nodes/:node/services/health`.

`https` upstreams are not proxied yet: such a service reports unhealthy with an
explicit detail instead of sending plaintext to a TLS port. The listener holds
at most 256 connections and a 10-second handshake deadline.

## Who can connect

Access needs both:

- the organisation policy to let the client and the target peer (a service
  never creates connectivity the policy does not), and
- the client to hold one of the service's `access_tags`, unless a policy rule
  explicitly denies the listener port to that client (a deny wins).

The coordinator compiles this per serving node, in the same peer-map pass that
compiles ACL ingress, and enforces it twice:

- **Port level (Linux `acl_filter`):** in the serving node's peer map, every
  peer without access gets a `deny_tcp` entry for the listener port, and every
  peer with access gets it added to `tcp` when its grant is narrower than
  `all`. Deny rules run first, so a non-member cannot reach the port even by raw
  overlay IP.
- **Listener:** the serving node receives `service_access` (per-service allowed
  overlay addresses). A source in no service's list is closed before any TLS
  byte. A known source is closed after its ClientHello and before the handshake
  completes if the SNI names a service it may not use, an unknown name, no name
  at all (a raw-IP request) or an expired certificate.

macOS serving nodes have no packet filter, so there the listener check is the
only enforcement on the listener port; other ports follow normal policy.

## DNS publication

Clients receive `service_records` in their peer map: the service name and the
target's overlay addresses (A and AAAA), only when the client holds an access
tag, the target is in the client's peer map, and the service is `serving`.
MagicDNS answers it under `svc.<org>.blaktail`; an unpublished name is
NXDOMAIN. A health change that publishes or withdraws a name bumps the control
revision, so clients update on their next long poll, and the coordinator
schedules a recompile for the moment the latest report goes stale or the
certificate expires, so a silent node's name is withdrawn without any event.

## Certificates

Each organisation gets one CA the first time it creates a service. The CA is
**name-constrained** to that organisation's `svc.<prefix>.blaktail` subtree, so
a client that trusts it cannot be made to accept it for any other name. Its key
is stored sealed with the coordinator's `BLAKTAIL_AUTH_HMAC_SECRET`
(ChaCha20-Poly1305) and is valid for two years. CA rotation is not automated.

The coordinator checks the node token (revoked, removed or expired nodes are
refused; suspended nodes get 403 `suspended` on every node service route), that
the service belongs to the node's organisation (other organisations get 404),
that the node is the service's target (403 otherwise), and that the service is
enabled. The CSR signature must verify, its key must be ECDSA P-256, ECDSA P-384
or Ed25519, and it may name only the service's full name. Any request carrying
private key material is rejected. Only the CSR's public key is used: the
coordinator sets the subject (organisation, service and node IDs), the single
DNS name, server-auth usage and a 24-hour lifetime. The CSR and certificate
fingerprint are stored and the issue is audited as `service.certificate_issued`
with actor role `node`, in the organisation's tamper-evident audit chain.
Suspending a device revokes every service certificate issued to it
(`service_certificates_revoked` in the `node.suspended` audit details); after
resuming it must request new ones. Keys, certificates and payloads are not
logged.

### Revocation

There is no CRL or OCSP. Revocation reaches clients by withdrawal and by the
short lifetime:

- Disable, delete, retarget and device suspension stop the coordinator listing
  the service to the target (suspended and revoked nodes are refused outright),
  and the agent drops the route, live connections and, when nothing is left,
  the listener on its next control update. Its key files are deleted.
- The name is withdrawn from clients' MagicDNS in the same control update, and
  the target's port-level allow entries go with it.
- A copied certificate and key stay cryptographically valid until they expire,
  at most 24 hours. Clients do not check revocation.

## Trusting the CA on clients

The CA is not installed automatically. On a client device:

```sh
blaktaild trust-service-ca --output ./blaktail-services.pem   # just write it
sudo blaktaild trust-service-ca                                 # install
```

The command fetches the CA from `GET /v1/nodes/:node/service-ca` (node token;
public material only), checks the SHA-256 fingerprint against the coordinator's
record, prints the fingerprint and the name constraint, and asks for `yes`
before installing (`--yes` skips the prompt). Linux: written to
`/usr/local/share/ca-certificates/` and `update-ca-certificates` (or
`/etc/pki/ca-trust/source/anchors/` and `update-ca-trust extract`). macOS:
`security add-trusted-cert -d -r trustRoot` into the System keychain, which asks
for an administrator. Browsers with their own trust store (Firefox) need the CA
imported separately. Compare the fingerprint with the console's Services page.

Old clients: any client that trusts the CA and honours X.509 name constraints
validates the certificate. Agents older than this release ignore
`service_records`, so their MagicDNS does not answer service names.

## Live lab (3 October 2026)

`deploy/homelab/prove-private-services.sh` on `docker --context m3-max`
(coordinator plus three privileged Linux agents on kernel WireGuard):

- Server (tags office, ranger; `--serve-services`), ally (office; the access
  tag), outsider (ranger; a policy peer of the server without the tag), target
  `python3 -m http.server` on `127.0.0.1:8080`.
- After create, the server generated its key, obtained a certificate and the
  console status became `serving` within seconds. Key file mode 600, no key
  material in the agent log. The listener was bound only to the server's
  overlay IPv4 and IPv6 addresses on 443, and `BLAKTAIL-ACL` held a tcp/443
  REJECT for the outsider.
- Ally: `blaktaild trust-service-ca --output` printed the name constraint and
  fingerprint; `curl --cacert <org CA> https://wiki.svc.<prefix>.blaktail/`
  resolved through MagicDNS and returned the target's page. `curl -k
  https://<overlay IP>/` (no SNI) was refused.
- Outsider: the name was NXDOMAIN; `curl --resolve <name>:443:<overlay IP>` and
  `curl -k https://<overlay IP>/` both failed; ordinary policy access (ping) to
  the server was unchanged.
- Stopping the target: `target_unhealthy` after 16 s and the ally's name
  withdrawn; restarting it: `serving` again after 22 s and served.
- Disable: the server's listener was gone at the first check (under 1 s), the
  ally could not connect even with the name forced, the name was withdrawn and
  the key file deleted.

Lab caveat: Docker rewrites container `resolv.conf`, so the lab points each
client's resolver at its own MagicDNS listener (and lists the coordinator in
`/etc/hosts`) instead of relying on the agent's system DNS routing.

## Not done yet

- `https` upstreams, HTTP/2 to clients, and per-request access logs.
- Relay-only paths are not separately exercised; the listener sees the same
  overlay source address either way.
- CA rotation, OCSP/CRL, `/api/v1` automation routes, and proof on macOS
  serving nodes, Windows clients and browser trust stores.
