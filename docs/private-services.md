# Private services

Status: **coordinator and console only.** Owners and admins can define private
services and the coordinator can issue certificates for them, but no BlakTail
agent serves them yet. Every service reports `reachable: false` and stays
"awaiting serving agent" (or "certificate issued") until a serving-agent
listener ships and is proven. Services are private-only: nothing is published to
public DNS or exposed to the Internet.

## Names

A service named `wiki` in an organisation whose MagicDNS suffix is
`12345678.blaktail` is `wiki.svc.12345678.blaktail`. Device names are a single
label under the organisation suffix, so the `svc` subtree cannot collide with a
device. Names are 3-63 lowercase letters, digits and hyphens. `svc`,
`localhost` and any existing device label in the organisation are refused, so a
short name never means two things. Two organisations can each have `wiki`; their
names, certificates and records never mix. Service names are not yet published
to the agent DNS snapshot, because a name that resolves but does not answer
would look like a working service.

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
  issued certificates.
- `DELETE /v1/orgs/:org/services/:id`: delete and revoke certificates.

Every change is audited (`service.created`, `service.updated`,
`service.enabled`, `service.disabled`, `service.deleted`) and bumps the
organisation control revision. There are no `/api/v1` automation routes for
services yet.

## Certificates

Each organisation gets one CA the first time it creates a service. The CA is
**name-constrained** to that organisation's `svc.<prefix>.blaktail` subtree, so
a client that trusts it cannot be made to accept it for any other name. Its key
is stored sealed with the coordinator's `BLAKTAIL_AUTH_HMAC_SECRET` (ChaCha20-Poly1305)
and is valid for two years. CA rotation is not automated.

A serving node generates its own key and sends only a PKCS#10 CSR:

- `GET /v1/nodes/:node/services` (node token): enabled services targeting
  this node.
- `POST /v1/nodes/:node/services/:service/certificate` with `{"csr_pem": …}`.

The coordinator checks the node token (revoked, removed or expired nodes are
refused; suspended nodes get 403 `suspended` on both node routes), that the service belongs to the node's organisation (other
organisations get 404), that the node is the service's target (403 otherwise),
and that the service is enabled. The CSR signature must verify, its key must be
ECDSA P-256, ECDSA P-384 or Ed25519, and it may name only the service's full
name. Any request carrying private key material is rejected. Only the CSR's
public key is used: the coordinator sets the subject (organisation, service and
node IDs), the single DNS name, server-auth usage and a 24-hour lifetime. The
CSR and certificate fingerprint are stored and the issue is audited as
`service.certificate_issued` with actor role `node`, in the organisation's
tamper-evident audit chain. Suspending a device revokes every service
certificate issued to it (`service_certificates_revoked` in the
`node.suspended` audit details); after resuming it must request new ones. Keys, certificates and
payloads are not logged.

Trusting the CA on client devices is manual today: download it from
`/services` and install it in each client's trust store.

## Not done yet

- Agent-side key generation, CSR submission, renewal, TLS listener and reverse
  proxy to the local port.
- Enforcing `access_tags` at the serving listener and in peer policy, so a
  device without a granted tag cannot reach the endpoint by name or raw IP.
- Publishing service names to agent DNS once a listener reports healthy.
- Health checks, certificate revocation distribution (revoked certificates are
  marked in the coordinator only; with 24-hour leaves, revocation relies on
  expiry), CA rotation, and automated trust installation.
