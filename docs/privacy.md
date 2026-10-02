# Privacy and data handling

This statement describes the BlakTail software. Each self-hosting organisation is
the operator and data controller for its deployment. Before exposing a console to
the public internet, the operator must publish its legal name, privacy contact,
Australian hosting locations, backup/log retention periods, subprocessors, and the
local process for access, correction, export, and deletion requests.

## Data processed

- The console Postgres database holds account name and email, the Better Auth
  credential record, sessions (which may include IP address and user agent),
  organisation membership and role/status, hashed invitation/bootstrap credentials,
  invitation status/expiry, actor-attributed console audit events, optional OIDC
  issuer/subject bindings, an email snapshot from the last successful SSO, and
  an encrypted IdP client secret. Raw bootstrap, invitation, API, and OIDC
  client secrets are shown once and are not stored in recoverable form.
- The coordinator's SQLite or PostgreSQL store holds organisation and node identifiers, device names,
  WireGuard public keys, tailnet addresses, advertised endpoints/routes, ACLs,
  hashed join/node/automation credentials, credential expiry, last-seen time,
  bounded agent OS/architecture/version/capability metadata, published organisation
  DNS settings, and actor-attributed audit events. Hardware serials, location,
  process inventory, and DNS query names are not collected.
- A relay keeps node identifiers and public socket addresses in memory. Registrations
  expire after 120 seconds idle. It forwards opaque WireGuard ciphertext and cannot
  decrypt the inner traffic.
- Runtime logs contain operational identifiers, counts, errors, and configured or
  observed endpoints where noted. They must not contain private WireGuard keys, raw
  join keys, node tokens, browser device codes, passwords, or tunnel payloads.

BlakTail does not add advertising, third-party analytics, tracking pixels, remote
fonts, or public-DNS forwarding. Better Auth session cookies are used to sign in and
protect the console. The macOS desktop stores its session token in Keychain.

## Purpose, location, and disclosure

The data is used only to authenticate operators, authorise and configure the
organisation's tailnet, route encrypted packets, diagnose availability, and record
security administration. The software is designed for Australian/onshore hosting,
but source code cannot enforce the location of an operator's databases,
TLS proxy, logs, backups, DNS, or support tooling. Operators must
verify every runtime and backup destination. Hosting providers selected by the
operator may process infrastructure metadata under their own terms.

BlakTail does not sell account or network data. An operator may disclose data when
authorised by its organisation, required by law, or necessary to respond to a
security incident.

## Retention and deletion

Expired browser authorisations are removed by the coordinator, and relay state is
short-lived in memory. Coordinator audit rows older than the organisation's
configured retention (default 90 days) are purged when the audit API is read.
Revoked node rows remain until an owner tombstones them; tombstones keep the
node id for audit and release the live name and WireGuard key. Inventory reads
hard-delete tombstones older than seven days without touching live nodes;
`node.tombstoned` audit rows stay until the organisation's audit retention
expires.
Console account, session, invitation, bootstrap-state, rate-limit, and audit
retention follows Better Auth plus the operator's database procedures. Used,
expired, and revoked invitation rows are not currently purged automatically. Logs
and backups follow deployment policy (the disposable AWS harness uses one-day
CloudWatch retention; the legacy reference root uses 30 days).

Traffic diagnostics are off by default. If an owner turns them on, devices
may upload aggregate counters (bytes, packets, service class, port,
transport, allow/deny per hour) — never payloads, URLs, DNS questions or host
names — kept for 1–30 days as the owner chooses and deletable at any time
from `/traffic`. Current agents do not upload them. See
[audit-and-traffic.md](audit-and-traffic.md).

Operators must choose and publish retention periods, test deletion across live
databases and backups, and preserve audit data only as long as their security and
legal needs require. Revoking a node stops tailnet access but is not a complete
privacy erasure workflow.

## Security and requests

WireGuard encrypts node traffic end to end. HTTPS protects console/coordinator API
traffic. Encryption reduces risk but does not remove endpoint, account, host, or
operator compromise risk; see the [threat model](threat-model.md).

People seeking access, correction, deletion, or a privacy complaint must contact the
organisation operating the console they use. A public operator must place its real
contact details beside the console's `/privacy` link before launch. This repository
does not name a universal controller for independently hosted deployments.
