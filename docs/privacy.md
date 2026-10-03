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
  bounded agent OS/architecture/version/capability metadata, the device's
  hardware serial number and physical MAC addresses (used only to match
  MDM/EDR records, below), published organisation DNS settings, and
  actor-attributed audit events. Location, process inventory, and DNS query
  names are not collected.
- A relay keeps node identifiers and public socket addresses in memory. Registrations
  expire after 120 seconds idle. It forwards opaque WireGuard ciphertext and cannot
  decrypt the inner traffic.
- Runtime logs contain operational identifiers, counts, errors, and configured or
  observed endpoints where noted. They must not contain private WireGuard keys, raw
  join keys, node tokens, browser device codes, passwords, or tunnel payloads.

BlakTail does not add advertising, third-party analytics, tracking pixels, remote
fonts, or public-DNS forwarding. Better Auth session cookies are used to sign in and
protect the console. The macOS desktop stores its session token in Keychain.

## MDM/EDR posture integrations (optional, off by default)

An organisation owner may connect one of these providers. Nothing is pulled
until the owner acknowledges the notice in `/posture`. For every provider
BlakTail keeps only the provider's device ID, hostname, serial number, MAC
addresses, a pass/fail verdict with a short status label, the provider's
last-seen time and BlakTail's sync time — the latest record per device, no
history. The rest of each response is discarded after parsing. Records are
deleted when the integration is removed or its settings change.

| Provider | Endpoint called | Fields used |
| --- | --- | --- |
| Microsoft Intune | `GET graph.microsoft.com/v1.0/deviceManagement/managedDevices` (app permission `DeviceManagementManagedDevices.Read.All`) | id, deviceName, serialNumber, wiFiMacAddress, ethernetMacAddress, complianceState, lastSyncDateTime |
| CrowdStrike Falcon | Hosts API scroll + `devices/entities/devices/v2` (scope Hosts: Read) | device_id, hostname, serial_number, mac_address, status, reduced_functionality_mode, last_seen |
| SentinelOne | `GET /web/api/v2.1/agents` (Viewer service user) | id, computerName, serialNumber, physical MACs, infected, isActive, isUpToDate, lastActiveDate |
| FleetDM | `GET /api/v1/fleet/hosts` (Observer API-only user) | id, hostname, hardware_serial, primary_mac, issues.failing_policies_count, seen_time |
| Huntress | `GET api.huntress.io/v1/agents` | id, hostname, serial_number, mac_addresses, last_callback_at |

**Residency.** These calls leave the deployment. Microsoft Graph,
CrowdStrike's US/EU clouds, SentinelOne consoles and Huntress are vendor
clouds that may be outside Australia; FleetDM data stays wherever your Fleet
server runs. BlakTail does not verify where a vendor hosts your tenant and
never labels an integration "onshore". The provider's own terms govern the
data it holds. Provider credentials are sealed at rest and never logged.

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
upload aggregate counters per minute bucket (bytes, packets, the peer
device's id, which side started the flow, protocol, service class and port,
transport, allow/deny) — never payloads, URLs, DNS questions, host names or
IP addresses — kept for 1–30 days as the owner chooses and deletable at any
time from `/traffic`. Linux, macOS, Windows and iOS agents report; Android
does not. Turning collection off stops agents within seconds and discards
their unsent counters. A Linux lab on 3 October 2026 checked that stored rows
contained no IP address and that nothing was stored before opt-in or after
opt-out. See [audit-and-traffic.md](audit-and-traffic.md).

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
