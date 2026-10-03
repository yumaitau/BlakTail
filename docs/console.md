# Console

`apps/console` is the BlakTail operator UI. Bun 1.4 runs Next.js 16.3 (App
Router), Better Auth, and Drizzle over Bun's native SQL client against onshore
Postgres. The Rust coordinator remains the source of truth for tailnet
authorisation.

## Pages

- `/sign-in` — email and password; shows the shared project mission
- `/privacy` — public software data-handling and retention statement
- `/devices` — device inventory across linked networks; each row shows its
  network and expands for rename, routes, tags, and revocation. The device
  name opens its detail page.
- `/devices/{nodeId}?organisation=…` — one device: node id, owner, WireGuard
  key fingerprint, friendly/technical/MagicDNS names, addresses, tags, approved
  routes, last heartbeat (online or stale by coordinator time), agent/OS
  version against the coordinator's minimum, credential expiry, the
  agent-reported transport (direct, relay, mixed, or "not measured") with its
  timestamp, per-peer tunnel protection as this device's agent reports it,
  recent audit entries for the device, and suspend/resume, revoke and delete
  with an impact preview (owner/admin)
- `/join-keys` — enrolment workspace (owner/admin): mint named one-use or
  reusable keys with optional maximum uses, expiry and tags; the secret is
  shown once; inventory with creator, uses left, last use, expiry and revoke;
  install steps per platform that never contain the secret
- `/acls` — people groups and access rules (owner/admin write), plus
  **Explain access** for any member: matched rule, deny precedence, posture,
  pairing and whether the destination device actually enforces the result
- `/posture` — versioned posture checks (owner/admin write) and each
  device's current assessment; self-reported data is labelled as such.
  **Integrations** (owner-only to connect): add an MDM/EDR provider with
  its fields and a write-only secret after acknowledging its data and
  residency notice, test the connection, see last sync, matched, ambiguous
  and unmatched counts, and outage state. Only implemented providers are
  listed. Device assessments show each provider's signal and source
- `/tunnel-protection` — opt-in hybrid post-quantum WireGuard pre-shared keys
  (owner writes; off by default): off/prefer/require with optional tag-pair
  rules and blocking under require, which agents advertise `pq-psk`, and every
  pair's negotiated state as each agent reports it ("Classical", "Hybrid PQ
  (ML-KEM-768 + X25519), rotated Ns ago", "Required but not established").
  There is no account-wide badge. See [post-quantum.md](post-quantum.md)
- `/topology` — who can reach what in the selected organisation: devices
  (online, stale, suspended, expired, agent-reported transport with its
  timestamp or "not measured"), network resources and routing peers, approved
  routes, and every effective path with a text explanation and a link to the
  page that owns it. Searchable and filterable; an optional static graph
  groups devices by tag. See [Topology and change drafts](#topology-and-change-drafts).
- `/changes` — server-side change drafts: stage access policy, network
  resource and DNS changes together, preview the diff and reachability change,
  and publish them atomically (owner, admin and network admin; members and
  auditors see summaries)
- `/dns` — organisation DNS workspace: effective settings, nameserver groups,
  custom zones, split DNS, split-match preview and revision history (owner/admin write)
- `/devices/{nodeId}/terminal` and `/devices/{nodeId}/desktop` — browser SSH
  (xterm.js) and RDP (Guacamole) through the onshore gateway, for owner, admin
  and network admin, with an access reason and a recent sign-in
  ([remote-access.md](remote-access.md))
- `/remote-access` — gateway settings (owner), pinned SSH host keys with an
  accept step for changed keys, and recent sessions with revoke
- `/remote-jobs` — owner-defined argv job templates, run requests, owner
  approval, cancel, and capped output
- `/services` — private service names, target device, access tags, status and
  the organisation service CA (owner/admin write)
- `/agents` — agent network (AI model gateway): offshore policy (owner),
  gateway designation (a device reporting the capability acts as a gateway
  only once an owner or admin designates it; audited),
  model providers with their declared data location, agent keys (secret shown
  once) and per-key policies, usage by key/model/day and recent requests
  (owner/admin write, auditor read; see [agent-gateway.md](agent-gateway.md))
- `/ingress` — **public** ingress: organisation on/off setting, owner
  designation of ingress hosts (the capability alone receives nothing), public routes
  (marked PUBLIC, styled apart from private services), per-ingress status,
  certificate expiry and policy reachability; owner-only to enable or publish,
  owner/admin/network admin may emergency-disable ([public-ingress.md](public-ingress.md))
- `/audit` — actor-attributed administration changes from the coordinator and
  console, filterable by actor, action, target and UTC date, paged with one
  cursor across both stores, redacted details, integrity-chain status, and
  CSV/JSON export for roles with `export_audit` ([audit-and-traffic.md](audit-and-traffic.md))
- `/traffic` — opt-in aggregate traffic diagnostics (owner turns on; off by
  default) with disabled, no-data and stale states; current agents do not
  report traffic yet
- `/status` — status-only coordinator readiness; region stays in protected diagnostics
- `/operations` — **Operator health** (owners and auditors only, enforced by the
  coordinator): console, coordinator and schema versions, relay reachability
  probed from the coordinator, this organisation's webhook outbox depth and
  dead letters, credential and certificate expiry counts, SSO provider counts,
  and the operator-recorded last backup. No keys, tokens or webhook addresses
- `/settings` — separate **Network accounts** and **Ways to sign in**, secure
  login linking/unlinking, owner conflict decisions, invitations, and account details
- `/invite?token=…` — one-use invitation acceptance; public account creation remains disabled

## Topology and change drafts

`GET /v1/orgs/{org}/topology` (any member) is a read model, not a second
policy engine: device-to-device paths come from the same evaluator and
peer-map compiler that agents receive (`policy_explain::device_flow`), and
resource paths from the network-resource distribution. Suspended and expired
devices have no paths. Path type combines the two endpoints' own transport
summaries; it is not a per-pair measurement, reports older than ten minutes
show as not measured, and nothing is sent to external analytics. Pairwise
evaluation stops at 400 active devices and says so.

A change draft (`/v1/orgs/{org}/changes`) is bound to one organisation,
versioned, and expires after seven days. It stores proposed documents for any
of access policy, DNS and network resources (the full desired resource list),
plus the live etag of each surface when it was created. Creating, editing,
previewing, rebasing, discarding and publishing need the permission of every
surface the draft touches (`manage_policy`, `manage_dns`,
`manage_networks`); other roles get summaries without payloads. Keys that look
like credentials are refused.

Preview and publish run the same code: every surface is applied with the
ordinary validators and writers on one database transaction, which preview
rolls back and publish commits. Publish therefore applies all surfaces or
none, bumps the control revision once, and records `change_draft.published`
with the draft id and before/after revisions (plus `acl.updated`,
`dns.updated` and per-resource entries). If any surface changed since the
draft's base, publish returns 409 and the draft must be rebased; editing with
a stale draft version returns 412. Risk flags (deny rules removed, defaults
widened, default-route exposure, nested route overlap, deleted resources,
paths opened or closed, DNS warnings) must each be confirmed. Last-owner
lockout does not apply: these surfaces cannot remove console access.

Limits: agents still pick up the published state on their next poll, so
devices converge over seconds rather than at one instant; the console shows
the previous document as the one-step rollback for policy and DNS, but there
is no multi-surface undo yet; reachability is address-family neutral.

## First owner and invitations

Public email/password sign-up is disabled in Better Auth itself. A fresh database
starts `uninitialised`; first ownership must be claimed from a trusted shell where
the console has its normal `DATABASE_URL`, `COORD_BASE_URL`, and
`BLAKTAIL_AUTH_HMAC_SECRET` environment. Run migrations first, then:

Commands below run from the repository root with Bun 1.4.

```sh
umask 077
openssl rand -base64 32 > owner-password
bun --filter @blaktail/console bootstrap -- init --token-file ./bootstrap-token
bun --filter @blaktail/console bootstrap -- claim \
  --token-file ./bootstrap-token \
  --password-file ./owner-password \
  --email owner@example.org.au \
  --name "First Owner" \
  --organisation-name "Example Organisation"
rm -f ./bootstrap-token
```

Both input files must be regular files inaccessible to group/other (`0400` or
`0600`). `init` creates one random, hashed-at-rest credential that expires after 15
minutes by default. `claim` reserves the coordinator organisation, creates one
Better Auth user and owner membership, commits the coordinator reservation, then
locks bootstrap. Console management stays unavailable until every stage succeeds.
Rerun the exact claim after a transient failure; use
`bun --filter @blaktail/console bootstrap -- status`
for a redacted state check. Races produce one owner and one rejection, and a locked
or expired credential cannot create another owner.

Migration locks any deployment already containing an owner. It reports ownerless
console organisations through `status` without silently assigning them. Repair
requires an explicit operator decision.

After bootstrap, owners invite people from `/settings`. Each URL is shown once,
expires after 48 hours, is bound to one email, role, and organisation, and can be
revoked before use. For a new email, acceptance atomically creates the account and
membership. For an existing email, the recipient signs in first and acceptance adds
the new membership to that same account without ending the session or replacing any
existing memberships. An unauthenticated attempt cannot attach a workspace to an
existing identity. Used, expired, revoked, mismatched, and cross-organisation tokens
are rejected. Admins and members cannot create or revoke invitations.

## Multiple workspaces in one session

This is a product invariant: a person's login identity and an organisation's
network account are different records. One Better Auth user can hold memberships
in many organisation workspaces, and membership in a second network never requires
logging out of the first. The
sidebar workspace selector persists an active workspace in an HTTP-only cookie;
the cookie is only a preference, and every request rechecks the selected ID against
the signed-in user's live memberships. Invalid or removed workspace selections
cannot fall through to a write in another organisation.

`/devices` deliberately ignores that display preference and concurrently loads the
machine inventory for every accessible workspace. Each row names its network and
carries that organisation ID into rename, route-approval, and revoke actions. The
server resolves the submitted ID back through the current user's memberships before
signing a coordinator assertion. This prevents a machine ID from being acted on
through whichever workspace happened to be selected first.

Organisation-scoped pages such as join keys, ACLs, audit, invitations, settings,
and browser enrolment use the active workspace. Switching them requires no logout
and does not issue or replace a Better Auth session. The desktop session endpoint
also returns the full workspace list and accepts `X-BlakTail-Organisation` for an
explicit, membership-checked selection.

Lost sole-owner credentials have no web reset. From a trusted host, create a new
protected password file and run:

```sh
bun --filter @blaktail/console bootstrap -- recover-owner \
  --email owner@example.org.au \
  --password-file ./new-owner-password
```

Recovery requires the exact sole-owner email, rotates that credential, revokes all
existing sessions, and writes an audit event.

## Linked login identities and network accounts

The product invariant is: **one person, many network accounts, one all-machines
view, with no logout/login switching**. The data model intentionally keeps the
person, immutable login identities (Better Auth users), authentication methods
(Better Auth accounts), organisation memberships, and named network accounts as
separate records. Linking changes only the person-to-identity graph. It never
copies a password, OIDC access/refresh token, provider session, or MFA state.

**Link another login** creates a random, hashed-at-rest, ten-minute challenge
bound to the current person, login identity, and Better Auth session. Completion
requires fresh authentication of both the current and second identity. An email address,
invitation URL, existing browser cookie, or cross-origin request is insufficient.
Challenges are single-use; replay, expiry, an already-linked identity, a changed
link graph, or concurrent attempts fail closed and write redacted audit events.
Errors use a generic reauthentication/recovery response so they do not disclose
whether an unrelated identity exists.

A same-organisation role mismatch pauses linking after fresh authentication.
An owner of that organisation must explicitly choose one of the existing roles as
the effective linked-person role. Both membership rows and their original roles
remain intact, and the decision is audited. A changed membership signature
invalidates the decision instead of silently elevating access.

Unlink and revocation require fresh authentication of the current identity.
Unlink moves the other identity back to its own person without deleting its
memberships. Revocation suspends only that identity in the live graph. The console
refuses to remove the last active sign-in or to suspend an identity that would
orphan a sole-owner organisation. Recovery reactivates the identity and is
audited. Existing browser and desktop sessions resolve the graph and memberships
again on every request, so unlink, deletion, suspension, role changes, and network
account revocation take effect on the next request.

Email changes do not relink accounts because identity ownership uses immutable
user IDs, never matching email strings. OIDC identities are keyed by issuer and
subject; a subject change is a new identity requiring the same explicit link or
recovery process. Deleting an identity cascades only its own network accounts and
memberships; unrelated linked identities remain. Provider-specific
reauthentication must preserve provider MFA when OIDC linking is enabled.

The browser `GET /api/me` and desktop `GET /api/desktop/me` responses list all
live organisations and network accounts. The workspace cookie selects only which
organisation-scoped ACL, key, audit, invitation, and enrolment pages are shown; it
is not an authorisation boundary and does not replace the Better Auth session.
Every device mutation from All networks submits the row's organisation ID and
performs a fresh membership/role lookup before a coordinator assertion is signed.


## Auth flow

1. Operators sign in with Better Auth. Sessions live in onshore Postgres.
2. On every request, the console resolves the current identity's live person graph,
   active network accounts, and all organisation memberships. Each coordinator
   mutation then selects the row's owning organisation and checks its live role.
3. The console signs a fresh assertion for each coordinator request. It binds the
   actor, role, organisation, exact issuer (`blaktail-console`), audience
   (`blaktail-coord`), action where applicable, a 60-second maximum lifetime, and a
   random nonce. It never contains the Better Auth cookie or session token.
4. Rust verifies every claim and consumes each nonce once. Missing, replayed,
   expired, cross-org, wrong-audience, wrong-issuer, or forged assertions receive
   `401`; valid actors without the required role receive `403`.
   Unknown role strings are rejected with `401`. Roles and the permission each
   action needs are in [roles.md](roles.md).
5. Organisations can require a recent sign-in for security changes and
   two-step verification for password owners and admins. Password sign-ins of
   identities with TOTP enabled show a code step after the password.

For headless Linux enrollment, `blaktaild up` prints `/enroll?code=...`. The
page preserves that destination through sign-in, displays the requested node name
and WireGuard-key fingerprint, and requires an explicit approval. Any signed-in
organisation member can enroll their own untagged device; only roles that can
manage devices (owner, admin, network admin) can attach privileged device tags. The browser code is not the join secret.

The Devices page also shows each node's requested subnet and exit routes. Owners
and admins approve routes individually; members can see them but cannot change
approval. An unchecked request is never included in peer WireGuard configuration.
Owners and admins can also set or clear a 64-character friendly name. This label is
for people: the agent-provided name, MagicDNS hostname, WireGuard identity, routes,
and persisted agent state do not change.

The Networks page names private subnets as resources, picks routing peers with a
failover metric, chooses which roles, tags or policy groups receive each route,
and shows routing-peer health and effective distribution per device. Members can
read it; owners and admins change it. See [network-resources.md](network-resources.md).
A DNS resource's page also shows its app connector's current answers, lease
expiry, each connector's last report and any block reason
([app-connectors.md](app-connectors.md)).

`/networks/addresses` shows the IPv4 and IPv6 device pools with used, reserved,
grace-period and available counts, every address with its owner, reservations
and conflicts. Owners, admins and network admins reserve and release addresses;
everyone else can read it. See [ipam.md](ipam.md).


`/dns` publishes organisation DNS (Settings now links there). The page shows the
published revision, how many enrolled devices have applied it, whether DNS is
managed, the protected MagicDNS suffix and coordinator warnings (for example
loopback or link-local record targets). Owners and admins edit nameserver groups
(ordered resolvers, match domains, enabled, all devices or office/ranger/store
tags), custom zones with A/AAAA/CNAME/TXT records and TTLs, and the original
split suffixes, search domains and extra A/AAAA records. An Advanced JSON editor
covers the whole document. **Check** asks the coordinator to validate and
canonicalise the draft without publishing; **Publish DNS** sends it with the
current etag, and a stale etag shows "Someone else published a newer revision;
reload". The split-match preview answers which source handles a name for a chosen
device or tag set (MagicDNS, zone, forwarded group or split route, or not
handled). Revision history lists revisions recorded since this workspace shipped,
compares any of them with the current document as a line diff, and restores one
as a new revision; one-step rollback still covers the latest earlier revision.
Members can read everything and use preview but cannot publish. Agents older than
this release answer only zone A/AAAA records.

`/services` lists private services under the organisation's
`svc.<org-prefix>.blaktail` namespace, separate from device MagicDNS names. Owners
and admins preview a name (full name, collisions, warnings) before creating it,
choose the target device, local port and protocol, and the device tags allowed to
use it, and can disable or delete it (certificates are revoked). Status comes from
the target device's serving agent (`blaktaild up --serve-services`): "Awaiting
certificate", "Certificate issued, not serving" (no fresh report naming the live
certificate), "Target unhealthy" (listener up, local target failing its check) or
"Serving". Only "Serving" publishes the name to allowed devices' MagicDNS, and it is
the device's own report, not a probe from a client. The organisation service CA
certificate and fingerprint can be viewed and downloaded; clients can install it
with `blaktaild trust-service-ca` (explicit, never automatic). See
`docs/private-services.md`.

`/ingress` (nav group "Services", labelled PUBLIC) is the only place a service
is put on the Internet. Public ingress is off per organisation until an owner
records an abuse contact and types `PUBLIC`. Owners publish a route by typing
its hostname again, choose an HTTP private service or a device and port as the
target, the certificate source (operator files or ACME HTTP-01 on the ingress
host), optional organisation sign-in (OIDC, optionally restricted to email
domains), per-client request rate, body size, connection limit and access-log
retention. Each route shows, per ingress host, whether it is live, blocked by
policy, offline, not designated or withdrawn, and the certificate expiry the
ingress reported. Under *Ingress hosts* an owner designates which capable
devices may act as ingress; an undesignated device receives no routes.
Owners, admins and network admins can emergency-disable a route; only an owner
can re-enable it, again by typing the hostname. Members and auditors see the
routes and status with no controls.

Device details list overlay file shares published by `blaktaild share enable`.
The coordinator stores the path and label only; file bytes never leave the node
except over the tailnet. Peers open the URL in a browser or mount it read-only
in Finder with Connect to Server.

The Audit log is readable by every organisation member. Bootstrap, invitation use
and revocation, role assignment, denied invitation administration, join-key
minting, browser enrollment approval, friendly-name changes, route approval, ACL
updates, node-key lifetime updates, and console revocation are recorded with actor,
source, and result. Raw bootstrap credentials, invitation tokens, passwords,
sessions, join keys, node tokens, and browser device codes are never included.
Details are also redacted by key name and value shape when displayed or
exported. Exports are audited as `audit.exported`.

Settings → Webhooks lets owners and admins choose which catalogued events
each destination receives, inspect deliveries (including dead-lettered ones
and their last error) and replay them. Settings → Notification channels adds
email, Slack and Microsoft Teams destinations with quiet hours, digests and
**Send test**; Slack and Teams need an owner's residency acknowledgement
([notifications.md](notifications.md)). Settings → Directory group roles maps
SCIM groups and OIDC `groups` claims to roles with a drift preview
([identity.md](identity.md#directory-groups-and-roles)).

## Local development

To run console, coordinator, and relay together, use
`scripts/quickstart.sh` ([getting-started.md](getting-started.md)).
The steps below are console-only.

```sh
cp apps/console/.env.example apps/console/.env
# point DATABASE_URL at onshore Postgres, then:
bun install
bun --filter @blaktail/console db:migrate
# complete the on-host first-owner ceremony above, then:
bun run dev:console
```

Build checks used in CI:

```sh
bun ci
bun run lint
bun run typecheck
bun --filter @blaktail/console db:migrate
bun --filter @blaktail/console test
bun run build
bun --filter @blaktail/console test:auth-e2e
```

UI smoke uses Lightpanda as the browser and Playwright-core over CDP.
`lightpanda mcp --cdp-port 9222` is the Cursor MCP server (see `.cursor/mcp.json`);
the Playwright script attaches to that port, or starts `lightpanda serve` itself.

```sh
# Lightpanda cannot open RFC1918 addresses; tunnel loopback HTTPS instead.
CONSOLE_URL=https://127.0.0.1:3443 \
CONSOLE_EMAIL=owner@homelab.test \
CONSOLE_PASSWORD_FILE=./owner-password \
CONSOLE_SSH_TUNNEL=homelab \
CONSOLE_CA_FILE=./certs/ca.crt \
bun --filter @blaktail/console test:ui
```

Do not pull fonts or analytics from offshore CDNs.

Before public hosting, complete the operator-specific requirements in
[privacy.md](privacy.md): legal name, contact, verified data/backup locations,
retention, subprocessors, and request handling. The generic `/privacy` page does not
invent those deployment-specific facts.
