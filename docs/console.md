# Console

`apps/console` is the BlakTail operator UI. Bun 1.4 runs Next.js 16.3 (App
Router), Better Auth, and Drizzle over Bun's native SQL client against onshore
Postgres. The Rust coordinator remains the source of truth for tailnet
authorisation.

## Pages

- `/sign-in` — email and password; shows the shared project mission
- `/privacy` — public software data-handling and retention statement
- `/devices` — device inventory across linked networks; each row shows its
  network and expands for rename, routes, tags, and revocation
- `/join-keys` — mint join keys (owner/admin)
- `/acls` — people groups and access rules (owner/admin write)
- `/dns` — organisation DNS workspace: effective settings, nameserver groups,
  custom zones, split DNS, split-match preview and revision history (owner/admin write)
- `/services` — private service names, target device, access tags, status and
  the organisation service CA (owner/admin write)
- `/audit` — latest actor-attributed security and administration changes
- `/status` — status-only coordinator readiness; region stays in protected diagnostics
- `/settings` — separate **Network accounts** and **Ways to sign in**, secure
  login linking/unlinking, owner conflict decisions, invitations, and account details
- `/invite?token=…` — one-use invitation acceptance; public account creation remains disabled

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

For headless Linux enrollment, `blaktaild up` prints `/enroll?code=...`. The
page preserves that destination through sign-in, displays the requested node name
and WireGuard-key fingerprint, and requires an explicit approval. Any signed-in
organisation member can enroll their own untagged device; only owners and admins
can attach privileged device tags. The browser code is not the join secret.

The Devices page also shows each node's requested subnet and exit routes. Owners
and admins approve routes individually; members can see them but cannot change
approval. An unchecked request is never included in peer WireGuard configuration.
Owners and admins can also set or clear a 64-character friendly name. This label is
for people: the agent-provided name, MagicDNS hostname, WireGuard identity, routes,
and persisted agent state do not change.

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
use it, and can disable or delete it (certificates are revoked). Status is honest:
no serving-agent listener ships yet, so services show "Awaiting serving agent" (or
"Certificate issued, not verified") and are never presented as reachable or
published in DNS. The organisation service CA certificate and fingerprint can be
viewed and downloaded; trusting it on clients is manual.

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
