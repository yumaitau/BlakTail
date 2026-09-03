# Project status

BlakTail is pre-release. There is no hosted product and no published agent tag
or installer. Operators build from source until the release checklist in
[releases.md](releases.md) is complete on clean hosts.

The laptop first-run path is [getting-started.md](getting-started.md).

Today it is an organisation-run private path: a night-sky operator console, a
Rust coordinator and Australian relay, WireGuard agents for Linux and macOS,
and a native macOS endpoint manager. A person can sign in once, enrol machines,
give them friendly names, apply tags and routes, and reach authorised devices
over IPv4 and IPv6. One session can show every machine across explicitly linked
network accounts.

“Onshore” is a deployment duty as well as a product rule. Included AWS
infrastructure is pinned to Sydney and the relay rejects non-Australian cloud
region identifiers. Self-hosters must keep the console database, coordinator
state, TLS proxy, logs, backups, DNS, and support tooling in Australia.

## How onboarding feels

1. Run `blaktaild up` on a new Linux or macOS device.
2. Open the short browser link it prints and sign in to the organisation portal.
3. Check the requested device name and WireGuard-key fingerprint, then approve it.
4. Give the device a clear friendly name such as “Community office iMac” or
   “Ranger ute tablet”. The technical hostname and MagicDNS identity stay stable.
5. Connect by private address or name. Direct UDP is preferred; the Australian
   relay is the encrypted fallback.

## Console

The operator console uses the night-sky brand from the artwork in the README.
These shots are from a throwaway inventory with invented organisation and device
names. Sign-in was captured before credentials were entered. The device view
contains no enrollment code, WireGuard fingerprint, cookie, key, or cloud
secret.

![BlakTail sign-in](images/console/sign-in.png)

![All networks inventory with invented device names](images/console/devices.png)

Operator UI lives in `apps/console` (Bun 1.4, Next.js 16.3, Better Auth,
Drizzle over Bun's native SQL client, onshore Postgres).
See [console.md](console.md).

## What it is today

- Open, self-hosted private networking for Indigenous Australian organisations
- Encrypted WireGuard paths between laptops, field devices, servers, and sites
- Organisation-held identity, policy, keys, and operational data
- One live login across many network accounts, without logout/login switching
- An operator console, Linux/macOS agents, a macOS desktop manager, and an iPhone client
- Optional organisation SSO (OIDC) with a password owner as the break-glass path
- An Australian relay as the encrypted fallback when a direct UDP path fails

## What works today

- First-owner bootstrap, disabled public sign-up, and one-use invitations
- Browser enrolment and join-key enrolment for automation
- Linked login identities and one **All networks** inventory
- Stable technical and MagicDNS identity, with editable audited friendly names
- Tags, people groups, ACL rules, advertised-route approval, revoke, and tombstone
- Linux subnet routers and opt-in IPv4 exit nodes
- Dual-stack overlay addresses (CGNAT IPv4 plus an organisation ULA `/64`)
- Device posture: last-seen/online, OS, agent version, search
- Owner-minted `/api/v1` automation credentials
- Prometheus metrics and an actor-attributed audit log
- Single-host SQLite or concurrent PostgreSQL coordinator storage
- A disposable Sydney AWS proof harness, not a production SaaS
- An iPhone client that joins a network as a WireGuard node and still administers All networks

## What it is not

- Not a released product; source builds are the only supported install path
- Not a hosted SaaS or a closed-source agent
- Not a Windows agent, and not a Windows or Linux desktop app
- Scaffold note (2026-09-03, history above unchanged): `apps/linux-tray/`
  (issue #12) and `docs/windows-agent.md` plus `blaktaild/windows-service.md`
  (issue #11) now exist as honest scaffolds/notes only — no functional agent
  or desktop app ships yet.
- Not a completed iPhone relay path: the phone joins as a WireGuard client over
  direct UDP; Australian relay fallback and hole punch are still the Mac/Linux
  agent cut
- Not a file-sync product (that is BlakSync)
- Not an anonymity network; the coordinator and relay can still see metadata
- Not a production-verified NAT claim: agents have hole punching and relay
  fallback, but a forced-relay proof across two independent NAT paths is still
  open in [#24](https://github.com/jusso-dev/BlakTail/issues/24)
- Not an IPv6-only product yet: dual-stack passed on private AWS agents, but
  the drill that removes each BlakTail IPv4 address is still open in
  [#32](https://github.com/jusso-dev/BlakTail/issues/32)

## Stack (locked for first cut)

- Rust workspace: `blaktaild` (node agent), `blaktail-coord`, `blaktail-relay`, `blaktail-ios-wg`
- WireGuard: userspace on macOS, kernel WG on Linux, boringtun in the iPhone packet tunnel
- Console: Bun 1.4 runtime/package manager and native SQL client, Next.js 16.3,
  Drizzle, Better Auth, Postgres onshore. Auth sessions are issued in the console
  and verified by Rust
- Desktop: macOS SwiftUI app wrapping the LaunchDaemon agent
- iPhone: native SwiftUI client (`apps/ios`) with a Network Extension packet tunnel
- CI on GitHub-hosted runners: `ubuntu-latest` for Rust, console, and security jobs; `macos-latest` for the Swift desktop app
- Apache-2.0

## Verified AWS smoke run

Run `20260824ma1` deployed immutable ARM64 console, two coordinator replicas, and
the relay in Sydney from source commit `07e5b05`. Schema-v1 configuration emitted
only redacted effective values before explicit SQLx and Drizzle migrations. Both
coordinators then served schema-v4 PostgreSQL concurrently behind the load balancer.

The supported first-owner ceremony locked after one owner. Live HTTP checks rejected
public signup, signed that owner in, and loaded the authenticated **All networks**
page. The portal approved private Ubuntu and Amazon Linux agents, saved “Sydney
Ubuntu Agent” and “Sydney AL2023 Agent” as friendly names, and retained each stable
technical/MagicDNS identity. Both nodes passed bidirectional IPv4, IPv6, MagicDNS,
overlay-route, and SSH checks over `blaktail0` with no public IP or inbound SSH.

The HA drill stopped one coordinator during 113 continuous public health requests:
zero failed and ECS returned to 2/2 tasks. An encrypted private RDS snapshot was
restored into a temporary instance, then a private Bun task verified coordinator
schema version 4, two node rows, and console identity/membership rows. The temporary
restore and snapshot were deleted. Guarded Terraform teardown destroyed all 92
resources; native service checks found zero active scoped residue and local
passwords, enrolment material, cookies, state, browser profiles, and registry login
were removed.

See the [redacted run report](e2e/aws-fargate-run.md),
[#27](https://github.com/jusso-dev/BlakTail/issues/27), and
[#34](https://github.com/jusso-dev/BlakTail/issues/34). This is source-commit smoke
proof, not release proof: forced relay traffic, IPv6-only operation,
revocation/re-enrolment, published signed agent packages, and secure linking of
pre-existing distinct login identities remain open acceptance work.

## Related documents

- [Threat model](threat-model.md)
- [Privacy](privacy.md)
- [Observability](observability.md)
- [Identity](identity.md)
- [Operator configuration](configuration.md)
