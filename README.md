# BlakTail

![BlakTail: secure, open and self-hosted private networking in Australia](docs/images/blaktail-banner.png)

> Built by Indigenous Australians for Indigenous Australian organisations. Data stays onshore, Indigenous Australian organisations stay in control, and the code stays public.

## What is BlakTail?

BlakTail is open, self-hosted private networking for Indigenous Australian
organisations. It connects laptops, field devices, servers, and sites with
encrypted WireGuard links while the organisation keeps identity, policy, keys,
and operational data.

It can join a handful of machines or a whole estate. The supplied cloud path is
pinned to Sydney. There is no hosted product; you run the control plane yourself.

Further documentation is in [docs/](docs/getting-started.md).

## Supported platforms

Until the first release is published, build from source. Do not use
`scripts/install-agent.sh` yet; it fails when no GitHub release exists. See
[docs/releases.md](docs/releases.md).

#### Desktop and server

- Linux — `blaktaild` (kernel WireGuard, userspace fallback)
- macOS — `blaktaild` plus a native SwiftUI manager (`apps/macos`, macOS 14+)
- Coordinator, relay, and console — Docker on Linux or macOS, or a Linux host

#### Mobile

- iPhone — native client (`apps/ios`, iOS 17+). Direct UDP only; relay fallback is still the Mac/Linux agent cut.

Windows agents and a Windows/Linux desktop app are not in this repository.

## Technical overview

BlakTail is a mutually authenticated WireGuard overlay. The coordinator assigns
each node a CGNAT IPv4 address and an organisation ULA IPv6 address, pushes
peers, tags, and ACLs, and signs enrolment. The Australian relay is the
encrypted fallback when a direct UDP path fails. The operator console holds
login identity (Better Auth) and never stores node private keys. One live
session can show every machine across explicitly linked network accounts.
Discovery and policy stay with the organisation; the repository stays public.

## Getting started (quickly)

There is no managed BlakTail service. To stand up a network on your laptop:

#### 1. Install Docker (Compose v2) and OpenSSL, then clone this repo

```sh
git clone https://github.com/jusso-dev/BlakTail && cd BlakTail
```

The agent later needs a Rust toolchain (this repo pins 1.98 in
`rust-toolchain.toml`) and, on Linux, `iproute2`, `wireguard-tools`, and
`iptables`. Root or `CAP_NET_ADMIN` is required to create the tunnel.

#### 2. Start the control plane

```sh
./scripts/quickstart.sh
```

Or `make up`. That writes local secrets into `.env`, starts Postgres, the
coordinator, the relay, and the console, generates throwaway certificates
inside Compose, and claims the first owner. The first image build compiles
Rust and Next.js and can take several minutes. If Docker is a remote
context, the script prints that host's console and coordinator URLs instead
of `localhost`.

#### 3. Sign in to the console

Open [http://localhost:3000](http://localhost:3000).

- Email: `owner@example.org.au`
- Password: the contents of `./owner-password` (mode `0600`)

Public sign-up is disabled. After this first-owner ceremony, invite people from
**Settings**.

#### 4. Build the agent for this machine

```sh
cargo build --locked --release -p blaktaild -p blaktail-config
sudo install -m 0755 target/release/blaktaild /usr/local/bin/blaktaild
sudo install -m 0755 target/release/blaktail-config /usr/local/bin/blaktail-config
```

#### 5. Enrol the node

```sh
sudo blaktaild up --coord https://127.0.0.1:8443 --coord-ca certs/ca.crt
```

`up` prints a ten-minute console URL and waits. It does not require a join key.

#### 6. Approve the device

Open that URL, confirm the device name and WireGuard-key fingerprint, then
approve it. Give it a friendly name if you want; the technical hostname and
MagicDNS identity stay stable.

#### 7. Confirm the tunnel

```sh
sudo blaktaild status
```

A second machine repeats steps 4–7 against the same coordinator. Enrolment
over SSH works the same way. Two machines behind separate NATs with no
inbound forwarding rely on the relay fallback, which is not yet proven
across independent NAT paths (see project status).

Example inputs live in [examples/](examples/). The full configuration schema is
[config/blaktail.toml.example](config/blaktail.toml.example).

For troubleshooting, a second node, and teardown, see
[docs/getting-started.md](docs/getting-started.md). To put the same Compose stack
on a public host, or to run the disposable Sydney AWS harness, see
[docs/deploy-aws.md](docs/deploy-aws.md).

## Building from source

Rust 1.98 (see `rust-toolchain.toml`), Bun 1.4 for the console, and Docker for
the bundled stack.

```sh
make rust     # cargo build --locked --workspace
make agent    # release blaktaild + blaktail-config
make up       # local Compose control plane
make down     # docker compose down
```

macOS desktop and iPhone clients:

```sh
bash scripts/validate-macos-desktop.sh
cd apps/macos && swift test

bash scripts/validate-ios-phone.sh
cd apps/ios && swift test
```

## Project status

BlakTail is pre-release. What works, what does not, and the verified Sydney
smoke run are in [docs/project-status.md](docs/project-status.md). Onshore
operation is a deployment duty: keep the console database, coordinator state,
TLS proxy, logs, backups, DNS, and support tooling in Australia.

## What never goes in git

The repository is public. Secrets are organisation-held.

Do not commit node WireGuard private keys, TLS private keys, join keys
(`btk_…`), node tokens (`btn_…`), coordinator dumps, `.env`,
`BETTER_AUTH_SECRET`, `BLAKTAIL_AUTH_HMAC_SECRET`, or live `wg*.conf`.
`.gitignore` blocks the common patterns. CI runs gitleaks and `cargo deny`.
If a real secret lands in git, rotate it; deleting the file later does not
erase the blob.

## License

Apache-2.0
