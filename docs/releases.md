# Agent release artifacts

BlakTail is pre-release. The repository currently has no published release tag, so
`scripts/install-agent.sh` must not be advertised as a working quickstart until a
release containing all required assets exists.

Each agent release uses one tag and these fixed asset names:

- `blaktaild-aarch64-apple-darwin.pkg`
- `blaktaild-x86_64-apple-darwin.pkg`
- `blaktaild-aarch64-unknown-linux-gnu.deb`
- `blaktaild-x86_64-unknown-linux-gnu.deb`
- `blaktaild-aarch64-unknown-linux-gnu.rpm`
- `blaktaild-x86_64-unknown-linux-gnu.rpm`
- `SHA256SUMS`
- `SHA256SUMS.sigstore.json` (Sigstore keyless signature bundle over `SHA256SUMS`)

See [compatibility.md](compatibility.md) for which console, coordinator, relay
and agent versions work together and what a rollback can undo.

Build on the matching native operating system. Linux binaries must be built on the
oldest glibc baseline supported by that release; do not relabel a binary built for a
different target.

```sh
cargo build --locked --release -p blaktaild -p blaktail-config
BLAKTAIL_VERSION=0.1.0 BLAKTAIL_TARGET=aarch64-apple-darwin \
  scripts/package-agent.sh pkg target/release/blaktaild dist

# On native Linux builders, produce both formats from the same tested binary.
BLAKTAIL_VERSION=0.1.0 scripts/package-agent.sh deb target/release/blaktaild dist
BLAKTAIL_VERSION=0.1.0 scripts/package-agent.sh rpm target/release/blaktaild dist
```

`pkgbuild`, `dpkg-deb`, or `rpmbuild` is required for its corresponding format.
The package installs the binary and service definition but deliberately does not
enrol the node or enable the service. Join secrets never enter package metadata,
argv, or an environment file.

Public macOS packages must be built with
both `BLAKTAIL_APPLICATION_IDENTITY="Developer ID Application: …"` and
`BLAKTAIL_INSTALLER_IDENTITY="Developer ID Installer: …"`, notarised, and stapled.
The installer rejects an unsigned package. Linux artifacts are verified against the
release's `SHA256SUMS`; this detects corruption but is not a substitute for protecting
the GitHub release account.

`scripts/publish-package-repos.sh DIST REPO_OUT` builds APT `Release` metadata and
copies RPM packages from the same bytes. Set `BLAKTAIL_REPO_GPG_KEY` to produce
`InRelease` / `Release.gpg`. Keep `stable` and opt-in `beta` as separate outputs;
never publish a mutable `latest` package identity. Repository signing keys stay
outside CI plaintext.

`.github/workflows/agent-release.yml` is the only publication path. It builds each
target on its native GitHub runner, signs and notarises both macOS packages, builds
Linux on the Amazon Linux 2023 glibc baseline, creates GitHub OIDC provenance
attestations, requires all six fixed package names, creates a draft release, uploads
the complete set, and publishes only after re-downloading and verifying the bytes.
Enable GitHub release immutability before the first tag so the published tag and
assets cannot later be replaced.

The macOS jobs fail closed unless these Actions secrets exist:

- `MACOS_DEVELOPER_CERTIFICATES_P12_BASE64`
- `MACOS_DEVELOPER_CERTIFICATES_PASSWORD`
- `MACOS_APPLICATION_IDENTITY`
- `MACOS_INSTALLER_IDENTITY`
- `APPLE_NOTARY_KEY_P8_BASE64`
- `APPLE_NOTARY_KEY_ID`
- `APPLE_NOTARY_ISSUER_ID`

The P12 must contain the named Developer ID Application and Developer ID Installer
identities. The App Store Connect API key must be authorised for notarisation. Never
store either file in the repository or a workflow artifact.

After collecting all native artifacts:

```sh
scripts/agent-checksums.sh dist
gh release create v0.1.0 dist/blaktaild-* dist/SHA256SUMS \
  --title "BlakTail agent v0.1.0" --notes-file RELEASE_NOTES.md
```

That manual command is retained only as an explanation of the asset set; public
releases must use the guarded workflow. Push an existing, exact-version tag, or
dispatch the workflow against that tag with `publish=true`. Verify downloaded
packages with:

```sh
gh attestation verify blaktaild-aarch64-unknown-linux-gnu.deb \
  --repo jusso-dev/BlakTail
```

## Signatures and reproducibility

The publish job signs `SHA256SUMS` with Sigstore keyless signing (`cosign
sign-blob`). The certificate in `SHA256SUMS.sigstore.json` names the release
workflow at the exact tag through GitHub OIDC, so there is no long-lived
signing key to store, leak or rotate. The job verifies the bundle before upload
and again after re-downloading the published bytes. Verify by hand with:

```sh
VERSION=0.1.0
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/jusso-dev/BlakTail/.github/workflows/agent-release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

`scripts/install-agent.sh` performs the same check whenever `cosign` is on
`PATH`, and refuses to install without it when `BLAKTAIL_REQUIRE_SIGNATURE=1`
(that mode needs a pinned `BLAKTAIL_VERSION`). The signature is recorded in the
public Rekor transparency log; that log is operated outside Australia and
contains only the checksum digest, certificate and workflow identity, never
package contents or customer data.

Builds pin the reproducibility inputs: `--locked` dependencies, the pinned
toolchain, `SOURCE_DATE_EPOCH` set to the tagged commit time, `CARGO_INCREMENTAL=0`
and `--remap-path-prefix` for build paths. Bit-for-bit reproduction by an
independent builder has **not** been demonstrated yet; until it is, treat the
signature and provenance attestation as the trust anchor, not a rebuild.

Before calling the release usable, install the pinned tag on clean Debian/Ubuntu,
RPM-family Linux, Apple silicon macOS, and Intel macOS hosts. Confirm the displayed
version, one-time enrollment, service startup, restart persistence, and the
[two-node drill](two-node-drill.md). Publishing files alone is not this proof.

### Clean-host drill in a lab (3 October 2026)

`deploy/homelab/prove-clean-install.sh` (Docker context `m3-max`, about four
minutes) rehearses the Debian/Ubuntu half of that list without a published
release. It builds the packages with `deploy/docker/agent-package.Dockerfile`
(the release build), serves them and `SHA256SUMS` from a lab HTTPS server, and
runs the unmodified `scripts/install-agent.sh` with `BLAKTAIL_RELEASE_BASE_URL`
pointed at it on fresh `debian:bookworm` and `ubuntu:24.04` systemd containers
(only systemd, curl and CA certificates preinstalled). Result of the last run,
arm64, 245 s:

- refusals: a tampered `.deb` (`SHA-256 mismatch`), `BLAKTAIL_REQUIRE_SIGNATURE=1`
  without cosign, and, with cosign v2.4.1 installed, a `SHA256SUMS.sigstore.json`
  that is not a valid bundle (`Sigstore signature on SHA256SUMS did not verify`).
  Nothing was installed after any refusal.
- install through the checksum path in 6 s (Debian) and 13 s (Ubuntu), with
  `wireguard-tools`, `iptables` and `iproute2` pulled in as dependencies.
- enrolment with a one-use join key on stdin (Debian) and in
  `BLAKTAIL_JOIN_KEY` (Ubuntu); about 1,200 reads of every `/proc/*/cmdline`
  taken every 50 ms during each enrolment never contained the key.
- `systemctl enable --now blaktaild`: ping both ways over the overlay; after
  `systemctl restart` on both, ping again with the same addresses.
- owner revocation of Ubuntu: Debian dropped the peer within 1 s and neither
  side could reach the other; Ubuntu's restarted service logs `authentication failed`.
- uninstall (below) on both: no binary, unit, state directory, `blaktail0`,
  iptables chain or policy rule left; both nodes show as revoked.

The drill found and fixed two bugs: the installer used bare `dpkg -i`, which
leaves the package unconfigured on a host without `wireguard-tools` and
`iptables` (it now uses `apt-get install`, or `dnf install` for RPMs), and
`blaktaild down` on an already revoked node stopped at the coordinator's 401
and left the tunnel and firewall chain behind (it now tears down locally and
says the coordinator no longer accepts the credential).

Not covered by the lab: a Sigstore bundle that **verifies** (only a tagged
GitHub release can produce one), RPM hosts, macOS packages, a real VM reboot,
and x86_64. The containers' WireGuard port is pinned to the advertised one
with `wg set` because the agent listens on a random port and there is no relay
in the lab.

## Install a published release

Download and inspect the installer from the same tag, then run it as root:

```sh
VERSION=0.1.0
curl -fsSLO "https://raw.githubusercontent.com/jusso-dev/BlakTail/v${VERSION}/scripts/install-agent.sh"
less install-agent.sh
sudo BLAKTAIL_VERSION="$VERSION" sh install-agent.sh
```

Omitting `BLAKTAIL_VERSION` selects the latest release. Pinning is recommended for
controlled rollout and rollback.

On Debian and Ubuntu the installer runs `apt-get update` and installs the
package with `apt-get install`, so its dependencies are fetched from the
distribution's archive.

### Uninstall

```sh
sudo systemctl disable --now blaktaild
sudo blaktaild down        # revokes the node; on an already revoked node it only cleans up locally
sudo apt-get purge blaktaild    # or: sudo dnf remove blaktaild
sudo rm -rf /etc/blaktail /var/lib/blaktail
```

`down` restores DNS settings, removes forwarding and filter rules and deletes
the WireGuard interface. Remove any `Include /var/lib/blaktail/sshd_policy.conf`
line you added to `sshd_config` and reload sshd.
