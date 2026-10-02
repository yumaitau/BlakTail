#!/bin/sh
set -eu

die() {
  printf 'install-agent: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || die "run as root (for example: sudo sh scripts/install-agent.sh)"
command -v curl >/dev/null 2>&1 || die "curl is required"

repository=${BLAKTAIL_REPOSITORY:-jusso-dev/BlakTail}
case "$repository" in
  *[!A-Za-z0-9_./-]* | */*/* | /* | */) die "invalid BLAKTAIL_REPOSITORY" ;;
esac
version=${BLAKTAIL_VERSION:-latest}
case "$version" in
  latest) tag=latest ;;
  v[0-9]* | [0-9]*)
    clean_version=${version#v}
    case "$clean_version" in
      *[!0-9A-Za-z.+~-]*) die "invalid BLAKTAIL_VERSION" ;;
    esac
    tag=v$clean_version
    ;;
  *) die "BLAKTAIL_VERSION must be latest or a release version" ;;
esac

case "$(uname -s):$(uname -m)" in
  Darwin:arm64)
    target=aarch64-apple-darwin
    format=pkg
    ;;
  Darwin:x86_64)
    target=x86_64-apple-darwin
    format=pkg
    ;;
  Linux:aarch64 | Linux:arm64)
    target=aarch64-unknown-linux-gnu
    if command -v dpkg >/dev/null 2>&1 && [ -f /etc/debian_version ]; then
      format=deb
    elif command -v rpm >/dev/null 2>&1; then
      format=rpm
    else
      die "supported package manager not found (dpkg or rpm)"
    fi
    ;;
  Linux:x86_64)
    target=x86_64-unknown-linux-gnu
    if command -v dpkg >/dev/null 2>&1 && [ -f /etc/debian_version ]; then
      format=deb
    elif command -v rpm >/dev/null 2>&1; then
      format=rpm
    else
      die "supported package manager not found (dpkg or rpm)"
    fi
    ;;
  *) die "unsupported operating system or architecture" ;;
esac

release_root=${BLAKTAIL_RELEASE_BASE_URL:-"https://github.com/$repository/releases"}
case "$release_root" in
  https://*) ;;
  *) die "BLAKTAIL_RELEASE_BASE_URL must use HTTPS" ;;
esac
if [ "$tag" = latest ]; then
  download_root="$release_root/latest/download"
else
  download_root="$release_root/download/$tag"
fi

asset="blaktaild-$target.$format"
work=$(mktemp -d "${TMPDIR:-/tmp}/blaktail-install.XXXXXX")
cleanup() {
  if [ -n "${work:-}" ] && [ -d "$work" ]; then
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT HUP INT TERM

curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "$download_root/$asset" --output "$work/$asset"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "$download_root/SHA256SUMS" --output "$work/SHA256SUMS"

# Sigstore keyless signature over SHA256SUMS, bound to the release workflow at
# this tag. Verified whenever cosign is installed; required with
# BLAKTAIL_REQUIRE_SIGNATURE=1.
if command -v cosign >/dev/null 2>&1 || [ "${BLAKTAIL_REQUIRE_SIGNATURE:-0}" = 1 ]; then
  command -v cosign >/dev/null 2>&1 || die "BLAKTAIL_REQUIRE_SIGNATURE=1 needs cosign on PATH"
  [ "$tag" != latest ] || die "signature verification needs a pinned BLAKTAIL_VERSION"
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    "$download_root/SHA256SUMS.sigstore.json" --output "$work/SHA256SUMS.sigstore.json"
  cosign verify-blob \
    --bundle "$work/SHA256SUMS.sigstore.json" \
    --certificate-identity "https://github.com/$repository/.github/workflows/agent-release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$work/SHA256SUMS" >/dev/null 2>&1 || die "Sigstore signature on SHA256SUMS did not verify"
fi

expected=$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { print $1 }' "$work/SHA256SUMS")
[ -n "$expected" ] || die "$asset is missing from SHA256SUMS"
[ "${#expected}" -eq 64 ] || die "invalid SHA-256 entry for $asset"
case "$expected" in
  *[!0-9a-f]*) die "invalid SHA-256 entry for $asset" ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work/$asset" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$work/$asset" | awk '{ print $1 }')
else
  die "sha256sum or shasum is required"
fi
[ "$actual" = "$expected" ] || die "SHA-256 mismatch for $asset"

case "$format" in
  pkg)
    pkgutil --check-signature "$work/$asset" >/dev/null 2>&1 || \
      die "macOS package is not signed with a trusted installer certificate"
    spctl --assess --type install "$work/$asset" >/dev/null 2>&1 || \
      die "macOS package failed Gatekeeper assessment"
    installer -pkg "$work/$asset" -target /
    printf '%s\n' \
      "Installed blaktaild. Enrol once with 'sudo blaktaild up --coord https://… --exit-after-join', then bootstrap the LaunchDaemon."
    ;;
  deb)
    dpkg -i "$work/$asset"
    printf '%s\n' \
      "Installed blaktaild. Enrol once with 'sudo blaktaild up --coord https://… --exit-after-join', then run 'sudo systemctl enable --now blaktaild'."
    ;;
  rpm)
    rpm -Uvh "$work/$asset"
    printf '%s\n' \
      "Installed blaktaild. Enrol once with 'sudo blaktaild up --coord https://… --exit-after-join', then run 'sudo systemctl enable --now blaktaild'."
    ;;
esac
