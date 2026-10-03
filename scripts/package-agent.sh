#!/bin/sh
set -eu

usage() {
  cat >&2 <<'EOF'
usage: scripts/package-agent.sh <pkg|deb|rpm> [binary] [output-directory]

Environment:
  BLAKTAIL_VERSION             package version; defaults to Cargo.toml
  BLAKTAIL_TARGET              Rust target triple; defaults to this host
  BLAKTAIL_APPLICATION_IDENTITY optional Developer ID Application identity for pkg
  BLAKTAIL_INSTALLER_IDENTITY  optional Developer ID Installer identity for pkg
EOF
  exit 2
}

die() {
  printf 'package-agent: %s\n' "$*" >&2
  exit 1
}

format=${1:-}
case "$format" in
  pkg | deb | rpm) ;;
  *) usage ;;
esac

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
binary=${2:-"$repo_root/target/release/blaktaild"}
output_dir=${3:-"$repo_root/dist"}
[ -f "$binary" ] || die "binary not found: $binary"
[ -x "$binary" ] || die "binary is not executable: $binary"
binary=$(CDPATH='' cd -- "$(dirname -- "$binary")" && pwd)/$(basename -- "$binary")
config_binary=${BLAKTAIL_CONFIG_BINARY:-"$(dirname -- "$binary")/blaktail-config"}
[ -f "$config_binary" ] || die "config binary not found: $config_binary"
[ -x "$config_binary" ] || die "config binary is not executable: $config_binary"
config_binary=$(CDPATH='' cd -- "$(dirname -- "$config_binary")" && pwd)/$(basename -- "$config_binary")
mkdir -p "$output_dir"
output_dir=$(CDPATH='' cd -- "$output_dir" && pwd)

version=${BLAKTAIL_VERSION:-$(awk -F '"' '/^version = / { print $2; exit }' "$repo_root/Cargo.toml")}
version=${version#v}
case "$version" in
  '' | *[!0-9A-Za-z.+~-]*) die "invalid package version: $version" ;;
esac

if [ -n "${BLAKTAIL_TARGET:-}" ]; then
  target=$BLAKTAIL_TARGET
else
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) target=aarch64-apple-darwin ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    Linux:aarch64 | Linux:arm64) target=aarch64-unknown-linux-gnu ;;
    Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
    *) die "unsupported host; set BLAKTAIL_TARGET explicitly" ;;
  esac
fi

case "$target" in
  aarch64-apple-darwin | x86_64-apple-darwin)
    os=macos
    ;;
  aarch64-unknown-linux-gnu)
    os=linux
    deb_arch=arm64
    rpm_arch=aarch64
    ;;
  x86_64-unknown-linux-gnu)
    os=linux
    deb_arch=amd64
    rpm_arch=x86_64
    ;;
  *) die "unsupported target triple: $target" ;;
esac

case "$format:$os" in
  pkg:macos | deb:linux | rpm:linux) ;;
  *) die "$format packages cannot contain a $target binary" ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/blaktail-package.XXXXXX")
cleanup() {
  if [ -n "${work:-}" ] && [ -d "$work" ]; then
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT HUP INT TERM

asset="$output_dir/blaktaild-$target.$format"
[ ! -e "$asset" ] || die "output already exists: $asset"

package_pkg() {
  command -v pkgbuild >/dev/null 2>&1 || die "pkgbuild is required for pkg output"
  case "${BLAKTAIL_APPLICATION_IDENTITY:+set}:${BLAKTAIL_INSTALLER_IDENTITY:+set}" in
    :) ;;
    set:set) ;;
    *) die "public pkg signing requires both application and installer identities" ;;
  esac
  root="$work/root"
  install -d "$root/usr/local/bin" "$root/Library/LaunchDaemons"
  install -m 0755 "$binary" "$root/usr/local/bin/blaktaild"
  install -m 0755 "$config_binary" "$root/usr/local/bin/blaktail-config"
  install -m 0644 "$repo_root/packaging/macos/com.blaktail.agent.plist" \
    "$root/Library/LaunchDaemons/com.blaktail.agent.plist"
  if [ -n "${BLAKTAIL_APPLICATION_IDENTITY:-}" ]; then
    codesign --force --options runtime --timestamp \
      --sign "$BLAKTAIL_APPLICATION_IDENTITY" \
      "$root/usr/local/bin/blaktaild"
    codesign --force --options runtime --timestamp \
      --sign "$BLAKTAIL_APPLICATION_IDENTITY" \
      "$root/usr/local/bin/blaktail-config"
    codesign --verify --strict --verbose=2 "$root/usr/local/bin/blaktaild"
    codesign --verify --strict --verbose=2 "$root/usr/local/bin/blaktail-config"
  fi
  if command -v xattr >/dev/null 2>&1; then
    xattr -cr "$root"
  fi

  if [ -n "${BLAKTAIL_INSTALLER_IDENTITY:-}" ]; then
    COPYFILE_DISABLE=1 pkgbuild --root "$root" --ownership recommended \
      --identifier org.blaktail.agent --version "$version" \
      --install-location / --sign "$BLAKTAIL_INSTALLER_IDENTITY" "$asset" >&2
  else
    COPYFILE_DISABLE=1 pkgbuild --root "$root" --ownership recommended \
      --identifier org.blaktail.agent --version "$version" \
      --install-location / "$asset" >&2
  fi
}

package_deb() {
  command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb is required for deb output"
  root="$work/root"
  install -d "$root/DEBIAN" "$root/usr/local/bin" \
    "$root/usr/lib/systemd/system" "$root/usr/share/doc/blaktaild"
  install -m 0755 "$binary" "$root/usr/local/bin/blaktaild"
  install -m 0755 "$config_binary" "$root/usr/local/bin/blaktail-config"
  install -m 0644 "$repo_root/packaging/systemd/blaktaild.service" \
    "$root/usr/lib/systemd/system/blaktaild.service"
  install -m 0644 "$repo_root/docs/linux-agent.md" \
    "$root/usr/share/doc/blaktaild/README.md"
  cat >"$root/DEBIAN/control" <<EOF
Package: blaktaild
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: BlakTail maintainers <noreply@users.noreply.github.com>
Depends: iproute2, wireguard-tools, iptables, procps
Recommends: conntrack
Homepage: https://github.com/jusso-dev/BlakTail
Description: Self-hosted BlakTail WireGuard node agent
 BlakTail joins Linux nodes to an organisation-controlled WireGuard tailnet.
EOF
  cat >"$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
EOF
  chmod 0755 "$root/DEBIAN/postinst"
  dpkg-deb --root-owner-group --build "$root" "$asset" >&2
}

package_rpm() {
  command -v rpmbuild >/dev/null 2>&1 || die "rpmbuild is required for rpm output"
  top="$work/rpmbuild"
  install -d "$top/BUILD" "$top/BUILDROOT" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS"
  install -m 0755 "$binary" "$top/SOURCES/blaktaild"
  install -m 0755 "$config_binary" "$top/SOURCES/blaktail-config"
  install -m 0644 "$repo_root/packaging/systemd/blaktaild.service" \
    "$top/SOURCES/blaktaild.service"
  install -m 0644 "$repo_root/docs/linux-agent.md" "$top/SOURCES/README.md"
  rpm_version=$(printf '%s' "$version" | tr '-' '~')
  cat >"$top/SPECS/blaktaild.spec" <<EOF
Name: blaktaild
Version: $rpm_version
Release: 1%{?dist}
Summary: Self-hosted BlakTail WireGuard node agent
License: Apache-2.0
URL: https://github.com/jusso-dev/BlakTail
BuildArch: $rpm_arch
Requires: iproute
Requires: wireguard-tools
Requires: iptables
Requires: procps-ng
Recommends: conntrack-tools
Source0: blaktaild
Source1: blaktaild.service
Source2: README.md
Source3: blaktail-config

%description
BlakTail joins Linux nodes to an organisation-controlled WireGuard tailnet.

%prep

%build

%install
install -D -m 0755 %{SOURCE0} %{buildroot}/usr/local/bin/blaktaild
install -D -m 0755 %{SOURCE3} %{buildroot}/usr/local/bin/blaktail-config
install -D -m 0644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/blaktaild.service
install -D -m 0644 %{SOURCE2} %{buildroot}/usr/share/doc/blaktaild/README.md

%post
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :

%postun
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :

%files
/usr/local/bin/blaktaild
/usr/local/bin/blaktail-config
/usr/lib/systemd/system/blaktaild.service
/usr/share/doc/blaktaild/README.md

%changelog
* Thu Jan 01 1970 BlakTail maintainers <noreply@users.noreply.github.com> - $rpm_version-1
- Automated release package.
EOF
  rpmbuild --define "_topdir $top" --define "_build_id_links none" \
    --target "$rpm_arch" -bb "$top/SPECS/blaktaild.spec" >&2
  set -- "$top/RPMS/$rpm_arch/"*.rpm
  [ "$#" -eq 1 ] && [ -f "$1" ] || die "rpmbuild did not produce exactly one package"
  cp "$1" "$asset"
}

case "$format" in
  pkg) package_pkg ;;
  deb) package_deb ;;
  rpm) package_rpm ;;
esac

printf '%s\n' "$asset"
