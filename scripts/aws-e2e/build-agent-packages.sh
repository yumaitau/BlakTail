#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

validate_base_inputs
for command_name in docker git tar; do
  require_command "$command_name"
done
[ ! -e "$PACKAGE_DIR" ] || die "package output already exists: $PACKAGE_DIR"

require_arm64_builder

build_context=$(prepare_git_context)
cleanup() {
  case "$build_context" in
    "$WORK_DIR"/build-context.*) rm -rf -- "$build_context" ;;
    *) die "refusing unsafe build-context cleanup" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$PACKAGE_DIR"
docker --context "$DOCKER_CONTEXT" buildx build \
  --platform linux/arm64 --target export --provenance=false --sbom=false \
  --output type=local,dest="$PACKAGE_DIR" \
  --file "$build_context/deploy/docker/agent-package.Dockerfile" "$build_context"

[ -f "$PACKAGE_DIR/blaktaild-aarch64-unknown-linux-gnu.deb" ] || die "ARM64 deb missing"
[ -f "$PACKAGE_DIR/blaktaild-aarch64-unknown-linux-gnu.rpm" ] || die "ARM64 rpm missing"
[ -f "$PACKAGE_DIR/SHA256SUMS" ] || die "package checksums missing"
printf 'ARM64 agent packages ready: %s\n' "$PACKAGE_DIR"

