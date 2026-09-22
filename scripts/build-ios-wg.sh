#!/usr/bin/env bash
# Cross-compile blaktail-ios-wg for the current Xcode platform.
# Usage: build-ios-wg.sh <iphoneos|iphonesimulator> <archs> <output-dir>
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLATFORM_NAME="${1:-}"
ARCHS="${2:-arm64}"
OUTPUT="${3:-"${ROOT}/target/ios-wg"}"

fail() { echo "build-ios-wg: $*" >&2; exit 1; }

command -v cargo >/dev/null || fail "cargo is required to build the iPhone WireGuard dataplane"
command -v rustup >/dev/null || fail "rustup is required to install Apple targets"

case "${PLATFORM_NAME}" in
  iphoneos) ;;
  iphonesimulator) ;;
  *) fail "platform must be iphoneos or iphonesimulator (got '${PLATFORM_NAME}')" ;;
esac

mkdir -p "${OUTPUT}"
libs=()
for arch in ${ARCHS}; do
  case "${PLATFORM_NAME}:${arch}" in
    iphoneos:arm64) rust_target="aarch64-apple-ios" ;;
    iphonesimulator:arm64) rust_target="aarch64-apple-ios-sim" ;;
    iphonesimulator:x86_64) rust_target="x86_64-apple-ios" ;;
    *) fail "unsupported platform/arch ${PLATFORM_NAME}/${arch}" ;;
  esac
  # Xcode exports SDKROOT as the iPhone SDK. Rust then looks for std inside that SDK.
  (
    unset SDKROOT
    unset IPHONEOS_DEPLOYMENT_TARGET
    rustup target add "${rust_target}" >/dev/null
    cargo build --manifest-path "${ROOT}/Cargo.toml" -p blaktail-ios-wg --release --target "${rust_target}"
  )
  libs+=("${ROOT}/target/${rust_target}/release/libblaktail_ios_wg.a")
done

if [ "${#libs[@]}" -eq 1 ]; then
  cp "${libs[0]}" "${OUTPUT}/libblaktail_ios_wg.a"
else
  command -v lipo >/dev/null || fail "lipo is required for a universal iOS WireGuard library"
  lipo -create "${libs[@]}" -output "${OUTPUT}/libblaktail_ios_wg.a"
fi

cp "${ROOT}/blaktail-ios-wg/include/blaktail_ios_wg.h" "${OUTPUT}/blaktail_ios_wg.h"
echo "build-ios-wg: wrote ${OUTPUT}/libblaktail_ios_wg.a"
