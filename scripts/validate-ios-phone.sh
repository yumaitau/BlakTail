#!/usr/bin/env bash
# Structural checks for the iPhone client. Runs on Linux CI hosts too.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MISSION="Built by Indigenous Australians for Indigenous Australian organisations. Data stays onshore, Indigenous Australian organisations stay in control, and the code stays public."

fail() { echo "validate-ios-phone: $*" >&2; exit 1; }

test -f apps/ios/Package.swift || fail "missing Package.swift"
test -f apps/ios/App/BlakTailPhoneApp.swift || fail "missing BlakTailPhoneApp"
test -f apps/ios/Sources/BlakTailPhone/Views/RootView.swift || fail "missing RootView"
test -f apps/ios/Sources/BlakTailPhone/Views/NetworkListView.swift || fail "missing network list"
test -f apps/ios/Sources/BlakTailPhone/Views/EndpointDetailView.swift || fail "missing endpoint detail"
test -f apps/ios/Sources/BlakTailPhone/Views/SettingsView.swift || fail "missing Settings"
test -f apps/ios/Sources/BlakTailPhone/Views/ThisPhoneView.swift || fail "missing This iPhone view"
test -f apps/ios/Sources/BlakTailPhone/PhoneModel+Client.swift || fail "missing phone join client"
test -f apps/ios/Tunnel/PacketTunnelProvider.swift || fail "missing packet tunnel provider"
test -f apps/ios/Tunnel/BlakTailTunnel.entitlements || fail "missing tunnel entitlements"
test -f apps/ios/App/BlakTailPhone.entitlements || fail "missing app entitlements"
test -f blaktail-ios-wg/src/lib.rs || fail "missing iPhone WireGuard dataplane"
test -f apps/macos/Sources/BlakTailCore/Agent/CoordinatorClient.swift || fail "missing coordinator client"
test -f apps/ios/Resources/Info.plist || fail "missing Info.plist"
test -f docs/ios.md || fail "missing iOS docs"
test -f apps/macos/Sources/BlakTailCore/Auth/KeychainStore.swift || fail "missing shared KeychainStore"
test -f apps/macos/Sources/BlakTailCore/Auth/BrowserSignIn.swift || fail "missing shared BrowserSignIn"
test -f apps/console/src/app/desktop/auth/page.tsx || fail "missing desktop auth page"

grep -Fq "This iPhone" apps/ios/Sources/BlakTailPhone/Views/RootView.swift \
  || fail "iPhone root must include the This iPhone tab"
grep -Fq "NEPacketTunnelProvider" apps/ios/Tunnel/PacketTunnelProvider.swift \
  || fail "tunnel must be a Network Extension packet tunnel"
grep -Fq "group.au.org.blaktail.ios" apps/ios/App/BlakTailPhone.entitlements \
  || fail "app must declare the iPhone app group"
grep -Fq "group.au.org.blaktail.ios" apps/ios/Widget/BlakTailWidget.entitlements \
  || fail "widget must share the iPhone app group"
grep -Fq "com.apple.widgetkit-extension" apps/ios/Widget/Info.plist \
  || fail "widget must be a WidgetKit extension"
grep -Fq "SetTunnelIntent" apps/ios/Widget/BlakTailWidgets.swift \
  || fail "widget must toggle the existing packet tunnel"
grep -Fq "BlakTailWidget" apps/android/app/src/main/AndroidManifest.xml \
  || fail "Android home-screen widget must be registered"
grep -Fq "au.org.blaktail.ios.tunnel" apps/ios/Tunnel/Info.plist \
  || fail "tunnel bundle identifier must be au.org.blaktail.ios.tunnel"
grep -Fq "TabView" apps/ios/Sources/BlakTailPhone/Views/RootView.swift \
  || fail "iPhone root must use a native tab bar"
grep -Fq "NavigationStack" apps/ios/Sources/BlakTailPhone/Views/RootView.swift \
  || fail "iPhone root must use NavigationStack"
grep -Fq ".searchable" apps/ios/Sources/BlakTailPhone/Views/NetworkListView.swift \
  || fail "network list must provide native search"
grep -Fq "ContentUnavailableView" apps/ios/Sources/BlakTailPhone/Views/NetworkListView.swift \
  || fail "empty and signed-out states must use ContentUnavailableView"
grep -Fq "confirmationDialog" apps/ios/Sources/BlakTailPhone/Views/SettingsView.swift \
  || fail "sign out must use a confirmation dialog"
grep -Fq "Revoke endpoint" apps/ios/Sources/BlakTailPhone/Views/EndpointDetailView.swift \
  || fail "endpoint detail must offer a destructive revoke action"
grep -Fq "au.org.blaktail.ios" apps/ios/Resources/Info.plist \
  || fail "Info.plist must use the iPhone bundle identifier"
grep -Fq "blaktail" apps/ios/Resources/Info.plist \
  || fail "Info.plist must register the blaktail URL scheme"
grep -Fq "phoneSession" apps/macos/Sources/BlakTailCore/Auth/KeychainStore.swift \
  || fail "shared Keychain must expose the iPhone service"
grep -Fq "organisation" apps/ios/Sources/BlakTailPhone/Views/NetworkListView.swift \
  || fail "UI should use Australian English 'organisation'"

grep -Fq "$MISSION" apps/macos/Sources/BlakTailCore/Support/Tagline.swift \
  || fail "Tagline.swift does not contain the shared project mission"
grep -Fq "$MISSION" docs/ios.md \
  || fail "iOS docs must quote the shared project mission"
grep -Fq "$MISSION" README.md \
  || fail "README must keep the shared project mission"

grep -Fq "iOS 17" docs/ios.md \
  || fail "docs must state minimum iOS 17"
grep -Fq "NEPacketTunnelProvider" docs/ios.md \
  || fail "docs must describe the Network Extension tunnel"
grep -Fq "do not" docs/ios.md \
  || fail "docs must say CI must not buy certificates"
grep -Fq "macos-latest" .github/workflows/ios-phone.yml \
  || fail "iPhone workflow must run Swift tests on macos-latest"
grep -Fq "swift test" .github/workflows/ios-phone.yml \
  || fail "iPhone workflow must run swift test"
grep -Fq "blaktail-ios-wg" .github/workflows/ios-phone.yml \
  || fail "iPhone workflow must test the boringtun crate"

if grep -R --include='*.swift' -n -- '--join-key' apps/ios/Sources apps/ios/App apps/ios/Tunnel; then
  fail "iPhone sources must not pass --join-key"
fi
if grep -R --include='*.swift' -n 'BLAKTAIL_JOIN_KEY' apps/ios/Sources apps/ios/App apps/ios/Tunnel; then
  fail "iPhone sources must not set BLAKTAIL_JOIN_KEY"
fi

echo "validate-ios-phone: ok"
