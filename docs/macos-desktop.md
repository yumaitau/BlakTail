# macOS desktop app

Native SwiftUI menu bar app and endpoint manager. It signs in through the onshore
console (Better Auth), stores its own desktop credential in Keychain, shows every machine
across every authorised network workspace, and starts or stops local `blaktaild`
without using the terminal.

**Choice:** native SwiftUI (not Tauri). The Mac agent is already a LaunchDaemon
(`com.blaktail.agent`); a Swift shell talks to it with `launchctl` and the `blaktaild`
CLI.

**Minimum macOS:** macOS 14 Sonoma (`LSMinimumSystemVersion` / Package.swift `macOS(.v14)`).

## Layout

| Path | Role |
| --- | --- |
| `apps/macos/Sources/BlakTailCore` | Auth, Keychain, agent driver, tagline |
| `apps/macos/Sources/BlakTail` | Menu bar, endpoint manager, local connection, and Settings |
| `apps/console/src/app/desktop` | Browser sign-in page for ASWebAuthenticationSession |
| `apps/console/src/app/api/desktop` | Session, selected-network join key, inventory, rename, route, and revoke APIs |
| `apps/console/src/lib/desktop-auth.ts` | PKCE codes, desktop credentials (Bearer) → console context |

Console bridge files merge with the Next.js console from the Better Auth work. They call the
same onshore coordinator; no offshore IdP.

## Build (on a Mac)

```sh
cd apps/macos
swift test
swift build -c release
```

To produce a signed `.app` for distribution, open the package in Xcode (or create an App
target that links `BlakTailCore`), set the bundle ID to `au.org.blaktail.desktop`, and use
`Resources/Info.plist` so the `blaktail://` URL scheme is registered. `LSUIElement` keeps
the app menu-bar-first.

## Endpoint manager

The main window follows [Apple's Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/)
and uses system SwiftUI controls:

- a resizable `NavigationSplitView` with **This Mac**, **All networks**, and each
  authorised workspace in the sidebar;
- native search across friendly name, technical name, MagicDNS name, addresses,
  tags, and network name;
- credential state communicated with a symbol and text, never colour alone;
- endpoint detail with selectable technical identity, copy controls, credential
  dates, and the owning network always visible;
- friendly-name editing that leaves the technical and MagicDNS identities stable;
- route approval for advertised subnet and exit-node routes;
- a destructive confirmation before audited endpoint revocation;
- a native Settings scene available with Command-Comma, plus standard sidebar,
  refresh, connect, and disconnect keyboard commands;
- keyboard navigation, VoiceOver labels, semantic system colours, system text,
  and no decorative motion.

The desktop inventory API aggregates the same organisation memberships as the
console's **All networks** page. Every returned endpoint carries its organisation
ID, organisation name, and mutation permission. Mutation requests must send that
organisation ID in `X-BlakTail-Organisation`; the server resolves membership again
and refuses cross-network or member-only changes.

When a person links another login in the web console, the Mac app keeps the same
desktop credential and the next refresh includes the linked identity's network
accounts and endpoints. The local Mac still has one active data-plane enrolment;
the endpoint manager can inspect and administer every authorised network at once.

## Sign in and connect

1. Set the onshore console URL in Settings (Australian-hosted HTTPS only).
2. **Sign in…** opens ASWebAuthenticationSession against `/desktop/auth` with a
   random `state` and a PKCE S256 `code_challenge` (see [Desktop and mobile sign-in](console.md#desktop-and-mobile-sign-in)).
3. After sign-in, the person presses **Allow**. The console redirects to
   `blaktail://auth/callback?code=…&state=…`; the app checks `state` and swaps the
   code and its verifier for a desktop credential (`btd_…`, not the browser session).
   It is stored in Keychain (`au.org.blaktail.desktop` / `better-auth.session_token`,
   the account name kept for compatibility).
4. Choose which authorised network this Mac should join. The choice is explicit
   and does not hide machines from the other workspaces.
5. **Connect** asks the selected network to mint a short-lived join key, then runs
   `blaktaild up` with the key on **stdin only** (never `--join-key`, never process env that
   persists). The LaunchDaemon is bootstrapped afterward.
6. Status shows connection state, device name, BlakTail address, network, and actionable errors.
7. **Disconnect** boots out the daemon and runs `blaktaild pause`. The encrypted
   interface stops, but enrolment remains for a later **Connect**. It does not
   revoke the endpoint. Revocation stays behind the explicit, confirmed endpoint action.
8. **Quit** clears transient UI state. It does not leave the join key in argv, environment,
   or UserDefaults. The desktop credential may remain in Keychain until **Sign out**,
   which revokes it on the console and deletes the Keychain item.

About BlakTail shows the shared project mission:

> Built by Indigenous Australians for Indigenous Australian organisations. Data stays onshore, Indigenous Australian organisations stay in control, and the code stays public.

## Australian English

UI copy uses Australian English (organisation, cancelled, unauthorised, notarisation).

## Notarisation (do not buy certificates in CI)

Developer ID Application signing and Apple notarisation are **manual operator steps**, not
CI jobs. CI must not purchase, renew, or upload payment-backed signing
certificates.

Suggested local release flow on a Mac with your organisation’s Developer ID:

```sh
# After building BlakTail.app
codesign --force --options runtime --sign "Developer ID Application: YOUR ORG" BlakTail.app
ditto -c -k --keepParent BlakTail.app BlakTail.zip
xcrun notarytool submit BlakTail.zip --keychain-profile "notary" --wait
xcrun stapler staple BlakTail.app
```

Store Notary credentials in the local Keychain profile (`notarytool store-credentials`), not
in the git repository. GitHub Actions for this repo run on hosted runners (`ubuntu-latest`, `macos-latest`)
runners and only build or test; they do not buy certs.

## Manual validation

On a current Mac (14+), with `blaktaild` installed and an onshore console + coordinator:

1. Launch BlakTail from the menu bar.
2. Sign in, then confirm **All networks** contains endpoints from every membership
   without changing accounts or ending the session.
3. Search by friendly name, technical name, MagicDNS name, address, tag, and network.
4. Rename an endpoint, reload, and confirm the friendly name persists while its
   technical and MagicDNS names do not change.
5. As a member, confirm endpoint controls are read-only. As an owner or admin,
   approve an advertised route and verify the owning network remains visible.
6. Start a revoke, confirm a destructive warning appears, then cancel before
   repeating against a disposable endpoint.
7. Choose a network for this Mac and connect; confirm status shows Connected and
   a BlakTail address. Ping a peer on the private path.
8. Test keyboard-only navigation and VoiceOver for the sidebar, endpoint rows,
   copy controls, connection action, and revoke confirmation.
9. Disconnect; confirm status returns to Disconnected, the endpoint remains active
   in its network, and local state still contains the same node ID. Connect again
   without minting or supplying another join key.
10. Quit. Confirm Activity Monitor or `ps` shows no child command line containing the join key.

## CI

`.github/workflows/macos-desktop.yml` runs `swift test` on `macos-latest`. `scripts/validate-macos-desktop.sh` checks structure and the locked
tagline on any host.
