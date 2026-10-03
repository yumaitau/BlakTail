# Threat model

Built by Indigenous Australians for Indigenous Australian organisations. Data stays onshore, Indigenous Australian organisations stay in control, and the code stays public.

That mission is a product constraint. This document says what we protect, what we do not, and what an operator does when something goes wrong. It is not an IRAP package and does not claim one.

BlakTail is a WireGuard mesh. Devices join an organisation tailnet, talk peer to peer, and fall back through a relay the organisation runs. The organisation holds the keys. The coordination server and relays stay in Australia. The code is public; the secrets are not.

## What we protect

| Asset | Where it lives | If it leaks |
| --- | --- | --- |
| Node WireGuard private key | `/var/lib/blaktail/private.key` on the device, mode `0600` | Attacker impersonates that node on the tailnet until revoke |
| Node token (`btn_…`) | `/var/lib/blaktail/state.json`, mode `0600` | Attacker polls peers and self-revokes; does not yield the WG private key by itself |
| Join key (`btk_…`) | Shown once at mint; optional `/etc/blaktail/blaktaild.env` | Attacker enrols a new node, with that key's tags and role, until the key is used, expired, or revoked |
| Coordinator database | Org host (`blaktail-coord.sqlite3` or `BLAKTAIL_DATABASE`) | Peer graph, public keys, endpoints, ACL, hashed join keys and tokens, MagicDNS names |
| ACL | Coordinator DB; edited in the console | Who may reach whom. Default is deny across device tags |
| Relay mapping | In-memory on the AU relay | Node id to UDP address, timing, and packet sizes |
| Reflexive candidates | Coordinator node records, expiring after 180 seconds | Node id to recently observed relay-socket address |
| Node credential expiry | Coordinator node records | Default 90-day control-plane and peer-map lifetime; re-auth rotates the token |
| Relay capability secret | Coordinator and relay env only | Attacker can register or hijack relay identities; it is separate from console-session signing |
| Console sessions and `BETTER_AUTH_SECRET` | Onshore Postgres and console env | Account takeover of the operator UI |
| `BLAKTAIL_AUTH_HMAC_SECRET` | Console and coordinator env | Forgery of console sessions into the coordinator |
| Bootstrap/invitation credentials | Shown once to operator/invitee; SHA-256 hashes in Postgres | First-owner or invited-role takeover before expiry/use |
| TLS private key | Coordinator host | Intercept of control-plane HTTP |

The coordinator stores hashes of join keys and node tokens, not the secrets themselves. It never stores user file contents. Shared-folder configuration is metadata only: label, absolute path, port, and enabled flag. File bytes stay on the publishing node and move only over the WireGuard overlay. WireGuard payload ciphertext is not a coordinator asset.
Browser enrollment follows the same rule: SQLite stores hashes of the high-entropy
device secret and the short display code. Approval creates a single-use grant bound
to the waiting node name and WireGuard public key; the raw secret stays in the agent.

## Trust boundaries

```
[operator laptop] --HTTPS--> [console, onshore Postgres]
                                  |
                                  | session + sync secret
                                  v
[node /var/lib/blaktail] --HTTPS--> [blaktail-coord in Australia]
        |                                    |
        | WireGuard (usually direct)         | peer list, public keys, ACL
        v                                    v
   [peer node] <---- UDP fallback ---- [blaktail-relay in Australia]
```

- Nodes treat the coordinator as the source of truth for membership and ACL.
- Relays are organisation infrastructure. They forward opaque UDP. They are not a second control plane.
- GitHub holds public code. It must not hold keys, env files, or the coordinator database.
- CI runs on GitHub-hosted runners (`ubuntu-latest`, `macos-latest`). The tree is never uploaded to a scanning SaaS; gitleaks and cargo-deny run as checksum-pinned binaries inside the workflow.

## Attackers we actually design for

### Stolen or unattended laptop

The node private key and node token sit in ordinary files. Mode `0600` stops other Unix users on a locked-down host. It does nothing once an attacker is in the logged-in session, or once they image an unencrypted disk.

Assume compromise of that node. Revoke it from a different, trusted admin machine. Do not wait to recover the laptop. After revoke, remaining peers drop the public key on their next poll (30 seconds by default, within 60 seconds if the coordinator is reachable).

### Leaked join key

A join key is a capability. Anyone who has a still-valid key can register a node with the tags and role bound to that key. Single-use and short expiry shrink the window; they do not shrink it to zero. A time-boxed reusable key is worse.

Treat a leaked unused key as: revoke that key (or every unused key for the org), then look at `nodes` created after the leak and revoke anything you did not enrol yourself.

### Curious relay operator

The relay does not decrypt WireGuard payloads and must not log them. It still sees UDP 5-tuples, 16-byte node ids, packet sizes, and timing. A person with shell on the relay host can watch who talks to whom. Registration requires a coordinator-minted, expiring HMAC capability; treat the relay as trusted org kit on an Australian network, not as an anonymity service.

### Offshore SaaS mistake

Typical ways to break the onshore rule without dropping a key in Slack:

- Coordinator or relay in `us-east-1`, `ap-southeast-1` (Singapore), or any non-AU region
- GitHub-hosted Actions runners
- Console on Vercel, Netlify, or another offshore app host
- Error, analytics, or font CDNs outside Australia
- Secret scanning SaaS that uploads the repository
- `cargo deny` / gitleaks run somewhere that ships the tree off the runner

The shared schema refuses coordinator, relay, and console startup unless
`BLAKTAIL_REGION` is an approved Australian cloud region (`ap-southeast-2`,
`australiaeast`, `australiasoutheast`, `australia-southeast1`, or
`australia-southeast2`). Public health responses contain status only and never
echo the configured region. Deployment policy still pins AWS stacks to Sydney.
Optional MDM/EDR posture integrations are a deliberate, owner-approved
exception: the coordinator calls the vendor's cloud, which may be offshore,
and the console says so before the first call.

### MDM/EDR integration abuse

Posture integrations (Intune, CrowdStrike Falcon, SentinelOne, FleetDM,
Huntress) add a credential and an outbound call per organisation:

- **Credential theft or exfiltration.** Secrets are sealed with a key derived
  from the coordinator secret, write-only through the API, absent from audit
  details, errors and logs (provider errors are reduced to fixed
  categories). Changing an integration's endpoint requires re-entering the
  secret, so an owner session cannot redirect a stored credential. Only
  owners can create, rotate, test or remove integrations. Ask vendors for
  read-only scopes only.
- **SSRF through provider URLs.** Fixed vendor hosts for Intune,
  CrowdStrike (region list) and Huntress; SentinelOne must be
  `*.sentinelone.net`; FleetDM must be a public HTTPS address. Every call
  goes through the webhook address policy (no private, loopback, link-local
  or metadata addresses), is pinned to the checked IP, follows no
  redirects, and pagination links must stay on the same origin.
- **Forged device identity.** Serials and MACs are reported by the node
  token holder. Copying another device's serial makes both devices'
  matches ambiguous, which fails; it cannot transfer a passing signal. A
  stolen node token for a device that is itself compliant remains a risk,
  as with any device-bound credential.
- **Cross-organisation signals.** Matching loads only the checking
  organisation's integrations and devices; check creation rejects another
  organisation's integration id.
- **Provider outage.** Failures never change stored records. Stale data
  fails closed unless the check opts into fail-open for outages, which only
  keeps devices whose last known record was passing.

## Required controls

These are not optional hardening. They are the v1 bar.

1. **Region pin.** Relays must use the Australian allow-list above. Coordinators must have a non-empty region and should use the same allow-list. Health checks show the label so an operator can see drift.
2. **Key files are `0600`.** `blaktaild` writes `private.key` and `state.json` with mode `0600` under a `0700` state directory. It refuses to run if an existing private key is world- or group-readable. Put `/etc/blaktail/blaktaild.env` at `0600` as well, and delete `BLAKTAIL_JOIN_KEY` from it after the first successful join.
3. **Revoke path.** Owners and admins can revoke from the console, the node can self-revoke with `blaktaild down`, and the coordinator API plus SQLite remain available when the UI is not. Copy-paste steps are below. Members cannot mint keys, edit ACLs, or revoke devices.
4. **No payload logs on the relay.** The relay forwards bytes. It must not log WireGuard payloads, plaintext, or packet bodies. Startup may log region and bind address only. Coordinator logs may include node ids and org ids; they must not include join keys, node tokens, or private keys.
5. **MagicDNS is authoritative-only.** Each agent answers its current private peer map locally. Unknown `*.blaktail` names return `NXDOMAIN`; public names are refused rather than forwarded, so a tailnet label is never leaked by the BlakTail stub to an upstream resolver.
6. **Routes require two decisions.** A Linux node may request a subnet or exit
   route, but the coordinator distributes it only after owner/admin approval.
   Default routes remain opt-in per client. The agent limits forwarding to the
   advertised destinations, and the coordinator accepts only RFC1918 private
   subnets while rejecting tailnet overlap and ambiguous approved routes.
7. **Ownership starts on-host.** Public email/password sign-up is disabled. A
   protected shell creates one short-lived first-owner credential, coordinator
   organisation activation is staged until console identity is ready, and
   bootstrap locks after one success. Later users require owner-issued,
   organisation-bound invitations. Sole-owner recovery requires the exact owner
   email from a trusted host and revokes existing sessions.

## Honest limits

Say these out loud. Do not market around them.

**Metadata is visible.** WireGuard hides payload contents from the relay and from the network path. It does not hide that two devices exist, when they talk, how much they send, or which configured and reflexive endpoints the coordinator recorded. The coordinator database is a complete membership directory: names, tags, roles, MagicDNS names, public keys, allowed IPs, endpoints. Reflexive candidates age out of peer responses after 180 seconds, but the latest value remains in the database until replaced or the node is removed. Anyone with that database can map the org's tailnet. Anyone with relay access can add timing. BlakTail is not an anonymity network.

**Unlocked or unencrypted disk is game over for that node.** `0600` is not a substitute for full-disk encryption, a screen lock, or firmware passwords. If the laptop is stolen while unlocked, or the disk is imaged without encryption, the thief has the private key and the node token. Revoke immediately. Re-enrol the user on known-good hardware. We cannot remotely wipe a machine we no longer control.

Node credentials expire after the organisation's configured lifetime (90 days by
default). Expired nodes stop receiving peer maps and are removed from other nodes'
maps on their next poll. Re-authentication requires both the prior node secret and a
fresh join key, rotates the node token, and preserves the existing tailnet identity.
Routine re-authentication intentionally keeps the WireGuard key. It is not compromise
recovery: if the private key may have leaked, revoke the node and enrol a new one.

**Join-key theft enrols an attacker.** If they redeem the key before you revoke it, you now have a hostile node with whatever tags that key carried. Revoking the join key afterwards does not kick them off; you must revoke the node they created. Unused keys in chat logs, email, ticket systems, or shell history are live credentials.

**Revoke is not instant if the coordinator is down.** Peers keep the last applied WireGuard configuration when polling fails, so existing tunnels survive a coordinator outage. That is deliberate. It also means a revoke does not propagate until peers can reach the coordinator again.

**Overlay shares are unauthenticated HTTP and read-only WebDAV.** The listener
binds only the node's tailnet IPv4 address. Anyone who can already reach that
node over the overlay can list and read the published directory. There is no
share password. macOS still has no packet filter, so the bind is the control
there. Writable uploads are rejected.

**This is not IRAP.** Public code, org-held keys, and onshore hosting are the product. Formal accreditation is out of scope.

## Revoke

Do this from a trusted admin host, not from the stolen device.

Replace `COORD`, `ORG_ID`, `NODE_ID`, `JOIN_KEY`, and `CONSOLE_SESSION` with your values. `COORD` is an `https://` coordinator URL.

### 1. Console (preferred)

Sign in as owner or admin.

1. Open `/devices`.
2. Press **Revoke** on the compromised node.
3. Confirm the row shows **Revoked**.
4. Open `/join-keys` and press **Revoke** on every key that may have leaked, including reusable keys that still have uses left. Mint replacements only after that. If the device may come back (lost then found), **Suspend** on its detail page is reversible; Revoke is not.
5. Wait one poll interval (30 seconds, worst case 60) then `ping` a remaining node from another remaining node.

### 2. Node self-revoke (machine you still control)

```sh
sudo blaktaild down
```

That calls `DELETE /v1/nodes/{node_id}` with the persisted node token, removes `blaktail0`, and deletes `state.json`. It does not delete `private.key`; remove that yourself if the device is being retired.

### 3. Coordinator API

Owner or admin session, after the console has synced it:

```sh
curl -sS -o /tmp/blaktail-revoke-http -w "%{http_code}\n" -X DELETE \
  -H "Authorization: Bearer ${CONSOLE_SESSION}" \
  "${COORD}/v1/orgs/${ORG_ID}/nodes/${NODE_ID}"
```

`204` means the node is revoked. `403` means the session is a member. `404` means the id is wrong or already revoked.

List, then confirm `revoked` is true:

```sh
curl -sS -H "Authorization: Bearer ${CONSOLE_SESSION}" \
  "${COORD}/v1/orgs/${ORG_ID}/nodes"
```

### 4. SQLite emergency (coordinator host)

On the coordinator box. Default DB path is `blaktail-coord.sqlite3` unless you set `BLAKTAIL_DATABASE`.

Revoke one node:

```sh
sqlite3 "${BLAKTAIL_DATABASE:-blaktail-coord.sqlite3}" \
  "UPDATE nodes SET revoked_at=strftime('%s','now') WHERE id='${NODE_ID}' AND revoked_at IS NULL;"
```

Revoke every live join key for the org (leaked key, not sure which one; reusable keys stay live after their first use):

```sh
sqlite3 "${BLAKTAIL_DATABASE:-blaktail-coord.sqlite3}" \
  "UPDATE join_keys SET revoked_at=strftime('%s','now')
     WHERE org_id='${ORG_ID}' AND revoked_at IS NULL;"
```

Revoke one known leaked join key (SHA-256 of the secret string, including the `btk_` prefix):

```sh
JOIN_HASH="$(printf '%s' "${JOIN_KEY}" | sha256sum | awk '{print $1}')"
sqlite3 "${BLAKTAIL_DATABASE:-blaktail-coord.sqlite3}" \
  "UPDATE join_keys SET revoked_at=strftime('%s','now')
     WHERE key_hash='${JOIN_HASH}' AND revoked_at IS NULL;"
```

Nodes created with a stolen key stay active until you revoke those rows too:

```sh
sqlite3 "${BLAKTAIL_DATABASE:-blaktail-coord.sqlite3}" \
  "SELECT id,name,created_at FROM nodes WHERE org_id='${ORG_ID}' AND revoked_at IS NULL ORDER BY created_at;"
```

### 5. After revoke

On the compromised device, if you get it back, do not rejoin until it is rebuilt:

```sh
sudo ip link delete dev blaktail0 || true
sudo rm -f /var/lib/blaktail/private.key /var/lib/blaktail/state.json
sudo shred -u /etc/blaktail/blaktaild.env 2>/dev/null || sudo rm -f /etc/blaktail/blaktaild.env
```

Mint a new single-use join key with a short expiry (an hour, not a month). Enrol only the replacement device. Rotate `BLAKTAIL_AUTH_HMAC_SECRET` and `BETTER_AUTH_SECRET` if those files were on the same laptop.

## What never goes in git

The public repository is the product. Keys are not.

Never commit:

- Node private keys, TLS private keys, WireGuard PSKs, `*.key`, `*.pem`, `*.psk`
- Join keys, node tokens, or any `btk_` / `btn_` secret
- Coordinator SQLite/Postgres dumps
- `.env`, `/etc/blaktail/blaktaild.env`, `BETTER_AUTH_SECRET`, `BLAKTAIL_AUTH_HMAC_SECRET`, database URLs
- `wg*.conf` and other live WireGuard configs
- Real `BLAKTAIL_TLS_KEY` material

`.gitignore` already excludes the filename patterns. CI runs gitleaks on every push, including custom rules for `btk_` and `btn_` prefixes. That is a backstop, not a licence to paste a key into a test branch that will be merged.

If a secret does land in git: treat it as leaked, rotate it, rewrite or abandon the branch, and keep the dummy-secret proof in CI (it exists so a throwaway branch with `AKIA`/`btk_` material fails). Do not "fix" a leak by deleting the file in a follow-up commit and leaving the blob in history.

## CI

GitHub-hosted runners. The security workflow must not upload the tree to a scanning SaaS; scanners are pinned binaries fetched with verified checksums.

| Check | Job |
| --- | --- |
| gitleaks against this revision | `.github/workflows/security.yml` job `gitleaks` |
| Throwaway branch with a dummy secret must fail gitleaks | `scripts/ci/prove-gitleaks-detects-dummy.sh` |
| `cargo deny` advisories, licences, bans, sources | job `cargo-deny`, policy in `deny.toml` |

Reproduce locally:

```sh
scripts/ci/install-security-tools.sh
scripts/ci/gitleaks-scan.sh
scripts/ci/prove-gitleaks-detects-dummy.sh
scripts/ci/cargo-deny-check.sh
```

The dummy-secret script builds a disposable git repo, commits a constructed AWS example access key and a constructed `btk_` join key, and requires gitleaks to exit non-zero. Those values are assembled at runtime so this repository itself stays clean.
