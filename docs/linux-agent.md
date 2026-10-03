# Linux node agent

`blaktaild` requires Linux, `iproute2`, `wireguard-tools`, `iptables`, `sysctl`, and `CAP_NET_ADMIN` (normally run as root). It first creates a kernel WireGuard interface. If the kernel does not support WireGuard, it tries the Rust `boringtun` binary as a userspace fallback.

No agent release is published yet. Build from source, or after a tagged release use
the checksum-verifying `.deb`/`.rpm` flow in [releases.md](releases.md). Packages
install `blaktaild`, the shared `blaktail-config` operator CLI, and the systemd
unit, but do not enrol or enable the service.

```sh
sudo install -d -m 0700 /var/lib/blaktail
blaktail-config check-config --service agent
# Laptop Compose stack from scripts/quickstart.sh:
sudo blaktaild up --coord https://127.0.0.1:8443 --coord-ca certs/ca.crt
# Deployed coordinator:
sudo blaktaild up --coord https://coord.example.org \
  --endpoint 203.0.113.10:51820
sudo blaktaild status
sudo blaktaild status --json   # one JSON object for local tools; no credentials
sudo blaktaild pause  # reversible; keeps enrolment
sudo blaktaild down
```

On a fresh node, `up` prints a ten-minute console URL and waits. Open that URL on
any browser, sign in, confirm the displayed name and WireGuard-key fingerprint,
then approve the node. This works unchanged over SSH and never requires copying a
join key. Automation may set `BLAKTAIL_JOIN_KEY` or pipe the key on stdin. There is
no `--join-key` argument: secrets never go in argv, where process listings and
shell history would expose them.

The coordinator URL must use HTTPS except for localhost testing. The private key and credential-bearing state are stored under `/var/lib/blaktail` with mode `0600`; they are never logged. `up` polls every 30 seconds. A polling failure leaves the last applied WireGuard peer configuration untouched, so live tunnels continue while the coordinator is unavailable.

The coordinator assigns both an IPv4 `/32` and an organisation-scoped ULA IPv6
`/128`. The agent applies both addresses and both peer host routes. An upgraded
agent also adds a missing IPv6 address returned by the coordinator to an existing
enrollment without changing its IPv4 address.

The agent sets the tunnel MTU to 1280. It starts with each peer's configured UDP
endpoint, moves an unresponsive peer to the advertised Australian relay within one
poll interval, and keeps WireGuard ciphertext flowing there while attempting a
nonce-confirmed UDP hole punch. Successful peer-to-peer traffic bypasses the relay;
stale direct handshakes fall back automatically. The relay socket's reflexive address
is refreshed through the coordinator, so port forwarding is not required for the
relay path.

The 1280-byte inner IPv6 packet plus 32 bytes of WireGuard transport overhead,
17 bytes of BlakTail relay framing, and a worst-case 48-byte outer IPv6/UDP
header totals 1377 bytes. That stays below a 1500-byte underlay MTU and below the
relay's 2048-byte encrypted-payload ceiling; the relay never parses the inner IP
version.

## Subnet routers and exit nodes

Advertise one or more RFC1918 private IPv4 networks from the Linux router:

```sh
sudo blaktaild up --coord https://coord.example.org \
  --advertise-routes 10.1.0.0/24,10.2.0.0/16
```

Or advertise a full IPv4 exit path with `--advertise-exit-node`. The request is
inert until an owner or admin opens **Devices** in the console and explicitly
checks each route, or creates a named resource on **Networks** that uses this
router as a routing peer ([network-resources.md](network-resources.md)).
Removing an advertisement also removes any approval for it.
Public, loopback, link-local, multicast, tailnet-overlapping, and ambiguous subnet
advertisements are rejected. Overlapping approved subnets on different active
routers are rejected.

A Linux client opts into one approved exit node by name, MagicDNS name, or UUID:

```sh
sudo blaktaild up --coord https://coord.example.org --exit-node router-one
```

Rerunning `up` resumes the existing enrollment; no join key is needed. Use
`--exit-node none` to stop using an exit node and `--advertise-routes none` to
withdraw all advertisements. When changing routes, pass the complete desired
list; the new list replaces the previous one.

On a router, BlakTail enables `net.ipv4.ip_forward`, filters what it forwards,
and masquerades tailnet sources leaving non-BlakTail interfaces. `down` and
`pause` remove those exact rules and restore forwarding when BlakTail originally
enabled it.

### Forward filter

The agent reports the `forward-filter` capability. When the coordinator answers
with a `forward_filter` allow-list, forwarded overlay traffic goes through the
`BLAKTAIL-FWD` chain (jumped to from `FORWARD -i blaktail0`, comment
`blaktail-forward`) in both `iptables` and `ip6tables`:

1. established and related flows;
2. every deny entry (`REJECT`), for example a policy host carve-out;
3. every allow entry: `-s <client overlay address> -d <prefix>`, limited to the
   entry's TCP/UDP ports or ICMP, IPv4 and IPv6 rules split by family;
4. reject everything else (default deny, including anything not advertised).

Each update builds `BLAKTAIL-FWD-NEW`, jumps to it at `FORWARD` position 1,
removes the old jump and chain, then renames the new chain, so there is never a
moment with no filter; if any command fails the previous chain stays in force
and the error is logged. Reapplying the same list is a no-op in effect. The
last list is kept in `state.json` and reinstalled before routing restarts. When
the coordinator predates forward filtering (no `forward_filter` field), the
agent keeps the legacy per-route `ACCEPT` rules. Inspect with
`sudo iptables -S BLAKTAIL-FWD`. On an exit client, policy routing preserves local/subnet routes and
WireGuard's marked transport packets while sending the remaining IPv4 default
through the selected peer. Existing conflicting kernel routes fail closed instead
of being overwritten. macOS peers can consume approved private subnet routes, but
route advertising and exit-node selection are Linux-only in this release. IPv6
subnet routing and IPv6 exit nodes are not enabled by this IPv4 routing feature;
node-to-node IPv6 is enabled independently.

## MagicDNS

The agent runs an authoritative UDP DNS stub on its tailnet IPv4 address, port 53.
It answers A and AAAA records for the node and currently authorised peers under the
organisation's `<org-prefix>.blaktail` domain. Unknown private names return
`NXDOMAIN`; names outside that suffix are refused and never forwarded by BlakTail.
Both `peer-name` and `peer-name.<org-prefix>.blaktail` resolve locally.
`up --exit-after-join` leaves system resolver configuration in place for
`blaktaild run`.

On systemd-resolved hosts, the agent installs a per-interface search and route-only
domain with `resolvectl`; otherwise it uses `resolvconf`. The final fallback safely
backs up and prepends `/etc/resolv.conf`, refuses to overwrite a symlink, and restores
the exact backup on `blaktaild down`. If the file changes after BlakTail manages it,
the agent preserves the backup and refuses to overwrite the operator's change.

The stub prefers the IPv4 overlay address so `ping peer-name` keeps working when
IPv6 is unroutable. AAAA answers remain available.

Share a folder with other devices on the same organisation:

```sh
sudo blaktaild share enable --path /srv/shared --name files
```

Peers browse `http://<this-node>.<org>.blaktail:5647/files/` over the overlay.
Finder can mount that URL with Go → Connect to Server (read-only WebDAV).
The listener binds only the tailnet IPv4 address. Policy that already allows a
peer to see the node also opens TCP 5647 unless a deny rule blocks it.
`blaktaild share disable` withdraws the share.

## IPv6-only path drill

After two current agents have joined the same organisation, record each ULA from
`blaktaild status`, then temporarily remove only the BlakTail IPv4 address:

```sh
sudo ip -4 address flush dev blaktail0
ping -6 <other-node-ULA>
```

The ping must succeed. Restart `blaktaild` afterward to restore the coordinator-
assigned IPv4 address. This does not disable the host's underlay IPv4 transport;
it proves the encrypted inner path and WireGuard `allowed-ips` work over IPv6.

## Credential renewal

`blaktaild status` shows the node credential expiry. Renew an expired or expiring
enrolment with a fresh join key; the node keeps its tailnet IP and WireGuard key:

```sh
printf '%s' "$BLAKTAIL_JOIN_KEY" | sudo blaktaild reauth
```

For systemd, first complete enrollment with `--exit-after-join`, then install
`packaging/systemd/blaktaild.service` and run
`sudo systemctl enable --now blaktaild`. The unit resumes persisted state with
`blaktaild run`, validates config in `ExecStartPre`, and keeps capabilities limited
to `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`. It never puts a join key in argv or
an environment file. Optional file configuration is selected by setting
`BLAKTAIL_CONFIG=/etc/blaktail/config.toml` in `/etc/blaktail/agent.env`; see
[configuration.md](configuration.md). See the
[upgrade/version-skew policy](upgrades.md) before replacing a running agent.

## SSH user policy

The agent always installs the inbound overlay filter compiled by the
coordinator and reports `acl-filter`. TCP 22 is rejected from sources with
no SSH grant on destinations that SSH rules select. Per-user limits
(`users: ["deploy"]`, or `*` with a denied user) need sshd to cooperate, so
they are opt-in and fail closed:

1. Add one line at the **end** of `/etc/ssh/sshd_config`:
   `Include /var/lib/blaktail/sshd_policy.conf`
2. Set `BLAKTAIL_SSHD_DROPIN=/var/lib/blaktail/sshd_policy.conf` in
   `/etc/blaktail/agent.env` and restart `blaktaild`.

On every peer-map apply the agent writes `Match Address` blocks there
(ending with `Match all`), then requires `sshd -t` to pass, `sshd -T -C` to
show the expected `allowusers`/`denyusers` for each limited source and none
of them for an unrelated address, and a running sshd to reload
(`systemctl reload ssh|sshd`, or `HUP` via `/run/sshd.pid`). Only then does
it report `ssh-users`, and only then does the coordinator open TCP 22 for
user-limited sources. Any failure restores the previous file, logs a
warning and keeps TCP 22 closed to those sources. Logins that are not plain
names become `DenyUsers *` for that source.

The agent never edits `sshd_config`. To revert, remove the `Include` line,
unset the variable, and reload sshd. The hardened systemd unit only allows
writes under `/var/lib/blaktail`, which is why the drop-in lives there.
The SSH port is fixed at 22.

### Browser SSH and remote jobs (opt-in)

To accept browser SSH sessions from the organisation's onshore gateway, also
set `BLAKTAIL_SSH_USER_CA=/var/lib/blaktail/ssh_user_ca.pub`. The agent writes
the organisation SSH user CA there and trusts it only in a `Match Address`
block for the gateway, verified with `sshd -T`, then reports `remote-ssh-ca`.
It also reports `/etc/ssh/ssh_host_ed25519_key.pub` so the gateway can pin it.

To run owner-approved remote jobs, start the agent with
`--allow-remote-jobs --remote-jobs-user <unprivileged account>` (or
`BLAKTAIL_ALLOW_REMOTE_JOBS=true` and `BLAKTAIL_REMOTE_JOBS_USER`). Root is
refused. See [remote-access.md](remote-access.md).

## Linux tray (scaffold, issue #12)

`apps/linux-tray/` holds an honest scaffold for a GTK/AppIndicator tray
that drives the `blaktaild` CLI on the same host (connect/disconnect/status,
sign-in via the normal browser-approval enrolment URL). It is not packaged,
not released, and not yet validated on Ubuntu 26.04. See its README for the
scope and the remaining `TODO` markers.
