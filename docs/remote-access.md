# Browser remote access and remote jobs

BlakTail can open an SSH terminal (and, with guacd, an RDP desktop) on a device
from the console, and can run owner-approved, allowlisted jobs on devices that
opted in. Both are off until an operator turns them on, and both follow
[ADR 0006](adr/0006-browser-remote-access.md).

## How a browser session works

```
browser ──wss (console origin)──▶ onshore gateway ──WireGuard (its own node)──▶ device:22
   │                                 │
   └ console server action           └ redeems the ticket with its node credential
     asks the coordinator for          gets a session-only SSH certificate
     a single-use ticket               pins the device's reported host key
```

1. A person with **use remote sessions** (owner, admin or network admin) opens
   a device, chooses **Open browser terminal**, enters the OS account and a
   reason. The console needs a sign-in within the last 5 minutes (or the
   organisation's shorter step-up window) and applies the organisation's MFA
   rule. Members and auditors are refused by the coordinator (`403`).
2. The coordinator checks, then issues a ticket valid for **60 seconds, once**:
   - the device and gateway are in this organisation, not suspended, revoked,
     deleted or credential-expired;
   - the access policy pairs the gateway with the device, lets the gateway
     reach TCP 22, and an **SSH rule lets the gateway log in as that OS user**;
   - the device's agent proved it installed the organisation SSH CA
     (`remote-ssh-ca` capability) and reported a host key with no pending
     change;
   - the person has no other live session to that device.
   Refusals are audited as `remote_session.denied` with the reason.
3. The browser opens a WebSocket to the gateway and sends only the ticket and
   its terminal size. The gateway generates an Ed25519 key in memory, redeems
   the ticket with **its own node credential**, and gets back the device's
   overlay address, the OS user, the pinned host key, and an SSH user
   certificate for its in-memory key: one principal (the OS user),
   `source-address` set to the gateway's overlay addresses, only `permit-pty`,
   valid until the session's end (at most 30 minutes).
4. The gateway connects over the overlay, negotiates only `ssh-ed25519` host
   keys, and refuses any key other than the reported one **before**
   authenticating. It then logs in with the certificate and relays a PTY.
5. Every 10 seconds the gateway reports byte counts. The coordinator re-runs
   the same checks and answers `terminate` if the session was revoked, the
   person was suspended, the device or gateway was suspended or revoked, the
   organisation's gateway setting was cleared or pointed at another device
   (`gateway_changed`), the policy changed, a new host key arrived or the time
   limit passed. The gateway also ends a session after 10 minutes without
   input. If redeeming fails after the ticket is spent (no overlay IPv4 on the
   device, a malformed or non-Ed25519 gateway key, a certificate signing
   failure), the session is ended with reason `error` and audited.

Nothing in the browser's messages names a device, port or account; those come
only from the ticket. The browser never sees a WireGuard key, node token,
certificate or private key.

### Limits

| | |
| --- | --- |
| Ticket | single use, 60 seconds |
| Session | at most 30 minutes (choose 1–30); no reconnect, start again |
| Idle | 10 minutes without input |
| Revoke, suspend, policy change, gateway change | ends the live session within one report (10 s) |
| Concurrency | one live session per person and device |
| Clipboard | the browser's own copy and paste only |
| File transfer | off (no SFTP, no drives, no RDP file streams) |
| Recording | none; only metadata is audited |

### What is audited

Coordinator audit (hash-chained): `remote_session.issued`, `.denied`,
`.started`, `.ended` (with reason, duration and bytes each way), `.revoked`,
`.host_key_changed`, `.host_key_acknowledged`, `.host_key_mismatch`, and
`remote_access.settings_updated`. Each names the person, device, OS user and
access reason. Keystrokes, screen output and passwords are never logged by the
coordinator, the gateway or the console.

## Setting it up

### 1. Run a gateway node

The gateway is an ordinary enrolled BlakTail device in the organisation, so
policy decides what it can reach and it can be suspended or revoked like any
device. Run it onshore, next to the coordinator. One gateway serves one
organisation; it never dials another organisation's devices.

```sh
# enrol the gateway host like any Linux device, tagged for policy
printf '%s' "$JOIN_KEY" | blaktaild up --coord https://coord.example.org.au --name remote-gateway
blaktaild run &

blaktail-gateway \
  --coord https://coord.example.org.au \
  --state-dir /var/lib/blaktail \
  --listen 0.0.0.0:8443 \
  --allowed-origin https://console.example.org.au \
  --tls-cert /etc/blaktail/gateway.crt --tls-key /etc/blaktail/gateway.key
```

`deploy/docker/gateway.Dockerfile` builds an image with both binaries. Without
`--tls-cert`/`--tls-key` the gateway serves plain HTTP and must sit behind a
TLS proxy. Browsers must send an `Origin` in `--allowed-origin`.

Then an owner opens **Remote → Remote access**, chooses the gateway device and
enters its `wss://` address. Saving creates the organisation's SSH user CA
(sealed with the coordinator secret) and publishes it to agents.

### 2. Write the policy

Give the gateway a tag and allow it explicitly, for example:

```json
{
  "rules": [{ "action": "allow", "src_tags": ["office"], "dst_tags": ["store"], "dst_ports": ["22"], "protocols": ["tcp"] }],
  "ssh": [{ "action": "allow", "src_tags": ["office"], "dst_tags": ["store"], "users": ["deploy"] }]
}
```

A browser session can never reach a port or account that an ordinary device
with the gateway's tags could not.

### 3. Opt devices in

On each Linux device that should accept browser SSH, use the existing sshd
drop-in (see [linux-agent.md](linux-agent.md#ssh-user-policy)) and also
name a CA file under `/var/lib/blaktail` (the hardened unit can only write
there):

```sh
BLAKTAIL_SSHD_DROPIN=/var/lib/blaktail/sshd_policy.conf \
BLAKTAIL_SSH_USER_CA=/var/lib/blaktail/ssh_user_ca.pub \
blaktaild run
```

The agent then writes the CA and appends, only for the gateway's overlay
addresses:

```
Match Address 100.64.0.5,fd…::5
    TrustedUserCAKeys /var/lib/blaktail/ssh_user_ca.pub
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
Match all
```

The principal mapping is sshd's built-in one: with no `AuthorizedPrincipalsFile`
or `AuthorizedPrincipalsCommand` configured, a certificate logs in only as a
login name it lists, and each session certificate lists exactly the one
approved OS user. The agent refuses to activate the CA if sshd has another
principals source. It proves the block with `sshd -T` for the gateway
address and for an unrelated address before claiming `remote-ssh-ca`; any
failure restores the previous file.

The agent also reports `/etc/ssh/ssh_host_ed25519_key.pub`
(`BLAKTAIL_SSH_HOST_KEY` overrides the path). The first report is pinned. A
different key later is held as pending, blocks new sessions and ends live ones,
until someone with **manage devices** compares it on the device
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`) and accepts it on the
Remote access page.

### Suspending people

Suspending or removing a membership in the console, or changing it to a role
without the permission, revokes that person's open sessions and unredeemed
tickets. So do SCIM deactivation (`PATCH active=false`, `DELETE`, or a
provisioned-inactive user), applying a directory group mapping that moves
someone to a role without **use remote sessions**, and the sweep that turns
an expired grace period into a tombstone. SCIM and directory sweeps have no
console session, so the console sends a service assertion that the
coordinator accepts only for this one revoke call; the coordinator audits it
as actor `system:scim` or `system:directory` with role `system`. These calls
are best effort: if the coordinator is unreachable the console logs a
warning and the session still ends at its 30-minute cap.

## RDP

With `--guacd 127.0.0.1:4822` (Apache Guacamole's `guacd` in the gateway's
network namespace, so it dials over the overlay), the device page offers
**Open remote desktop**. The coordinator issues a ticket the same way, checking
that policy lets the gateway reach TCP 3389. The gateway performs the guacd
handshake itself with the ticket's address and account; the browser supplies
only the password, which is used once and never stored. Browser instructions
outside an allowlist (keys, mouse, size, clipboard, sync) are dropped, and
upload, download, drive and printing are disabled.

Limits: the RDP server certificate is not pinned (`ignore-cert`); the device's
identity rests on its WireGuard-authenticated overlay address. The device's
own Windows or xrdp sign-in is enforced. The lab proved the path to xrdp at
the protocol level (desktop image instructions reached the client); it has
not been checked visually in a browser or against Windows.

## Remote jobs

Owners define **job templates** on **Remote → Remote jobs**: a name, an
absolute program path and fixed arguments (one per line, never a shell
string), a timeout (at most 10 minutes), an output cap (at most 64 KiB) and
target tags or devices. Shells, `env`, `sudo`, `xargs` and interpreters are
refused as the program.

A run is requested for one template and one device (owner, admin or network
admin, with a reason). The request carries no command text, so nothing can be
added to the owner's argv. Only an owner can approve it. Approval signs the
exact job (run, organisation, device, argv, limits, a 10-minute claim window)
with an Ed25519 key derived from the coordinator secret; a database write alone
cannot create a runnable job.

Devices opt in explicitly:

```sh
blaktaild --allow-remote-jobs --remote-jobs-user blaktail-jobs run
```

The agent pins the organisation's job key on first use, polls every 15
seconds, verifies each job's signature, device and expiry, records the run ID in
`remote-jobs-runs.json` in its state directory (owner-only, kept until the
job's signed expiry) and refuses any run ID it has already seen, even across
restarts or if the coordinator offers it again, claims it once, and
runs exactly its argv with no shell, an empty environment (`PATH` and `LANG`
only), stdin closed, `/` as the working directory and its own process group,
as the named non-root user (supplementary groups dropped). The timeout, the
output cap and a console cancel each kill the whole process group. The result
(status, exit code, capped output) is stored on the run; the audit chain
records `remote_job.template_created`, `.requested`, `.approved`, `.started`,
`.finished` (with an output SHA-256) and `.cancel_requested`. Linux and macOS
only.

## Live lab proof

`deploy/homelab/prove-remote-access.sh` (run with
`DOCKER_CONTEXT=m3-max`) builds the coordinator image and
`deploy/docker/gateway.Dockerfile` from tracked sources and runs a
coordinator, a gateway node (blaktaild, blaktail-gateway, guacd sidecar) and a
Linux target (blaktaild, OpenSSH with the opt-in drop-in and CA, xrdp) on one
Docker network, with kernel WireGuard between the nodes. A Node 22 driver
signs console assertions like the console and opens the gateway WebSocket
like the browser terminal.

Run on 3 October 2026 (m3-max, Linux containers), commit `d05f493` plus the
lab script changes recorded with these docs. Summarised output:

```
ok target ready: capabilities=acl-filter,forward-filter,magicdns,remote-jobs,remote-ssh-ca,ssh-users,wireguard
Match Address 100.64.0.1,fda4:…::1      # gateway only
    TrustedUserCAKeys /var/lib/blaktail/ssh_user_ca.pub
== browser SSH session
ok browser session ran id: uid=1000(deploy) gid=1000(deploy) groups=1000(deploy)
ok reused ticket refused by the coordinator
ok member refused (403)
ok OS user outside the SSH rule refused: no SSH rule lets the gateway log in to this device as root
ok live session ended 10.0s after revoke (reason revoked)
ok live session ended 10.0s after the device was suspended (policy: the device is suspended)
ok suspended device refused: the device is suspended
== remote jobs
ok shell template refused
ok approved job ran as the unprivileged user: uid=1001(jobrunner) gid=1001(jobrunner) groups=1001(jobrunner)
ok job killed at its 2 s timeout (timed_out)
ok running job cancelled from the console
ok audit chain intact over 34 events
== RDP through guacd to xrdp
ok RDP desktop drawn through guacd: {"size":5,"img":5,"blob":5,"cursor":4,"sync":5,…}
== host key swapped behind the agent's back
ok host key mismatch failed closed before login and was audited
== agent reports the new key
ok changed host key blocks new sessions: this device reported a new SSH host key; an administrator must acknowledge it
== gateway logs carry no terminal content
remote_access_proof passed
```

sshd logged each login as `Accepted certificate ID
"blaktail-session:<session>:<person>" … via /var/lib/blaktail/ssh_user_ca.pub`.
Two defects found by the lab were fixed before the passing run: sshd has no
`AuthorizedPrincipalsFile none` value (the drop-in now relies on the built-in
mapping and checks no other principals source is set), and job privileges
were dropped in the wrong order (setgroups after setuid). `cargo clippy
--workspace --all-targets -D warnings` and the agent and gateway tests also
pass on Linux.

Not proven by the lab: a real browser (xterm.js and Guacamole rendering,
keyboard focus, tab-close behaviour), Windows RDP targets, TLS through a
public proxy, gateway behaviour across NAT or relay paths, and Postgres.
