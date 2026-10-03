# Browser SSH/RDP sessions over authorised BlakTail paths

**Priority:** P2. **Depends on:** draft 07 actual service/SSH enforcement, draft 12 peer state; security ADR. **Area:** browser gateway, session auth, console.

## Gap and outcome

NetBird has in-browser SSH/RDP and remote job surfaces. BlakTail offers overlay SSH capability and a policy schema, but no browser session or secure job executor. Add optional operator access only after end-to-end enforcement; UI convenience must not bypass device or OS login policy.

## Scope

- Design explicit trust boundary: ephemeral browser-to-onshore gateway session, target peer, OS identity, host-key validation, short TTL, MFA/step-up where needed, clipboard/file-transfer decision and separate audit from terminal contents. Gateway may not become an unrestricted cross-org proxy.
- SSH first; RDP only if there is a proven supported target/platform and independent security review. Session start/stop/status/reconnect UI with named device/organisation and authorised access reason. No persistent password, SSH private key or raw session recording by default.
- Treat remote jobs as a separate later phase: allowlisted commands, owner approval, strict duration/output cap, worker identity, cancellation and tamper-evident audit. No arbitrary shell execution from a “diagnostic” button.

## Acceptance / proof

Unauthorised member and revoked/suspended device cannot open new or existing session. Invalid host key fails closed; expired session cannot reconnect. Forced route failure does not send traffic outside approved AU path. Browser tests include keyboard access and safe tab closing; onshore gateway logs omit command contents unless explicitly opted in.

**Evidence:** `docs/policy.md`, `apps/console/src/components/acl-editor.tsx`; https://docs.netbird.io/manage/peers/browser-client, https://docs.netbird.io/manage/peers/ssh, https://docs.netbird.io/manage/peers/remote-jobs.

## Status (2 October 2026)

**Done:** design only. [ADR 0006](../adr/0006-browser-remote-access.md) (Proposed) covers:
- the trust boundary: a per-organisation onshore gateway that is itself a policy-checked BlakTail node, and never a cross-organisation proxy
- single-use 60-second session tickets bound to person, org, gateway, target and OS user
- a 30-minute hard cap, with policy and lifecycle re-checked every 60 seconds
- host keys reported by the agent and pinned, failing closed
- short-lived SSH certificates instead of stored credentials
- no recording by default
- a separate set of audit events
- why it waits for draft 07 SSH enforcement, draft 12 field proof and step-up auth

No UI or endpoint shipped.

**Proven by tests:** nothing. This is a design record.

**Still needs live/field proof or a decision:**
- Accept or revise the ADR.
- Proof of draft 07 SSH enforcement.
- Draft 12 two-node lifecycle drills.
- Step-up/MFA (draft 15).
- A gateway section in the threat model, and an external review.
- Separate ADRs for RDP and remote jobs.

## Status (2 October 2026)

Supersedes the design-only status above. ADR 0006 is Accepted (3 October 2026) and built.

**Done:**
- Coordinator `blaktail-coord/src/remote_access.rs`, migration slot 30:
  - gateway settings and an organisation SSH user CA sealed with the coordinator secret;
  - agent-reported Ed25519 host keys, pinned on first report, with pending changes needing an audited acknowledgement;
  - single-use 60-second tickets, re-checking org, role, lifecycle, policy pairing, TCP port and SSH rule user, device CA opt-in and host key;
  - gateway redeem with a session certificate (one principal, `source-address`, `permit-pty` only, at most 30 minutes);
  - 10-second gateway reports that end sessions on revoke, suspend, policy change, new host key or deadline;
  - per-user revoke, used by console membership suspension;
  - remote job templates, runs, owner approval and Ed25519 signing with a key derived from the coordinator secret;
  - agent pull, claim, state and result endpoints;
  - chained audit for every step.
- Permissions `use_remote_sessions` (owner, admin, network admin) and `manage_remote_jobs` (owner), in `permissions.rs`, `roles.ts` and `docs/permission-matrix.json`.
- New crate `blaktail-gateway`:
  - runs beside blaktaild on an enrolled node and uses its node credential;
  - WebSocket with an Origin allowlist;
  - russh client that negotiates only `ssh-ed25519` and fails closed on a host-key mismatch before authenticating;
  - certificate login, PTY relay, idle and deadline timers;
  - guacd handshake for RDP with a client opcode allowlist;
  - `deploy/docker/gateway.Dockerfile`.
- Agent (`blaktaild`):
  - opt-in gateway-only CA block in the existing sshd drop-in (`BLAKTAIL_SSH_USER_CA`), verified with `sshd -T` before claiming `remote-ssh-ca`;
  - host-key report;
  - `--allow-remote-jobs --remote-jobs-user`: signature, device and expiry check, key pinning, argv-only execution as a non-root user with an empty environment and its own process group, timeout, 64 KiB cap, cancel.
- Console:
  - `/devices/[id]/terminal` (xterm.js, bundled npm);
  - `/devices/[id]/desktop` (guacamole-common-js with a custom tunnel);
  - `/remote-access` (gateway, host keys, sessions, revoke);
  - `/remote-jobs` (templates, requests, approval, cancel, output);
  - 5-minute step-up plus the MFA rule for tickets and job approval;
  - membership suspension revokes sessions.
- Docs: `docs/remote-access.md`, ADR 0006, threat model, roles, console, Linux agent and policy capability table.

**Proven by tests:**
- Coordinator, 10 integration tests and 3 unit tests. They cover:
  - single-use tickets and expiry;
  - one live session per person and device;
  - member and auditor `403`, and admin unable to set the gateway;
  - cross-organisation gateway, target, ticket, revoke and report attempts;
  - suspended and revoked devices refused, and live sessions ended by suspend, revoke, person revoke and policy change;
  - host-key change blocking until acknowledged, and mismatch audited;
  - wildcard and shell-shaped OS users;
  - template validation (shells, relative paths, limits) and extra `argv` on a run request refused;
  - owner-only approval;
  - signed payload verification, single claim, output cap, cancel and an intact audit chain;
  - certificate principal, `source-address` and extensions.
- Agent:
  - argv passed literally with shell metacharacters;
  - timeout, output cap and cancel kill the job;
  - signature, device, expiry, extra-field and wrong-key rejection;
  - key pinning and root refusal;
  - CA block trusted only from the gateway, leak and principals-source refusal, and injection-shaped CA input never reaching sshd config.
- Gateway, 12 tests:
  - certificate login to an in-process SSH server;
  - host-key mismatch fails closed;
  - certificate for another user refused;
  - Origin allowlist;
  - end-to-end WebSocket that runs `id` and ends on a coordinator `terminate`;
  - used or unknown ticket, and mismatch reported;
  - guac encoding, partial UTF-8, opcode filter and the handshake using ticket values.
- Live lab on m3-max (`deploy/homelab/prove-remote-access.sh`, results in `docs/remote-access.md`):
  - browser-style session ran `id` as `deploy` over WireGuard with a certificate;
  - reused ticket, member and unlisted user refused;
  - revoke and device suspend ended live sessions in 10 s;
  - host-key swap failed closed and was audited, and the reported new key blocked sessions;
  - jobs ran as `jobrunner`, with timeout and cancel enforced and the audit chain intact;
  - RDP frames reached the client from xrdp through guacd.
- Linux clippy and agent and gateway tests pass.

**Still needs live/field proof or a decision:**
- A real-browser run: rendering, keyboard focus escape (Ctrl+Alt+E), screen reader output, tab-close prompt.
- Windows RDP targets, and the decision to leave RDP certificates unpinned.
- Gateway behind a public TLS proxy, and across NAT or relay paths.
- Postgres runs of the new tables.
- SCIM-driven deactivation does not revoke live sessions; they end at the 30-minute cap.
- CA and job-key rotation are not built: a changed job key stops jobs until the pin file is removed.
- Draft 07/12 field drills.
- Threat-model external review of the gateway.
- One gateway per organisation; no gateway pool or high availability.
