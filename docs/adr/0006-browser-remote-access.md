# ADR 0006 — Browser remote access (SSH first) over authorised BlakTail paths

- Status: Accepted (3 October 2026). The product owner approved building
  browser SSH/RDP and remote jobs. Every constraint below is a requirement.
- Date: 2026-10-02 (proposed), 2026-10-03 (accepted and implemented)
- Tracks: NetBird parity draft 13 (`docs/netbird-parity/13-browser-remote-access.md`)

## Context

NetBird ships in-browser SSH/RDP and remote-job surfaces. BlakTail has overlay
SSH capability in the agent, an `ssh` section in the policy schema, and now a
peer lifecycle with revoke, tombstone and reversible suspend (draft 12). It has
no browser session, no gateway and no job executor.

A browser terminal is convenient and dangerous. It joins two trust domains: the
console (people, Better Auth sessions, organisation roles) and the data plane
(WireGuard identity, policy, OS login). A shortcut there can bypass the device
policy, the OS account, or the organisation boundary all at once. This ADR
fixes the boundaries before any code is written.

## Decision

Build browser SSH only after the preconditions below hold, and only in this
shape. RDP and remote jobs are separate later decisions.

### Trust boundary

```
browser ──TLS (console origin)──▶ onshore gateway ──WireGuard (its own node)──▶ target peer:22
   │                                  │
   └ console session + step-up        └ policy-checked as a normal BlakTail node
```

- The **gateway** is a dedicated BlakTail node per organisation (or a pool whose
  members each hold one organisation's node credential). It is enrolled, tagged
  (for example `tag:remote-access`), subject to the same ACL and SSH rules as
  any peer, and can be suspended or revoked like any peer. It is never a
  cross-organisation proxy: one gateway credential belongs to exactly one
  organisation and it only dials addresses from that organisation's peer map.
- The gateway runs onshore in the same Australian deployment as the
  coordinator. It is not a hosted service.
- The browser never receives WireGuard keys, node tokens or SSH private keys.
- The gateway is not trusted to decide authorisation alone. The coordinator
  issues each session; the gateway only executes it.

### Session model

1. An owner/admin (or a member, if policy grants them SSH to that device) picks
   a device and OS user in the console and states an access reason.
2. The console requires a recent sign-in (step-up within 5 minutes; MFA once
   draft 15 lands) and asks the coordinator for a session.
3. The coordinator checks, at issue time: organisation scope, role, the policy
   `ssh` rule for (person, target tags, OS user), target lifecycle `active`
   (not suspended, revoked, deleted or credential-expired), and gateway
   lifecycle `active`. It returns a single-use session id bound to (person,
   organisation, gateway node, target node, OS user) with a short TTL.
4. The browser opens a WebSocket to the gateway with that id. The gateway
   redeems it once with the coordinator and dials the target over WireGuard.

Limits:

- Session ticket TTL 60 seconds (redeem window); live session hard cap 30
  minutes; idle timeout 10 minutes. No reconnect after expiry: start again.
- The coordinator re-checks policy and lifecycle every 60 seconds; suspend,
  revoke, policy change or role loss ends live sessions within that bound.
- One concurrent session per (person, target) by default.

### Host-key validation

- The agent reports the target's SSH host-key fingerprints with its heartbeat
  (new field, same pattern as the transport summary from draft 12).
- The gateway pins against the coordinator-recorded fingerprint and fails
  closed on mismatch or absence. There is no "trust on first use" in the
  browser. A host-key change needs an owner/admin acknowledgement, audited.

### Credentials and OS identity

- OS login is still enforced by the target. Preferred: short-lived SSH user
  certificates signed by an organisation CA held by the coordinator (or KMS),
  valid for the session only and naming the OS user from the policy rule.
- No persistent passwords or private keys are stored in the console, the
  gateway or the browser. Password login through the browser is not offered.

### Clipboard, files and recording

- Clipboard follows the browser's own permission model; no server-side clipboard
  sync.
- File transfer is off. It is a separate decision with its own audit.
- No terminal content is recorded by default. Recording, if ever offered, is a
  per-organisation opt-in stored onshore with its own retention, and is
  announced in the session banner.

### Audit

Separate from terminal contents:

- `remote_session.requested`, `.issued`, `.denied` (with reason), `.started`,
  `.ended` (who/what ended it: user, timeout, policy, suspend, revoke),
  `.host_key_mismatch`.
- Each event records person, organisation, gateway node, target node, OS user,
  access reason and timestamps. Never command text or keystrokes.

### Remote jobs and RDP

- Remote jobs are not a "diagnostic button". If built: allowlisted commands
  only, owner approval, duration and output caps, a named worker identity,
  cancellation, and tamper-evident audit. Separate ADR.
- RDP only with a proven supported target platform and independent security
  review. Separate ADR.

## Implementation notes (3 October 2026)

Built as decided, with these specifics (see [remote-access.md](../remote-access.md)):

- `blaktail-gateway` runs beside `blaktaild` on an enrolled node and uses
  that node's credential to redeem tickets; one gateway per organisation.
- Live sessions are re-checked on every gateway report, every 10 seconds
  (tighter than the 60-second bound above); a gateway that cannot reach the
  coordinator ends its sessions.
- Session certificates carry one principal, `source-address` set to the
  gateway's overlay addresses and only `permit-pty`; devices trust the CA
  only inside a `Match Address` block for the gateway, with
  sshd's built-in principal mapping (principal equals login name; the agent
  refuses to activate the CA if another principals source is configured).
- Host keys are pinned on first report; a later change is pending until
  acknowledged by someone with manage devices, and blocks sessions meanwhile.
- Step-up: a sign-in within 5 minutes (or the organisation's shorter
  window) plus the organisation's MFA rule.
- RDP and remote jobs were approved alongside SSH rather than in separate
  ADRs. RDP uses a guacd sidecar with the gateway doing the handshake; the
  RDP certificate is not pinned. Remote jobs are owner-defined argv
  templates, owner approval, a coordinator-derived signing key, an opt-in
  agent executor as a named non-root user, timeout, output cap and cancel.

## Preconditions (originally why this was deferred)

These were the reasons to defer. With the build approved they remain
requirements and open proof items:

1. **SSH enforcement is not proven end to end** (draft 07). The policy schema
   has `ssh` rules and the editor itself warns that agent enforcement is
   incomplete. A browser gateway built on unenforced rules would make policy
   look stronger than it is.
2. **Peer state must be reliable first** (draft 12). Session issue and the
   60-second re-check depend on suspend/revoke/expiry and heartbeat freshness
   behaving correctly in the field. The lifecycle code and tests now exist, but
   revoke-to-disconnect timing and stale-heartbeat behaviour still need
   two-node and NAT drills.
3. **Step-up authentication** (draft 15) is not in place; a long-lived console
   cookie alone must not open a root shell.
4. **Gateway hosting** adds an always-on, internet-facing onshore component and
   a new attack surface that needs its own threat-model section and review.

## Acceptance before implementation starts

- Draft 07 proves agent-side SSH policy enforcement with tests and a live drill.
- Draft 12 drills show suspend and revoke remove a peer from maps and break
  connectivity within a measured bound on two real nodes.
- Step-up sign-in exists.
- Threat-model update and an external review plan for the gateway.

## Acceptance for the eventual build (from draft 13)

Unauthorised member and suspended/revoked device cannot open a new or keep an
existing session; invalid host key fails closed; expired session cannot
reconnect; forced route failure never sends traffic outside the approved AU
path; browser tests cover keyboard access and safe tab closing; gateway logs
omit command contents unless explicitly opted in.

## Consequences

- The console offers a browser terminal, a remote desktop page and remote
  jobs; all are off until an owner configures a gateway and device operators
  opt in.
- The gateway is a new always-on onshore component. Its threat-model section
  and an external review are still open.
- Host keys are reported through a dedicated agent endpoint rather than the
  heartbeat query string.

## Status (2 October 2026)

**Done:** Accepted and implemented. Built in:
- `blaktail-coord/src/remote_access.rs` (migration slot 30);
- the `blaktail-gateway` crate;
- the `blaktaild` sshd CA block, host-key report and remote jobs executor;
- the console terminal, desktop, remote access and remote jobs pages.

See [remote-access.md](../remote-access.md) and draft 13.

**Proven by tests:**
- The coordinator, agent and gateway suites listed in draft 13.
- The m3-max lab: browser-style SSH `id`, refusals, revoke and suspend within 10 s, host-key mismatch failing closed, signed jobs with timeout and cancel, and RDP frames via guacd.

**Still needs live/field proof or a decision:**
- A real-browser run.
- Windows RDP.
- RDP certificate pinning.
- Public TLS or NAT deployment of the gateway.
- Postgres.
- SCIM-driven revocation.
- CA and job-key rotation.
- An external review of the gateway.
