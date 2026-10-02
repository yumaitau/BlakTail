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
