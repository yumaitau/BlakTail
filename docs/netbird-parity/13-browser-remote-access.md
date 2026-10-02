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
