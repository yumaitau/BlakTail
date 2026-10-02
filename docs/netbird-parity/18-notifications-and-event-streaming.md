# Operator alerts and onshore event forwarding with reliable delivery

**Priority:** P2. **Depends on:** draft 17 event model and existing signed webhook outbox. **Area:** notification preferences, event pipeline, console.

## Gap and outcome

BlakTail has signed HTTPS webhooks for selected policy/DNS/device/membership changes, not NetBird-style notification preferences and event-streaming integrations. Build on the transactional outbox rather than duplicate delivery systems or imply Slack/email support before configured.

## Scope

- Event catalogue with severity, actor, org, retention, deduplication and delivery policy. Candidate alerts: unusual enrollment, repeated failed approval, posture loss, expiring credential, route outage, relay saturation, IdP failure and admin write. Distinguish actionable event from routine heartbeat.
- Per-organisation owner settings for email, signed HTTPS webhook and optional onshore object/event sink. Explicit destination validation, SSRF/metadata protection, bounded retries/backoff, dead-letter inspection, replay and disable; do not leak secrets in delivery preview. Consider Slack/Datadog/etc. only via opt-in adapter and residency assessment.
- Console subscription/quiet-hour preferences and delivery status; explain that alerts are best effort, not safety control. No automatic offshore export under onshore copy.

## Acceptance / proof

Transactional event delivered once logically despite retry; dedupe key and signature verify. Failing endpoint cannot block policy publish or exhaust outbox. Revoked destination stops later delivery; cross-org URLs and private/metadata destinations rejected. End-to-end disposable sink confirms payload redaction and dead-letter recovery.

**Evidence:** `docs/admin-api.md`, `apps/console/src/components/webhook-manager.tsx`; https://docs.netbird.io/manage/settings/notifications, https://docs.netbird.io/manage/activity/event-streaming.
