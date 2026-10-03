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

## Status (2 October 2026)

**Done:**
- Event catalogue with severity (`blaktail-coord/src/notifications.rs`, `docs/notifications.md`), served at `/v1/orgs/{org}/events/catalogue` and `/api/v1/events/catalogue`; a test keeps every enqueue site catalogued.
- Per-destination subscriptions (`event_types_json`, default `["*"]` so existing destinations are unchanged): console **Choose events**, `PUT /v1/orgs/{org}/webhooks/{id}/subscriptions`, `PUT /api/v1/webhooks/{id}/subscriptions`, audited.
- New events: `join_key.used` (enrolment via join key), `posture.failed` (pass→fail on an inventory report), `credential.expiring` (sweep, deduplicated by deterministic event id with `ON CONFLICT DO NOTHING`), `route.approved`, `service_user.suspended` and `traffic.settings_changed` (raised from audit actions in the same transaction), `membership.role_changed` (console, when the role actually changed), plus the existing `device.suspended`/`device.resumed` now catalogued. `X-BlakTail-Severity` header.
- Dead-letter view and replay already existed (coordinator + console); the console now shows the last error on dead-lettered rows.
- SSRF hardening: URL host checked via the parsed host (IPv6 literals were previously not IP-checked), IPv4-mapped IPv6, CGNAT/overlay `100.64/10`, multicast, documentation, reserved ranges, AWS IPv6 and Alibaba metadata; delivery pins the connection to the address it checked (no DNS-rebinding window).
- Console copy states webhooks are the only channel; no email/Slack is implied.

**Proven by tests:** `tests::events_audit::webhook_subscriptions_filter_new_events_and_reject_unsafe_destinations` (metadata/mapped/loopback destinations rejected over HTTP, unknown event types rejected, member cannot change subscriptions, filtered destination receives only `route.approved`, security destination receives exactly its four types with one expiry notice across two sweeps, disabled destination receives nothing further, role-change event accepted, catalogue served); `webhooks::tests::webhook_urls_reject_mapped_cgnat_and_cloud_metadata_targets`; existing delivery matrix (timeout/429/redirect) still passes.

**Still needs live/field proof or a decision:**
- End-to-end delivery to a disposable external sink with signature verification and dead-letter recovery (only in-process tests here).
- Email, chat adapters, quiet hours, digests and an onshore object-store sink are not implemented; any adapter needs a residency assessment.
- `posture.failed` does not fire for time-based lapses (credential age, report freshness); route-outage, relay-saturation, IdP-failure and "unusual enrolment" heuristics are not implemented.
- Outbox rows are never pruned; long-term growth needs a retention decision.

## Status (2 October 2026), channels round

**Done:** email, Slack and Microsoft Teams channels on the existing outbox (`blaktail-coord/src/notify_channels.rs`, coordinator migration slot 37): channels are `webhook_destinations` rows with a `kind`, so subscriptions, the 8-destination limit, retries with backoff, dead-letter, replay and disable are shared. Email goes through an operator-configured relay (`BLAKTAIL_SMTP_*`, `lettre` over rustls, STARTTLS by default, optional private CA, credentials refused without TLS, password never stored or logged). Slack/Teams URLs are pinned to vendor hosts, pass the SSRF guard and DNS pinning, are sealed at rest, never returned, kept out of audit and delivery errors, and erased on disable; creating one requires an owner and an explicit residency acknowledgement. Rendering uses the audit log's redaction. Per-channel quiet hours (IANA zone, `Australia/Sydney` default, wall-clock and DST aware) hold info/notice events until the window ends while warning events and test sends always go at once; optional digests batch routine events. Test-send endpoint for any destination. Console: Settings → Notification channels (`components/notification-channels.tsx`, `lib/coord-notifications.ts`, `app/settings/notification-actions.ts`) with residency warning, owner-only acknowledgement, quiet hours, digest, test send and deliveries. Docs: `docs/notifications.md`.
**Proven by tests:** `notify_channels::tests` (quiet-hour boundaries across midnight and same-day, Sydney DST start and end, an end time in the spring-forward gap, Brisbane vs Sydney, invalid input, critical classification, SMTP env parsing and password redaction, email rendering with secrets redacted and header injection stripped, Slack Block Kit and Teams Adaptive Card shapes, vendor host pinning). `tests::notify_channels` (HTTP, in-memory store, local mock servers): admin/member 403 and missing acknowledgement 400 for Slack, metadata/foreign/look-alike hosts 400, sealed URL never in listings or audit, Slack test send and Teams subscribed event received by the mock with the right shapes, cross-organisation test/schedule 404 and foreign session 401, failing endpoint error without the secret path, disable erases the sealed URL; email refused until a relay exists, member 403, bad recipient 400, test email through an in-test SMTP server, a warning delivered during quiet hours while an info event is held to the window end, then a digest delivering held events as one message. Live: `deploy/homelab/prove-notifications.sh` on m3-max with Mailpit requiring STARTTLS and AUTH: test email and a real `device.revoked` alert arrived, no SMTP password, HMAC secret or node token in messages or logs (`docs/notifications.md`).
**Still needs live/field proof or a decision:** delivery to real Slack and Teams workspaces (mocks only) and a vendor residency assessment beyond the acknowledgement; an onshore object-store sink; per-person preferences; outbox retention/pruning; heuristics for route outage, relay saturation, IdP failure and unusual enrolment; email deliverability (SPF/DKIM) is the operator relay's responsibility.
