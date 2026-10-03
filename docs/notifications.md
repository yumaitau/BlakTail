# Notifications and event forwarding

BlakTail sends operator events as **signed HTTPS webhooks**, and to people by
**email** (through the operator's own SMTP relay), **Slack** or **Microsoft
Teams** incoming webhooks. All four use the same outbox, subscriptions,
retries, dead-letter and replay. Slack and Teams are offshore services and
need an owner's residency acknowledgement (see
[Notification channels](#notification-channels)). There is no Datadog or
other adapter.

Alerts are best effort. They are not a safety control: policy and enrolment
decisions never wait for, or depend on, a delivery.

## Destinations and subscriptions

Owners and admins (`manage_integrations`) add destinations in Settings →
Webhooks, or with `POST /api/v1/webhooks` (`webhooks:write`). An organisation
can have 8 active destinations. Each destination receives either every event
(`["*"]`, the default and the behaviour of destinations created before
subscriptions existed) or a chosen list of event types:

- Console: **Choose events** on a destination.
- API: `PUT /api/v1/webhooks/{id}/subscriptions` with
  `{"event_types": ["posture.failed", "credential.expiring"]}`.

Unknown event types are rejected. Changing a subscription is audited
(`webhook.subscriptions_updated`).

## Event catalogue

`GET /v1/orgs/{org}/events/catalogue` (console) and
`GET /api/v1/events/catalogue` (`webhooks:read`) return this table from the
coordinator. The `X-BlakTail-Severity` header carries the severity.

| Event | Severity | When |
| --- | --- | --- |
| `device.enrolled` | info | A device enrolled (join key or browser approval) |
| `join_key.used` | notice | A join key, not a browser approval, enrolled a device |
| `device.renamed` | info | A device's friendly name changed |
| `device.revoked` | warning | A device credential was revoked |
| `device.deleted` | warning | A device was removed |
| `device.suspended` | warning | A device was suspended |
| `device.resumed` | info | A suspended device was resumed |
| `credential.expiring` | warning | A device credential expires within 7 days (once per credential) |
| `posture.failed` | warning | A new inventory report made a device fail a policy-referenced posture check |
| `device.hardware_changed` | warning | A device reported a serial number or MAC addresses other than those pinned at its first report; its integration checks fail until an admin approves |
| `device.hardware_clash` | warning | A device reported a serial number or MAC address another device already holds; the first reporter keeps the provider match |
| `route.approved` | notice | The subnet routes approved for a device changed |
| `policy.published` | notice | A new access policy revision was published |
| `policy.rolled_back` | warning | Access policy was rolled back |
| `dns.published` | notice | A new DNS revision was published |
| `dns.rolled_back` | warning | DNS was rolled back |
| `membership.updated` | info | A membership's role or status changed |
| `membership.role_changed` | warning | A person's organisation role changed |
| `service_user.suspended` | warning | An automation client was suspended |
| `traffic.settings_changed` | notice | Traffic diagnostics were turned on/off or re-tuned |

Notes:

- `route.approved`, `service_user.suspended`, `traffic.settings_changed`,
  `device.hardware_changed` and `device.hardware_clash` are raised from the matching audit action inside the same transaction;
  their payload is `{action, target_type, target_id, actor: {user_id, role},
  details, audit_event_id}` with details redacted as in the audit log.
- `posture.failed` fires on a pass→fail transition caused by a device's own
  inventory report. Checks that lapse purely with time (credential age,
  report freshness) do not raise it.
- `credential.expiring` comes from a sweep every 15 minutes. Its event id is
  derived from the device and expiry, so it is delivered once per
  destination even across sweeps and coordinator replicas.
- Role changes come from the console; the coordinator accepts only
  `membership.updated` and `membership.role_changed` from it.

## Delivery

Each event is written to a transactional outbox with the change that caused
it, one row per subscribed, enabled destination (unique per destination and
event id). The coordinator posts JSON with `X-BlakTail-Event`,
`X-BlakTail-Event-Id`, `X-BlakTail-Delivery`, `X-BlakTail-Severity`,
`X-BlakTail-Organisation` and `X-BlakTail-Signature: t={unix},v1={hex}` where
`v1` is HMAC-SHA256 of `{t}.{body}` with the destination's signing secret.
Receivers should verify the signature, reject old timestamps and deduplicate
on `X-BlakTail-Event-Id`.

Failures (timeout after 5 s, non-2xx, 429, any redirect) retry with
exponential backoff up to 8 attempts, then the row is **dead-lettered**.
Settings → Webhooks → **Deliveries** lists the latest 50 deliveries with the
last error; **Replay** resets a pending or dead-lettered delivery
(`POST /api/v1/webhooks/deliveries/{id}/replay`, audited). Disabling a
destination stops all later delivery to it. A failing destination never
blocks a change; it only accumulates outbox rows.

## Destination safety

URLs must be HTTPS without embedded credentials. Rejected at create time and
again at every delivery (after DNS resolution, connecting only to the checked
address): loopback, private (RFC 1918, IPv6 ULA), link-local, CGNAT and the
BlakTail overlay (`100.64.0.0/10`), multicast, documentation, benchmarking and
reserved ranges, IPv4-mapped IPv6 forms of all of these, `localhost`,
`*.local`, `*.internal`, and cloud metadata endpoints (`169.254.169.254`,
`fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`).

Slack and Teams URLs get the same checks, and must also be on the vendor's
host: `https://hooks.slack.com/services/…` for Slack; `*.webhook.office.com`,
`*.logic.azure.com` or `*.api.powerplatform.com` (Workflows) for Teams.

## Notification channels

Settings → **Notification channels** (owners and admins with
`manage_integrations`) adds email, Slack and Microsoft Teams destinations.
Console routes: `GET /v1/orgs/{org}/notification-channels/capabilities`,
`POST /v1/orgs/{org}/notification-channels`,
`PUT /v1/orgs/{org}/notification-channels/{id}/schedule` and
`POST /v1/orgs/{org}/notification-channels/{id}/test`. A channel is a row in
the same destination table as webhooks (`kind` = `email`, `slack` or
`teams`), so it counts towards the limit of 8, has event subscriptions,
appears in **Deliveries** with the last error, and is disabled the same way.
Creating, rescheduling and test-sending are audited
(`notification_channel.created`, `.schedule_updated`, `.test_sent`).

**Email.** The operator configures one SMTP relay for the coordinator; the
organisation only chooses up to 10 recipients. Without a relay the console
says email is unavailable and the coordinator refuses email channels.

| Variable | Meaning |
| --- | --- |
| `BLAKTAIL_SMTP_HOST` | Relay host. Unset means email is off. |
| `BLAKTAIL_SMTP_PORT` | Default 587 (`starttls`), 465 (`tls`), 25 (`none`). |
| `BLAKTAIL_SMTP_TLS` | `starttls` (default, required upgrade), `tls` (implicit) or `none` (local relay only). |
| `BLAKTAIL_SMTP_USERNAME`, `BLAKTAIL_SMTP_PASSWORD` or `BLAKTAIL_SMTP_PASSWORD_FILE` | Optional AUTH. Refused with `none`: credentials never cross an unencrypted link. |
| `BLAKTAIL_SMTP_FROM` | Required sender, e.g. `BlakTail Alerts <alerts@example.org.au>`. |
| `BLAKTAIL_SMTP_CA_FILE` | Optional PEM CA for a relay with a private certificate. |

Mail is sent with `lettre` over rustls. The password is read from the
environment or a file, never stored in the database, never logged (the
config's debug form redacts it) and never shown in the console. Use an
onshore relay: email content is only as onshore as the relay and the
recipients' mailboxes.

**Slack and Microsoft Teams.** Paste an incoming webhook URL (Teams: an
incoming webhook or a Workflows "post to a channel" URL). These vendors
process message content outside Australia, so the console shows a residency
warning and the coordinator requires **an owner** (`manage_security`) and
`residency_acknowledged: true`; an admin gets 403 and a missing
acknowledgement gets 400. The URL is the credential: it is sealed at rest
(ChaCha20-Poly1305, the same key as webhook signing secrets), shown only as
`https://hooks.slack.com/…`, kept out of audit details and delivery errors,
and erased when the channel is disabled. Slack receives a `text` fallback
plus Block Kit `header`/`section`/`context` blocks; Teams receives an
Adaptive Card 1.4 `message` attachment. Values from events (device and
organisation names, reasons) are escaped for each format: `&`, `<`, `>` for
Slack, and a backslash before `\ [ ] ( ) * _ ~ `` ` `` for Teams, so they
cannot become links or formatting.

**Content.** Messages carry the event type, severity, catalogue summary,
time in the channel's time zone, event id and the event payload flattened to
`key: value` lines after the audit log's redaction (secret-looking keys and
`bt*_` tokens become `[redacted]`), capped at 20 fields of 200 characters.
The email subject is `[BlakTail] {severity} {event} - {organisation}` and
the body links to the console audit log.

**Quiet hours and digests.** Each channel may set quiet hours (`HH:MM` to
`HH:MM`, wrapping midnight, in an IANA zone; `Australia/Sydney` by default)
and a digest interval (off, or 5–1440 minutes). They apply to email, Slack
and Teams, not to webhooks.

- **Warning** events are critical: they are always sent at once, during
  quiet hours and outside any digest. Test sends are too.
- Info and notice events that fall in quiet hours wait in the outbox until
  the window ends, computed on the local wall clock, so daylight saving
  shifts the end time with the clock. An end time inside a spring-forward
  gap resolves to the first valid local time after it.
- With a digest, routine events wait until their interval has passed and
  are then sent together (up to 50 per message) as
  `[BlakTail] N notifications - {organisation}`; a failure retries the whole
  batch with the usual backoff and dead-letter.

**Test send.** **Send test** queues a `notification.test` delivery for one
destination (any kind, including a webhook) and reports through
**Deliveries**.

Not provided: per-person preferences, SMS or paging, an object-store sink,
or Datadog-style adapters. Alerts stay best effort.

## Live proof (3 October 2026)

`DOCKER_CONTEXT=m3-max deploy/homelab/prove-notifications.sh` builds a Linux
release coordinator and runs it with TLS beside Mailpit acting as the
operator's SMTP relay with **STARTTLS required**, **SMTP AUTH required** and
a certificate from a private lab CA (`BLAKTAIL_SMTP_CA_FILE`). Result:

- capabilities: `email_configured: true`, `email_tls: starttls`, default
  zone `Australia/Sydney`;
- an admin adding Slack got 403; an owner without the residency
  acknowledgement got 400;
- an admin created an email channel with quiet hours 22:00–07:00
  Australia/Sydney (the run was at 11:23 AEST, outside them);
- **Send test** arrived as `[BlakTail] test notification.test - Notifications lab`;
- enrolling a device with a join key and revoking it delivered
  `[BlakTail] warning device.revoked - Notifications lab`, body with the
  summary, `When: 2026-10-03 11:23 AEST`, event id, `device_id` and the
  console audit link; `device.enrolled` and `join_key.used` were delivered
  too, all on the first attempt;
- neither raw message contained the SMTP password, the coordinator HMAC
  secret or the node token, and the coordinator log held no SMTP password.

The Slack and Teams payloads, quiet-hour hold, digest batching, DST
boundaries and failing-endpoint error redaction are proven against local
mocks in `blaktail-coord` tests (`notify_channels::tests`,
`tests::notify_channels`), not against the real Slack or Teams services.
