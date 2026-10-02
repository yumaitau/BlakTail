# Notifications and event forwarding

BlakTail sends operator events as **signed HTTPS webhooks** only. There is no
email, Slack, Teams, Datadog or other third-party adapter; the console does
not offer them. Forward webhooks into your own onshore tooling if you need
those channels, and assess where that tooling stores data.

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

- `route.approved`, `service_user.suspended` and `traffic.settings_changed`
  are raised from the matching audit action inside the same transaction;
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

Not provided: quiet hours, digests, per-person preferences, email, chat
adapters, or an object-store sink.
