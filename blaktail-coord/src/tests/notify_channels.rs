//! Email, Slack and Teams channels on the outbox (draft 18).

use super::*;
use crate::notify_channels::{set_smtp_for_test, SmtpConfig, SmtpTls};
use std::sync::{Arc as StdArc, Mutex as StdMutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

type Captured = StdArc<StdMutex<Vec<(String, serde_json::Value)>>>;

/// Local stand-in for Slack and Teams: records every JSON body by path.
async fn chat_mock() -> (std::net::SocketAddr, Captured) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured: Captured = StdArc::default();
    let sink = captured.clone();
    tokio::spawn(async move {
        let server =
            axum::Router::new().fallback(move |uri: axum::http::Uri, body: axum::body::Bytes| {
                let sink = sink.clone();
                async move {
                    if uri.path().contains("fail") {
                        return StatusCode::INTERNAL_SERVER_ERROR;
                    }
                    let value = serde_json::from_slice(&body).unwrap_or_default();
                    sink.lock().unwrap().push((uri.path().to_owned(), value));
                    StatusCode::OK
                }
            });
        axum::serve(listener, server).await.ok();
    });
    (addr, captured)
}

type Mailbox = StdArc<StdMutex<Vec<String>>>;

/// Minimal SMTP sink: accepts every message and keeps its DATA section.
async fn smtp_mock() -> (u16, Mailbox) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mailbox: Mailbox = StdArc::default();
    let sink = mailbox.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let sink = sink.clone();
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                write.write_all(b"220 mock ESMTP\r\n").await.ok();
                let mut data: Option<String> = None;
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(body) = data.as_mut() {
                        if line == "." {
                            sink.lock().unwrap().push(std::mem::take(body));
                            data = None;
                            write.write_all(b"250 queued\r\n").await.ok();
                        } else {
                            body.push_str(&line);
                            body.push('\n');
                        }
                        continue;
                    }
                    let verb = line.to_ascii_uppercase();
                    let reply: &[u8] = if verb.starts_with("EHLO") || verb.starts_with("HELO") {
                        b"250 mock\r\n"
                    } else if verb.starts_with("DATA") {
                        data = Some(String::new());
                        b"354 go ahead\r\n"
                    } else if verb.starts_with("QUIT") {
                        write.write_all(b"221 bye\r\n").await.ok();
                        return;
                    } else {
                        b"250 ok\r\n"
                    };
                    write.write_all(reply).await.ok();
                }
            });
        }
    });
    (port, mailbox)
}

async fn wait_for<T>(mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for delivery"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn create_channel(
    router: &Router,
    org_id: Uuid,
    session: &str,
    body: serde_json::Value,
) -> Response {
    call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org_id}/notification-channels"),
        body,
        Some(session),
    )
    .await
}

async fn deliveries(
    router: &Router,
    org_id: Uuid,
    owner: &str,
    destination_id: Uuid,
) -> Vec<crate::webhooks::WebhookDelivery> {
    body(
        call(
            router,
            Method::GET,
            &format!("/v1/orgs/{org_id}/webhooks/{destination_id}/deliveries"),
            serde_json::Value::Null,
            Some(owner),
        )
        .await,
    )
    .await
}

#[tokio::test]
async fn chat_channels_need_owner_residency_ack_and_seal_their_urls() {
    let (addr, captured) = chat_mock().await;
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "chat-channels").await;
    let other = create_test_org(&router, "chat-channels-other").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    let other_owner = signed_session(other.id, "owner-2", Role::Owner, now() + 60);
    let slack_url = format!("http://{addr}/services/slack-secret-path");
    let slack = serde_json::json!({
        "kind": "slack",
        "name": "ops-slack",
        "url": slack_url,
        "residency_acknowledged": true,
    });

    // Offshore channels need an owner and an explicit acknowledgement.
    for (session, status) in [
        (&admin, StatusCode::FORBIDDEN),
        (&member, StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            create_channel(&router, org.id, session, slack.clone())
                .await
                .status(),
            status
        );
    }
    let mut unacknowledged = slack.clone();
    unacknowledged["residency_acknowledged"] = false.into();
    let refused = create_channel(&router, org.id, &owner, unacknowledged).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let refused: serde_json::Value = body(refused).await;
    assert!(refused["error"]
        .as_str()
        .unwrap_or_default()
        .contains("outside Australia"));
    // The SSRF guard and the vendor host pin still apply.
    for bad in [
        "https://169.254.169.254/services/x",
        "https://example.com/services/x",
        "https://hooks.slack.com.evil.example/services/x",
    ] {
        let mut input = slack.clone();
        input["url"] = bad.into();
        assert_eq!(
            create_channel(&router, org.id, &owner, input)
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }

    let created = create_channel(&router, org.id, &owner, slack.clone()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: crate::webhooks::WebhookDestination = body(created).await;
    assert_eq!(created.kind, "slack");
    assert!(created.residency_acknowledged_at.is_some());
    assert!(!created.url.contains("slack-secret-path"));
    let teams: crate::webhooks::WebhookDestination = body(
        create_channel(
            &router,
            org.id,
            &owner,
            serde_json::json!({
                "kind": "teams",
                "name": "ops-teams",
                "url": format!("http://{addr}/workflows/teams-secret-path"),
                "event_types": ["device.enrolled"],
                "residency_acknowledged": true,
            }),
        )
        .await,
    )
    .await;

    // Listing never returns the sealed URL.
    let listing = call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{}/webhooks", org.id),
        serde_json::Value::Null,
        Some(&owner),
    )
    .await;
    let listing = String::from_utf8(
        to_bytes(listing.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(listing.contains("\"kind\":\"slack\""));
    assert!(!listing.contains("secret-path"));
    let stored: String =
        sqlx::query_scalar("SELECT target_sealed FROM webhook_destinations WHERE id=$1")
            .bind(created.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(stored.starts_with("bte1.") && !stored.contains("secret-path"));

    // Test send to Slack, and a subscribed event to Teams.
    let sent = call(
        &router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/notification-channels/{}/test",
            org.id, created.id
        ),
        serde_json::Value::Null,
        Some(&admin),
    )
    .await;
    assert_eq!(sent.status(), StatusCode::ACCEPTED);
    let _node = register_test_node(&router, org.id, &owner, "office-1", "office-key", &[]).await;
    let (slack_body, teams_body) = wait_for(|| {
        let seen = captured.lock().unwrap();
        let slack = seen
            .iter()
            .find(|(path, body)| {
                path.contains("slack") && body.to_string().contains("notification.test")
            })?
            .1
            .clone();
        let teams = seen
            .iter()
            .find(|(path, _)| path.contains("teams"))?
            .1
            .clone();
        Some((slack, teams))
    })
    .await;
    assert!(slack_body["text"]
        .as_str()
        .unwrap()
        .contains("notification.test"));
    assert_eq!(slack_body["blocks"][0]["type"], "header");
    assert_eq!(teams_body["type"], "message");
    let card = &teams_body["attachments"][0]["content"];
    assert_eq!(card["type"], "AdaptiveCard");
    assert!(card.to_string().contains("device.enrolled"));
    // The Teams channel is subscribed to device.enrolled only.
    let teams_types: Vec<String> = deliveries(&router, org.id, &owner, teams.id)
        .await
        .into_iter()
        .map(|row| row.event_type)
        .collect();
    assert_eq!(teams_types, vec!["device.enrolled"]);

    // Cross-org: another organisation cannot test, schedule or list it.
    for (method, path, payload) in [
        (
            Method::POST,
            format!(
                "/v1/orgs/{}/notification-channels/{}/test",
                other.id, created.id
            ),
            serde_json::Value::Null,
        ),
        (
            Method::PUT,
            format!(
                "/v1/orgs/{}/notification-channels/{}/schedule",
                other.id, created.id
            ),
            serde_json::json!({"digest_minutes": 0}),
        ),
    ] {
        assert_eq!(
            call(&router, method, &path, payload, Some(&other_owner))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        call(
            &router,
            Method::POST,
            &format!(
                "/v1/orgs/{}/notification-channels/{}/test",
                org.id, created.id
            ),
            serde_json::Value::Null,
            Some(&other_owner),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &router,
            Method::POST,
            &format!(
                "/v1/orgs/{}/notification-channels/{}/test",
                org.id, created.id
            ),
            serde_json::Value::Null,
            Some(&member),
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );

    // A failing endpoint records an error without the secret URL path.
    let failing: crate::webhooks::WebhookDestination = body(
        create_channel(
            &router,
            org.id,
            &owner,
            serde_json::json!({
                "kind": "slack",
                "name": "broken",
                "url": format!("http://{addr}/services/fail-secret-path"),
                "event_types": ["policy.published"],
                "residency_acknowledged": true,
            }),
        )
        .await,
    )
    .await;
    call(
        &router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/notification-channels/{}/test",
            org.id, failing.id
        ),
        serde_json::Value::Null,
        Some(&owner),
    )
    .await;
    let last_error = loop {
        let rows = deliveries(&router, org.id, &owner, failing.id).await;
        if let Some(error) = rows.first().and_then(|row| row.last_error.clone()) {
            break error;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(last_error.contains("500"), "{last_error}");
    assert!(!last_error.contains("secret-path"), "{last_error}");

    // Disabling a channel drops the sealed URL; audit never held it.
    assert_eq!(
        call(
            &router,
            Method::DELETE,
            &format!("/v1/orgs/{}/webhooks/{}", org.id, created.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let sealed: Option<String> =
        sqlx::query_scalar("SELECT target_sealed FROM webhook_destinations WHERE id=$1")
            .bind(created.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(sealed.is_none());
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT details_json FROM audit_events WHERE org_id=$1 AND action LIKE 'notification_channel.%'",
    )
    .bind(org.id.to_string())
    .fetch_all(&store.pool)
    .await
    .unwrap();
    assert!(audit.len() >= 4);
    assert!(audit.iter().all(|details| !details.contains("secret-path")));
}

#[tokio::test]
async fn email_channel_sends_through_the_relay_with_quiet_hours_and_digest() {
    set_smtp_for_test(None);
    let (port, mailbox) = smtp_mock().await;
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "email-channels").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    let email = serde_json::json!({
        "kind": "email",
        "name": "ops-email",
        "recipients": ["Ops@Example.org.au"],
    });
    // Email is refused until the operator configures a relay.
    let refused = create_channel(&router, org.id, &admin, email.clone()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    set_smtp_for_test(Some(SmtpConfig {
        host: "127.0.0.1".into(),
        port,
        tls: SmtpTls::None,
        username: None,
        password: None,
        from: "BlakTail <alerts@example.org.au>".parse().unwrap(),
        ca_pem: None,
    }));
    let capabilities: serde_json::Value = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/notification-channels/capabilities", org.id),
            serde_json::Value::Null,
            Some(&admin),
        )
        .await,
    )
    .await;
    assert_eq!(capabilities["email_configured"], true);
    assert_eq!(capabilities["default_timezone"], "Australia/Sydney");
    assert_eq!(
        create_channel(&router, org.id, &member, email.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut bad = email.clone();
    bad["recipients"] = serde_json::json!(["not-an-address"]);
    assert_eq!(
        create_channel(&router, org.id, &admin, bad).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Email does not need a residency acknowledgement: the relay is the
    // operator's own.
    let channel = create_channel(&router, org.id, &admin, email).await;
    assert_eq!(channel.status(), StatusCode::CREATED);
    let channel: crate::webhooks::WebhookDestination = body(channel).await;
    assert_eq!(channel.recipients, vec!["ops@example.org.au"]);

    // Test send arrives at once.
    call(
        &router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/notification-channels/{}/test",
            org.id, channel.id
        ),
        serde_json::Value::Null,
        Some(&admin),
    )
    .await;
    let first = wait_for(|| mailbox.lock().unwrap().first().cloned()).await;
    assert!(first.contains("Subject: [BlakTail] test notification.test - email-channels"));
    assert!(first.contains("To: ops@example.org.au"));
    assert!(!first.contains("btw_") && !first.contains("bte1."));

    // Quiet hours around "now" in Sydney hold back info events, never
    // warnings.
    let sydney = chrono_tz::Australia::Sydney;
    let local = chrono::Utc::now().with_timezone(&sydney);
    let minute = |offset: i64| {
        let value = (i64::from(chrono::Timelike::hour(&local)) * 60
            + i64::from(chrono::Timelike::minute(&local))
            + offset)
            .rem_euclid(1440);
        format!("{:02}:{:02}", value / 60, value % 60)
    };
    let schedule = call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/notification-channels/{}/schedule", org.id, channel.id),
        serde_json::json!({"quiet_hours": {"start": minute(-60), "end": minute(60)}, "digest_minutes": 0}),
        Some(&admin),
    )
    .await;
    assert_eq!(schedule.status(), StatusCode::OK);
    let node = register_test_node(&router, org.id, &owner, "office-1", "office-key", &[]).await;
    assert_eq!(
        call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/nodes/{}/tombstone", org.id, node.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let critical = wait_for(|| {
        mailbox
            .lock()
            .unwrap()
            .iter()
            .find(|message| message.contains("device.deleted"))
            .cloned()
    })
    .await;
    assert!(critical.contains("Subject: [BlakTail] warning device.deleted"));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let held = deliveries(&router, org.id, &owner, channel.id).await;
    let enrolled = held
        .iter()
        .find(|row| row.event_type == "device.enrolled")
        .expect("enrolled row");
    assert!(enrolled.delivered_at.is_none());
    let next_attempt: i64 =
        sqlx::query_scalar("SELECT next_attempt_at FROM webhook_outbox WHERE id=$1")
            .bind(enrolled.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(next_attempt > now() + 30 * 60, "held until quiet hours end");
    assert!(!mailbox
        .lock()
        .unwrap()
        .iter()
        .any(|message| message.contains("device.enrolled")));

    // Quiet hours off, digest on: held info events go out as one message
    // once their digest window has passed.
    assert_eq!(
        call(
            &router,
            Method::PUT,
            &format!(
                "/v1/orgs/{}/notification-channels/{}/schedule",
                org.id, channel.id
            ),
            serde_json::json!({"digest_minutes": 15}),
            Some(&admin),
        )
        .await
        .status(),
        StatusCode::OK
    );
    sqlx::query(
        "UPDATE webhook_outbox SET created_at=$1,next_attempt_at=$2 WHERE destination_id=$3 AND delivered_at IS NULL",
    )
    .bind(now() - 20 * 60)
    .bind(now())
    .bind(channel.id.to_string())
    .execute(&store.pool)
    .await
    .unwrap();
    let digest = wait_for(|| {
        mailbox
            .lock()
            .unwrap()
            .iter()
            .find(|message| message.contains("notifications - email-channels"))
            .cloned()
    })
    .await;
    assert!(digest.contains("device.enrolled"));
    assert!(digest.contains("join_key.used"));
    let pending = deliveries(&router, org.id, &owner, channel.id)
        .await
        .into_iter()
        .filter(|row| row.delivered_at.is_none())
        .count();
    assert_eq!(pending, 0);
    set_smtp_for_test(None);
}
