mod admin;
pub mod connectors;
pub mod flows;
pub mod https_fallback;
pub mod https_services;
pub mod ipam;
mod metrics;
mod org_dns;
mod shares;
pub mod tailnet_lock;
mod webhooks;
mod wg_only;

pub use metrics::CoordMetrics;
pub use org_dns::{check_dns_document, DnsCheckReport};

#[derive(Debug, Serialize)]
pub struct PolicyCheckReport {
    pub version: u32,
    pub defaults: &'static str,
    pub groups: usize,
    pub hosts: usize,
    pub rules: usize,
    pub ssh: usize,
    pub tests: usize,
    pub tag_owners: usize,
}

pub fn check_policy_document(document: &str) -> Result<PolicyCheckReport, String> {
    let acl: Acl = serde_json::from_str(document).map_err(|error| error.to_string())?;
    acl.validate().map_err(|error| error.to_string())?;
    Ok(PolicyCheckReport {
        version: acl.version,
        defaults: acl.defaults.as_str(),
        groups: acl.groups.len(),
        hosts: acl.hosts.len(),
        rules: acl.rules.len(),
        ssh: acl.ssh.len(),
        tests: acl.tests.len(),
        tag_owners: acl.tag_owners.len(),
    })
}

use axum::{
    extract::{MatchedPath, Path as UrlPath, Query, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    any::{install_default_drivers, AnyPoolOptions},
    AnyConnection, AnyPool, AssertSqlSafe, Row,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

const SCHEMA: &str = include_str!("../schema.sql");
pub const CURRENT_SCHEMA_VERSION: i64 = 18;
const MAX_CONTROL_UPDATE_WAIT_SECS: u64 = 25;
const MAX_CONTROL_VIEWS: usize = 10_000;
type ControlViewMap = HashMap<Uuid, (i64, BTreeSet<Uuid>)>;
const DEFAULT_AUDIT_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
const DEFAULT_TOMBSTONE_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
const NODE_ONLINE_SECS: i64 = 90;
const EPHEMERAL_OFFLINE_SECS: i64 = 24 * 60 * 60;
const DEFAULT_NODE_KEY_TTL_SECS: i64 = 90 * 24 * 60 * 60;
const MIN_NODE_KEY_TTL_SECS: i64 = 24 * 60 * 60;
const MAX_NODE_KEY_TTL_SECS: i64 = 365 * 24 * 60 * 60;
const DEVICE_AUTH_TTL_SECS: i64 = 10 * 60;
const DEVICE_AUTH_POLL_SECS: u64 = 2;
const MAX_PENDING_DEVICE_AUTHS: i64 = 1_000;
const MAX_FRIENDLY_NAME_CHARS: usize = 64;
const DEFAULT_CONSOLE_URL: &str = "https://console.invalid";
const CONSOLE_ASSERTION_ISSUER: &str = "blaktail-console";
const CONSOLE_ASSERTION_AUDIENCE: &str = "blaktail-coord";
const MAX_CONSOLE_ASSERTION_LIFETIME_SECS: i64 = 60;
const CONSOLE_ASSERTION_CLOCK_SKEW_SECS: i64 = 5;
const BOOTSTRAP_RESERVATION_TTL_SECS: i64 = 60 * 60;
const POSTGRES_MIGRATION_LOCK: i64 = 0x424c_414b_5441_494c;
pub(crate) const ADMIN_API_MAX_BODY_BYTES: usize = 64 * 1024;
pub(crate) const ADMIN_API_RATE_LIMIT: u32 = 120;
pub(crate) const ADMIN_API_RATE_WINDOW_SECS: i64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

#[derive(Clone)]
pub struct Store {
    pub(crate) pool: AnyPool,
    backend: DatabaseBackend,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(
        "database schema version {found} is newer than this coordinator supports ({supported}); upgrade blaktail-coord"
    )]
    UnsupportedSchema { found: i64, supported: i64 },
    #[error("invalid coordinator migration plan: expected version {expected}, found {found}")]
    InvalidMigrationPlan { expected: i64, found: i64 },
    #[error("invalid SQLite database path: {0}")]
    InvalidDatabasePath(String),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

struct Migration {
    version: i64,
    name: &'static str,
    postgres_sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "consolidated baseline",
        postgres_sql: include_str!("../migrations/postgres/0001_baseline.sql"),
    },
    Migration {
        version: 2,
        name: "friendly device names",
        postgres_sql: include_str!("../migrations/postgres/0002_friendly_device_names.sql"),
    },
    Migration {
        version: 3,
        name: "console assertion replay protection",
        postgres_sql: include_str!("../migrations/postgres/0003_console_assertion_nonces.sql"),
    },
    Migration {
        version: 4,
        name: "bootstrap reservations and device poll throttling",
        postgres_sql: include_str!("../migrations/postgres/0004_bootstrap_and_poll_throttling.sql"),
    },
    Migration {
        version: 5,
        name: "device inventory, audit retention, and automation clients",
        postgres_sql: include_str!("../migrations/postgres/0005_inventory_admin_api.sql"),
    },
    Migration {
        version: 6,
        name: "organisation DNS settings",
        postgres_sql: include_str!("../migrations/postgres/0006_org_dns.sql"),
    },
    Migration {
        version: 7,
        name: "wireguard-only peers",
        postgres_sql: include_str!("../migrations/postgres/0007_wireguard_only_peers.sql"),
    },
    Migration {
        version: 8,
        name: "organisation control revision",
        postgres_sql: include_str!("../migrations/postgres/0008_control_revision.sql"),
    },
    Migration {
        version: 9,
        name: "oauth access tokens",
        postgres_sql: include_str!("../migrations/postgres/0009_oauth_access_tokens.sql"),
    },
    Migration {
        version: 10,
        name: "policy revision and previous document",
        postgres_sql: include_str!("../migrations/postgres/0010_acl_revision.sql"),
    },
    Migration {
        version: 11,
        name: "organisation webhook destinations and outbox",
        postgres_sql: include_str!("../migrations/postgres/0011_webhooks.sql"),
    },
    Migration {
        version: 12,
        name: "wireguard-only public-key overlap rotation",
        postgres_sql: include_str!("../migrations/postgres/0012_wg_only_overlap.sql"),
    },
    Migration {
        version: 13,
        name: "node shares and applied DNS revision",
        postgres_sql: include_str!("../migrations/postgres/0013_shares_and_dns_applied.sql"),
    },
    Migration {
        version: 14,
        name: "organisation IPAM pools and reservations",
        postgres_sql: include_str!("../migrations/postgres/0014_ipam.sql"),
    },
    Migration {
        version: 15,
        name: "opt-in flow visibility settings and records",
        postgres_sql: include_str!("../migrations/postgres/0015_flows.sql"),
    },
    Migration {
        version: 16,
        name: "domain application connectors",
        postgres_sql: include_str!("../migrations/postgres/0016_connectors.sql"),
    },
    Migration {
        version: 17,
        name: "private HTTPS services and CSRs",
        postgres_sql: include_str!("../migrations/postgres/0017_https_services.sql"),
    },
    Migration {
        version: 18,
        name: "tailnet lock admission roots",
        postgres_sql: include_str!("../migrations/postgres/0018_tailnet_lock.sql"),
    },
];

impl Store {
    /// Opens a database and applies pending migrations. Operator-controlled
    /// migration commands use this; service startup must use `open_existing`.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let pool = connect_sqlite(path.as_ref(), true).await?;
        apply_sqlite_migrations(&pool).await?;
        configure_sqlite(&pool).await?;
        Ok(Self {
            pool,
            backend: DatabaseBackend::Sqlite,
        })
    }

    /// Opens an already-migrated database without creating or changing schema.
    pub async fn open_existing(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let pool = connect_sqlite(path.as_ref(), false).await?;
        validate_schema_version(&pool, DatabaseBackend::Sqlite).await?;
        configure_sqlite(&pool).await?;
        Ok(Self {
            pool,
            backend: DatabaseBackend::Sqlite,
        })
    }

    /// Applies PostgreSQL migrations under an advisory lock so multiple
    /// deployment jobs cannot race schema changes.
    pub async fn migrate_postgres(database_url: &str) -> Result<Self, StoreError> {
        let pool = connect_postgres(database_url).await?;
        apply_postgres_migrations(&pool).await?;
        Ok(Self {
            pool,
            backend: DatabaseBackend::Postgres,
        })
    }

    /// Opens PostgreSQL without mutating schema. Service replicas use this.
    pub async fn open_existing_postgres(database_url: &str) -> Result<Self, StoreError> {
        let pool = connect_postgres(database_url).await?;
        validate_schema_version(&pool, DatabaseBackend::Postgres).await?;
        Ok(Self {
            pool,
            backend: DatabaseBackend::Postgres,
        })
    }

    pub async fn readiness(&self) -> Result<(), StoreError> {
        validate_schema_version(&self.pool, self.backend).await?;
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orgs")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn memory() -> Result<Self, StoreError> {
        install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        apply_sqlite_migrations(&pool).await?;
        configure_sqlite(&pool).await?;
        Ok(Self {
            pool,
            backend: DatabaseBackend::Sqlite,
        })
    }
}

async fn connect_sqlite(path: &Path, create: bool) -> Result<AnyPool, StoreError> {
    install_default_drivers();
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().map_err(sqlx::Error::Io)?.join(path)
    };
    let file_url = url::Url::from_file_path(&absolute)
        .map_err(|_| StoreError::InvalidDatabasePath(absolute.display().to_string()))?;
    let suffix = file_url
        .as_str()
        .strip_prefix("file://")
        .expect("file URL has file scheme");
    let mode = if create { "rwc" } else { "rw" };
    let url = format!("sqlite://{suffix}?mode={mode}");
    Ok(AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?)
}

async fn connect_postgres(database_url: &str) -> Result<AnyPool, StoreError> {
    install_default_drivers();
    Ok(AnyPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?)
}

async fn configure_sqlite(pool: &AnyPool) -> Result<(), StoreError> {
    sqlx::raw_sql("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")
        .execute(pool)
        .await?;
    Ok(())
}

async fn schema_version(pool: &AnyPool, backend: DatabaseBackend) -> Result<i64, StoreError> {
    match backend {
        DatabaseBackend::Sqlite => Ok(sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(pool)
            .await?),
        DatabaseBackend::Postgres => Ok(sqlx::query_scalar(
            "SELECT COALESCE(MAX(version),0) FROM coordinator_schema_migrations",
        )
        .fetch_one(pool)
        .await?),
    }
}

async fn validate_schema_version(
    pool: &AnyPool,
    backend: DatabaseBackend,
) -> Result<(), StoreError> {
    let found = if backend == DatabaseBackend::Postgres {
        let rows =
            sqlx::query("SELECT version FROM coordinator_schema_migrations ORDER BY version")
                .fetch_all(pool)
                .await?;
        let versions = rows
            .iter()
            .map(|row| row.try_get::<i64, _>(0))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, version) in versions.iter().enumerate() {
            let expected = index as i64 + 1;
            if *version != expected {
                return Err(StoreError::InvalidMigrationPlan {
                    expected,
                    found: *version,
                });
            }
        }
        versions.last().copied().unwrap_or(0)
    } else {
        schema_version(pool, backend).await?
    };
    if found > CURRENT_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if found != CURRENT_SCHEMA_VERSION {
        return Err(StoreError::InvalidMigrationPlan {
            expected: CURRENT_SCHEMA_VERSION,
            found,
        });
    }
    Ok(())
}

async fn apply_sqlite_migrations(pool: &AnyPool) -> Result<(), StoreError> {
    let found: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await?;
    if found > CURRENT_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }

    let mut applied = found;
    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version > found)
    {
        let expected = applied + 1;
        if migration.version != expected {
            return Err(StoreError::InvalidMigrationPlan {
                expected,
                found: migration.version,
            });
        }
        let mut tx = pool.begin().await?;
        match migration.version {
            1 => migrate_sqlite_to_v1(&mut tx).await?,
            2 => migrate_sqlite_to_v2(&mut tx).await?,
            3 => migrate_sqlite_to_v3(&mut tx).await?,
            4 => migrate_sqlite_to_v4(&mut tx).await?,
            5 => migrate_sqlite_to_v5(&mut tx).await?,
            6 => migrate_sqlite_to_v6(&mut tx).await?,
            7 => migrate_sqlite_to_v7(&mut tx).await?,
            8 => migrate_sqlite_to_v8(&mut tx).await?,
            9 => migrate_sqlite_to_v9(&mut tx).await?,
            10 => migrate_sqlite_to_v10(&mut tx).await?,
            11 => migrate_sqlite_to_v11(&mut tx).await?,
            12 => migrate_sqlite_to_v12(&mut tx).await?,
            13 => migrate_sqlite_to_v13(&mut tx).await?,
            14 => migrate_sqlite_to_v14(&mut tx).await?,
            15 => migrate_sqlite_to_v15(&mut tx).await?,
            16 => migrate_sqlite_to_v16(&mut tx).await?,
            17 => migrate_sqlite_to_v17(&mut tx).await?,
            18 => migrate_sqlite_to_v18(&mut tx).await?,
            found => {
                return Err(StoreError::InvalidMigrationPlan { expected, found });
            }
        }
        let version_sql = match migration.version {
            1 => "PRAGMA user_version=1",
            2 => "PRAGMA user_version=2",
            3 => "PRAGMA user_version=3",
            4 => "PRAGMA user_version=4",
            5 => "PRAGMA user_version=5",
            6 => "PRAGMA user_version=6",
            7 => "PRAGMA user_version=7",
            8 => "PRAGMA user_version=8",
            9 => "PRAGMA user_version=9",
            10 => "PRAGMA user_version=10",
            11 => "PRAGMA user_version=11",
            12 => "PRAGMA user_version=12",
            13 => "PRAGMA user_version=13",
            14 => "PRAGMA user_version=14",
            15 => "PRAGMA user_version=15",
            16 => "PRAGMA user_version=16",
            17 => "PRAGMA user_version=17",
            18 => "PRAGMA user_version=18",
            found => {
                return Err(StoreError::InvalidMigrationPlan { expected, found });
            }
        };
        sqlx::raw_sql(version_sql).execute(&mut *tx).await?;
        tx.commit().await?;
        info!(
            version = migration.version,
            name = migration.name,
            "coordinator database migration applied"
        );
        applied = migration.version;
    }
    if applied != CURRENT_SCHEMA_VERSION {
        return Err(StoreError::InvalidMigrationPlan {
            expected: CURRENT_SCHEMA_VERSION,
            found: applied,
        });
    }
    Ok(())
}

async fn apply_postgres_migrations(pool: &AnyPool) -> Result<(), StoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(POSTGRES_MIGRATION_LOCK)
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS coordinator_schema_migrations (
            version BIGINT PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at BIGINT NOT NULL
        )",
    )
    .execute(&mut *tx)
    .await?;
    let rows = sqlx::query("SELECT version FROM coordinator_schema_migrations ORDER BY version")
        .fetch_all(&mut *tx)
        .await?;
    let versions = rows
        .iter()
        .map(|row| row.try_get::<i64, _>(0))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, version) in versions.iter().enumerate() {
        let expected = index as i64 + 1;
        if *version != expected {
            return Err(StoreError::InvalidMigrationPlan {
                expected,
                found: *version,
            });
        }
    }
    let found = versions.last().copied().unwrap_or(0);
    if found > CURRENT_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    let mut applied = found;
    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version > found)
    {
        let expected = applied + 1;
        if migration.version != expected {
            return Err(StoreError::InvalidMigrationPlan {
                expected,
                found: migration.version,
            });
        }
        sqlx::raw_sql(migration.postgres_sql)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO coordinator_schema_migrations(version,name,applied_at) VALUES($1,$2,$3)",
        )
        .bind(migration.version)
        .bind(migration.name)
        .bind(now())
        .execute(&mut *tx)
        .await?;
        info!(
            version = migration.version,
            name = migration.name,
            "coordinator database migration applied"
        );
        applied = migration.version;
    }
    if applied != CURRENT_SCHEMA_VERSION {
        return Err(StoreError::InvalidMigrationPlan {
            expected: CURRENT_SCHEMA_VERSION,
            found: applied,
        });
    }
    tx.commit().await?;
    Ok(())
}

async fn migrate_sqlite_to_v1(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(SCHEMA).execute(&mut **tx).await?;
    // Version zero includes every pre-runner database. These guarded additions
    // consolidate that historical schema into the version-one baseline.
    ensure_column(tx, "join_keys", "user_id", "TEXT NOT NULL DEFAULT ''").await?;
    ensure_column(
        tx,
        "join_keys",
        "user_role",
        "TEXT NOT NULL DEFAULT 'owner'",
    )
    .await?;
    ensure_column(tx, "join_keys", "tags_json", "TEXT NOT NULL DEFAULT '[]'").await?;
    ensure_column(tx, "nodes", "user_id", "TEXT NOT NULL DEFAULT ''").await?;
    ensure_column(tx, "nodes", "user_role", "TEXT NOT NULL DEFAULT 'owner'").await?;
    ensure_column(tx, "nodes", "tags_json", "TEXT NOT NULL DEFAULT '[]'").await?;
    ensure_column(tx, "nodes", "dns_name", "TEXT NOT NULL DEFAULT ''").await?;
    ensure_column(
        tx,
        "nodes",
        "advertised_routes_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )
    .await?;
    ensure_column(
        tx,
        "nodes",
        "approved_routes_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )
    .await?;
    ensure_column(tx, "nodes", "relay_endpoint", "TEXT").await?;
    ensure_column(tx, "nodes", "relay_endpoint_updated_at", "INTEGER").await?;
    ensure_column(
        tx,
        "orgs",
        "node_key_ttl_seconds",
        "INTEGER NOT NULL DEFAULT 7776000",
    )
    .await?;
    ensure_column(
        tx,
        "nodes",
        "credential_expires_at",
        "INTEGER NOT NULL DEFAULT 0",
    )
    .await?;
    sqlx::query(
        "UPDATE nodes SET credential_expires_at=CAST(created_at AS INTEGER)+(SELECT node_key_ttl_seconds FROM orgs WHERE orgs.id=nodes.org_id) WHERE credential_expires_at=0",
    )
    .execute(&mut **tx)
    .await?;
    normalise_dns_names(tx).await?;
    backfill_ipv6_addresses(tx).await?;
    sqlx::raw_sql(
        "CREATE UNIQUE INDEX IF NOT EXISTS nodes_dns_name_org_idx ON nodes(org_id,dns_name) WHERE dns_name<>''",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v2(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(tx, "nodes", "display_name", "TEXT").await
}

async fn migrate_sqlite_to_v3(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS console_assertion_nonces (
            jti_hash TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS console_assertion_nonces_expiry_idx
            ON console_assertion_nonces(expires_at);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v4(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(tx, "device_authorizations", "last_polled_at", "INTEGER").await?;
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS pending_bootstrap_orgs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            acl_json TEXT NOT NULL CHECK (json_valid(acl_json)),
            node_key_ttl_seconds INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS pending_bootstrap_orgs_expiry_idx
            ON pending_bootstrap_orgs(expires_at);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v5(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(
        tx,
        "orgs",
        "audit_retention_seconds",
        "INTEGER NOT NULL DEFAULT 7776000",
    )
    .await?;
    ensure_column(tx, "nodes", "last_seen_at", "INTEGER").await?;
    ensure_column(tx, "nodes", "os", "TEXT").await?;
    ensure_column(tx, "nodes", "os_version", "TEXT").await?;
    ensure_column(tx, "nodes", "agent_version", "TEXT").await?;
    ensure_column(tx, "nodes", "hostname", "TEXT").await?;
    ensure_column(
        tx,
        "nodes",
        "capabilities_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )
    .await?;
    ensure_column(tx, "nodes", "ephemeral", "INTEGER NOT NULL DEFAULT 0").await?;
    ensure_column(tx, "nodes", "deleted_at", "INTEGER").await?;
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS api_clients (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            scopes_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scopes_json)),
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            expires_at INTEGER,
            revoked_at INTEGER,
            UNIQUE(org_id,name)
        );
        CREATE INDEX IF NOT EXISTS api_clients_org_idx ON api_clients(org_id, revoked_at);
        CREATE TABLE IF NOT EXISTS api_idempotency (
            org_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            request_hash TEXT NOT NULL DEFAULT '',
            status INTEGER NOT NULL,
            body_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (org_id, client_id, key_hash)
        );",
    )
    .execute(&mut **tx)
    .await?;
    ensure_column(
        tx,
        "api_idempotency",
        "request_hash",
        "TEXT NOT NULL DEFAULT ''",
    )
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v6(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(
        tx,
        "orgs",
        "dns_json",
        "TEXT NOT NULL DEFAULT '{\"managed\":true,\"global_resolvers\":[],\"split\":[],\"search_domains\":[],\"records\":[]}'",
    )
    .await?;
    ensure_column(tx, "orgs", "dns_revision", "INTEGER NOT NULL DEFAULT 0").await?;
    ensure_column(tx, "orgs", "dns_previous_json", "TEXT").await?;
    Ok(())
}

async fn migrate_sqlite_to_v7(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS wireguard_only_peers (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'wireguard_only' CHECK (kind = 'wireguard_only'),
            wg_public_key TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            allowed_ips_json TEXT NOT NULL CHECK (json_valid(allowed_ips_json)),
            tags_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags_json)),
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            revoked_at INTEGER,
            revision INTEGER NOT NULL DEFAULT 1
        );
        CREATE UNIQUE INDEX IF NOT EXISTS wireguard_only_peers_org_name_idx
            ON wireguard_only_peers(org_id, name) WHERE revoked_at IS NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS wireguard_only_peers_org_key_idx
            ON wireguard_only_peers(org_id, wg_public_key) WHERE revoked_at IS NULL;
        CREATE INDEX IF NOT EXISTS wireguard_only_peers_org_idx
            ON wireguard_only_peers(org_id, revoked_at);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v8(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(tx, "orgs", "control_revision", "INTEGER NOT NULL DEFAULT 1").await
}

async fn migrate_sqlite_to_v9(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS oauth_access_tokens (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            api_client_id TEXT NOT NULL REFERENCES api_clients(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            scopes_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scopes_json)),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_used_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS oauth_access_tokens_client_idx
            ON oauth_access_tokens(api_client_id, expires_at);
        CREATE INDEX IF NOT EXISTS oauth_access_tokens_org_idx
            ON oauth_access_tokens(org_id, expires_at);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v10(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(tx, "orgs", "acl_revision", "INTEGER NOT NULL DEFAULT 1").await?;
    ensure_column(tx, "orgs", "acl_previous_json", "TEXT").await
}

async fn migrate_sqlite_to_v11(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS webhook_destinations (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            signing_secret TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            secret_prefix TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            UNIQUE(org_id, name)
        );
        CREATE TABLE IF NOT EXISTS webhook_outbox (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            destination_id TEXT NOT NULL REFERENCES webhook_destinations(id) ON DELETE CASCADE,
            event_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
            created_at INTEGER NOT NULL,
            next_attempt_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            delivered_at INTEGER,
            dead_lettered_at INTEGER,
            UNIQUE(destination_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS webhook_outbox_due_idx
            ON webhook_outbox(next_attempt_at, delivered_at, dead_lettered_at);
        CREATE INDEX IF NOT EXISTS webhook_destinations_org_idx
            ON webhook_destinations(org_id, enabled);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v12(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(tx, "wireguard_only_peers", "previous_wg_public_key", "TEXT").await?;
    ensure_column(tx, "wireguard_only_peers", "overlap_until", "INTEGER").await?;
    ensure_column(tx, "wireguard_only_peers", "overlap_peer_id", "TEXT").await?;
    Ok(())
}

async fn migrate_sqlite_to_v13(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    ensure_column(tx, "nodes", "shares_json", "TEXT NOT NULL DEFAULT '[]'").await?;
    ensure_column(
        tx,
        "nodes",
        "dns_applied_revision",
        "INTEGER NOT NULL DEFAULT 0",
    )
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v14(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS ipam_pools (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            cidr TEXT NOT NULL,
            exclusions_json TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            UNIQUE(org_id, name)
        );
        CREATE TABLE IF NOT EXISTS ipam_reservations (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            pool_id TEXT NOT NULL REFERENCES ipam_pools(id) ON DELETE CASCADE,
            address TEXT NOT NULL,
            node_id TEXT,
            enrol_key_hash TEXT,
            state TEXT NOT NULL DEFAULT 'active',
            reason TEXT NOT NULL DEFAULT '',
            expires_at INTEGER,
            created_at INTEGER NOT NULL,
            UNIQUE(pool_id, address)
        );
        CREATE INDEX IF NOT EXISTS ipam_pools_org_idx ON ipam_pools(org_id);
        CREATE INDEX IF NOT EXISTS ipam_reservations_org_idx
            ON ipam_reservations(org_id, state);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v15(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS flow_settings (
            org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
            sampling_rate REAL NOT NULL DEFAULT 1.0,
            retention_days INTEGER NOT NULL DEFAULT 7,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS flow_records (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            service TEXT NOT NULL DEFAULT '',
            start_bucket INTEGER NOT NULL,
            end_bucket INTEGER NOT NULL,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            bytes INTEGER NOT NULL DEFAULT 0,
            packets INTEGER NOT NULL DEFAULT 0,
            transport TEXT NOT NULL,
            decision TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS flow_records_org_bucket_idx
            ON flow_records(org_id, start_bucket);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v16(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS domain_apps (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            hostnames_json TEXT NOT NULL DEFAULT '[]',
            ports_json TEXT NOT NULL DEFAULT '[]',
            protocols_json TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            UNIQUE(org_id, name)
        );
        CREATE TABLE IF NOT EXISTS app_connector_assignments (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            app_id TEXT NOT NULL REFERENCES domain_apps(id) ON DELETE CASCADE,
            node_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(app_id, node_id)
        );
        CREATE TABLE IF NOT EXISTS app_resolutions (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            app_id TEXT NOT NULL REFERENCES domain_apps(id) ON DELETE CASCADE,
            host TEXT NOT NULL,
            addrs_json TEXT NOT NULL DEFAULT '[]',
            resolved_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS app_resolutions_app_host_idx
            ON app_resolutions(app_id, host, resolved_at);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v17(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS org_services (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL,
            target_node TEXT NOT NULL,
            port INTEGER NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(org_id, service_name)
        );
        CREATE TABLE IF NOT EXISTS service_csrs (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL,
            target_node TEXT NOT NULL,
            csr_pem TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS service_csrs_org_service_idx
            ON service_csrs(org_id, service_name, created_at);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn migrate_sqlite_to_v18(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS org_admission_roots (
            org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
            secret_hash TEXT NOT NULL,
            epoch INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            rotated_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS admission_signatures (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            node_id TEXT NOT NULL,
            pubkey_b64 TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            valid_from INTEGER NOT NULL,
            valid_to INTEGER NOT NULL,
            signature TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(org_id, node_id, epoch)
        );
        CREATE INDEX IF NOT EXISTS admission_signatures_org_idx
            ON admission_signatures(org_id, valid_to);",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn normalise_dns_names(tx: &mut sqlx::Transaction<'_, sqlx::Any>) -> Result<(), sqlx::Error> {
    let rows =
        sqlx::query("SELECT id,org_id,name,dns_name FROM nodes ORDER BY org_id,created_at,id")
            .fetch_all(&mut **tx)
            .await?;
    let mut used = std::collections::HashSet::new();
    for row in rows {
        let id: String = row.try_get(0)?;
        let org_id: String = row.try_get(1)?;
        let name: String = row.try_get(2)?;
        let current: String = row.try_get(3)?;
        let base = magic_dns_name(&name, &org_id);
        let mut desired = base.clone();
        if used.contains(&(org_id.clone(), desired.clone())) {
            let id_hash = hash(&id);
            let suffix = format!("-{}", &id_hash[..8]);
            let (label, domain) = base.split_once('.').expect("generated DNS name has domain");
            let keep = 63usize.saturating_sub(suffix.len());
            desired = format!(
                "{}{}.{}",
                label
                    .chars()
                    .take(keep)
                    .collect::<String>()
                    .trim_end_matches('-'),
                suffix,
                domain
            );
        }
        used.insert((org_id, desired.clone()));
        if current != desired {
            sqlx::query("UPDATE nodes SET dns_name=$1 WHERE id=$2")
                .bind(desired)
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
    }
    Ok(())
}

async fn backfill_ipv6_addresses(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query("SELECT id,org_id,allowed_ips_json FROM nodes")
        .fetch_all(&mut **tx)
        .await?;
    for row in rows {
        let node_id: String = row.try_get(0)?;
        let org_id: String = row.try_get(1)?;
        let addresses_json: String = row.try_get(2)?;
        let mut addresses: Vec<String> = serde_json::from_str(&addresses_json).unwrap_or_default();
        if addresses.iter().any(|address| address.contains(':')) {
            continue;
        }
        let Some(host) = assigned_ipv4_host(&addresses) else {
            continue;
        };
        addresses.push(org_ula_address(&org_id, host));
        sqlx::query("UPDATE nodes SET allowed_ips_json=$1 WHERE id=$2")
            .bind(serde_json::to_string(&addresses).unwrap())
            .bind(node_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}
async fn ensure_column(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), sqlx::Error> {
    // Every identifier and definition comes from the static migration plan.
    let rows = sqlx::query(AssertSqlSafe(format!("PRAGMA table_info({table})")))
        .fetch_all(&mut **tx)
        .await?;
    let names = rows
        .iter()
        .map(|row| row.try_get::<String, _>(1))
        .collect::<Result<Vec<_>, _>>()?;
    if !names.iter().any(|name| name == column) {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )))
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
#[derive(Clone, Default)]
pub(crate) struct ApiRateLimiter {
    inner: Arc<Mutex<HashMap<String, Vec<i64>>>>,
}

impl ApiRateLimiter {
    pub(crate) fn allow(&self, key: &str, now: i64, limit: u32, window_secs: i64) -> bool {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stamps = map.entry(key.to_owned()).or_default();
        stamps.retain(|stamp| now.saturating_sub(*stamp) < window_secs);
        if stamps.len() as u32 >= limit {
            return false;
        }
        stamps.push(now);
        true
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Store,
    metrics: Arc<CoordMetrics>,
    auth_hmac_secret: Arc<[u8]>,
    relay_auth_secret: Arc<[u8]>,
    /// Advertised relay endpoints (host:port, UDP) handed to nodes.
    relays: Arc<Vec<String>>,
    console_url: Arc<String>,
    api_rate: ApiRateLimiter,
    control_views: Arc<Mutex<ControlViewMap>>,
}
pub fn app(store: Store, region: String, auth_hmac_secret: impl Into<Vec<u8>>) -> Router {
    app_with_relays_and_console(
        store,
        region,
        auth_hmac_secret,
        Vec::<u8>::new(),
        Vec::new(),
        DEFAULT_CONSOLE_URL.into(),
    )
}
pub fn app_with_relays(
    store: Store,
    region: String,
    auth_hmac_secret: impl Into<Vec<u8>>,
    relay_auth_secret: impl Into<Vec<u8>>,
    relays: Vec<String>,
) -> Router {
    app_with_relays_and_console(
        store,
        region,
        auth_hmac_secret,
        relay_auth_secret,
        relays,
        DEFAULT_CONSOLE_URL.into(),
    )
}
pub fn app_with_relays_and_console(
    store: Store,
    region: String,
    auth_hmac_secret: impl Into<Vec<u8>>,
    relay_auth_secret: impl Into<Vec<u8>>,
    relays: Vec<String>,
    console_url: String,
) -> Router {
    app_with_relays_console_and_metrics(
        store,
        region,
        auth_hmac_secret,
        relay_auth_secret,
        relays,
        console_url,
        Arc::new(CoordMetrics::default()),
    )
}

pub fn app_with_relays_console_and_metrics(
    store: Store,
    _region: String,
    auth_hmac_secret: impl Into<Vec<u8>>,
    relay_auth_secret: impl Into<Vec<u8>>,
    relays: Vec<String>,
    console_url: String,
    metrics: Arc<CoordMetrics>,
) -> Router {
    let state = AppState {
        store,
        metrics,
        auth_hmac_secret: auth_hmac_secret.into().into(),
        relay_auth_secret: relay_auth_secret.into().into(),
        relays: Arc::new(relays),
        console_url: Arc::new(console_url.trim_end_matches('/').to_owned()),
        api_rate: ApiRateLimiter::default(),
        control_views: Arc::new(Mutex::new(HashMap::new())),
    };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tokio::spawn(webhooks::delivery_loop(state.clone()));
    Router::new()
        .route("/health", get(readiness))
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness))
        .route(
            "/v1/device-authorizations",
            post(create_device_authorization),
        )
        .route(
            "/v1/device-authorizations/:device_code",
            get(poll_device_authorization),
        )
        .route("/v1/orgs", post(prepare_org))
        .route("/v1/orgs/:org_id/bootstrap-commit", post(commit_org))
        .route("/v1/orgs/:org_id/join-keys", post(mint_join_key))
        .route(
            "/v1/orgs/:org_id/device-authorizations/:user_code",
            get(get_device_authorization).post(approve_device_authorization),
        )
        .route("/v1/orgs/:org_id/nodes", get(list_nodes))
        .route("/v1/orgs/:org_id/nodes/:node_id", delete(admin_revoke_node))
        .route(
            "/v1/orgs/:org_id/nodes/:node_id/tombstone",
            post(admin_tombstone_node),
        )
        .route(
            "/v1/orgs/:org_id/nodes/:node_id/friendly-name",
            put(update_node_friendly_name),
        )
        .route(
            "/v1/orgs/:org_id/nodes/:node_id/routes",
            put(approve_node_routes),
        )
        .route("/v1/orgs/:org_id/acl", get(get_acl))
        .route("/v1/orgs/:org_id/acl", put(put_acl))
        .route("/v1/orgs/:org_id/dns", get(get_dns).put(put_dns))
        .route(
            "/v1/orgs/:org_id/wireguard-only-peers",
            get(wg_only::list_console).post(wg_only::create_console),
        )
        .route(
            "/v1/orgs/:org_id/wireguard-only-peers/:peer_id",
            get(wg_only::get_console).delete(wg_only::revoke_console),
        )
        .route(
            "/v1/orgs/:org_id/wireguard-only-peers/:peer_id/rotate",
            post(wg_only::rotate_console),
        )
        .route("/v1/orgs/:org_id/security", get(get_security_policy))
        .route("/v1/orgs/:org_id/security", put(put_security_policy))
        .route("/v1/orgs/:org_id/audit", get(list_audit_events))
        .route(
            "/v1/orgs/:org_id/api-clients",
            get(admin::list_api_clients).post(admin::create_api_client),
        )
        .route(
            "/v1/orgs/:org_id/api-clients/:client_id",
            delete(admin::revoke_api_client),
        )
        .route(
            "/v1/orgs/:org_id/webhooks",
            get(webhooks::list_destinations_console).post(webhooks::create_destination_console),
        )
        .route(
            "/v1/orgs/:org_id/webhooks/events",
            post(webhooks::enqueue_console_event),
        )
        .route(
            "/v1/orgs/:org_id/webhooks/:destination_id",
            delete(webhooks::delete_destination_console),
        )
        .route(
            "/v1/orgs/:org_id/webhooks/:destination_id/deliveries",
            get(webhooks::list_deliveries_console),
        )
        .route(
            "/v1/orgs/:org_id/webhooks/deliveries/:delivery_id/replay",
            post(webhooks::replay_delivery_console),
        )
        .merge(admin::api_routes())
        .route("/oauth/token", post(admin::oauth_token))
        .route("/v1/nodes/register", post(register_node))
        .route("/v1/nodes/:node_id/reauth", post(reauth_node))
        .route("/v1/nodes/:node_id/peers", get(list_peers))
        .route("/v1/nodes/:node_id/updates", get(list_updates))
        .route("/v1/nodes/:node_id/routes", put(update_advertised_routes))
        .route("/v1/nodes/:node_id/shares", put(update_node_shares))
        .route(
            "/v1/nodes/:node_id/relay-endpoint",
            put(update_relay_endpoint),
        )
        .route("/v1/nodes/:node_id", delete(revoke_node))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            record_metrics,
        ))
        .with_state(state)
}

#[derive(Clone)]
struct MetricsState {
    store: Store,
    metrics: Arc<CoordMetrics>,
    diagnostics_token: Arc<[u8]>,
}

pub fn metrics_app(store: Store, metrics: Arc<CoordMetrics>) -> Router {
    metrics_app_with_token(store, metrics, None)
}

pub fn metrics_app_with_token(
    store: Store,
    metrics: Arc<CoordMetrics>,
    diagnostics_token: Option<Vec<u8>>,
) -> Router {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/diagnostics/readiness", get(private_readiness))
        .with_state(MetricsState {
            store,
            metrics,
            diagnostics_token: diagnostics_token.unwrap_or_default().into(),
        })
}

async fn prometheus_metrics(
    State(state): State<MetricsState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require_diagnostics_authorization(&headers, &state.diagnostics_token)?;
    let active_nodes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE revoked_at IS NULL AND credential_expires_at>$1",
    )
    .bind(now())
    .fetch_one(&state.store.pool)
    .await?;
    Ok((
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render(active_nodes.max(0) as u64),
    ))
}

async fn private_readiness(
    State(state): State<MetricsState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require_diagnostics_authorization(&headers, &state.diagnostics_token)?;
    state
        .store
        .readiness()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(serde_json::json!({
        "status": "ready",
        "database": "ok",
        "schema_version": CURRENT_SCHEMA_VERSION,
    })))
}

fn require_diagnostics_authorization(headers: &HeaderMap, expected: &[u8]) -> Result<(), ApiError> {
    if expected.is_empty() {
        return Ok(());
    }
    let candidate = headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let mut expected_mac =
        Hmac::<Sha256>::new_from_slice(expected).map_err(|_| ApiError::Unauthorized)?;
    expected_mac.update(b"blaktail-private-diagnostics");
    let expected_digest = expected_mac.finalize().into_bytes();
    let mut candidate_mac =
        Hmac::<Sha256>::new_from_slice(candidate.as_bytes()).map_err(|_| ApiError::Unauthorized)?;
    candidate_mac.update(b"blaktail-private-diagnostics");
    candidate_mac
        .verify_slice(&expected_digest)
        .map_err(|_| ApiError::Unauthorized)
}

async fn record_metrics(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let operation = request.extensions().get::<MatchedPath>().and_then(|path| {
        match (request.method(), path.as_str()) {
            (&Method::POST, "/v1/nodes/register") => Some(metrics::Operation::Register),
            (&Method::GET, "/v1/nodes/:node_id/peers") => Some(metrics::Operation::Peers),
            (&Method::GET, "/v1/nodes/:node_id/updates") => Some(metrics::Operation::Updates),
            (&Method::DELETE, "/v1/nodes/:node_id")
            | (&Method::DELETE, "/v1/orgs/:org_id/nodes/:node_id") => {
                Some(metrics::Operation::Revoke)
            }
            _ => None,
        }
    });
    let started = Instant::now();
    let response = next.run(request).await;
    if let Some(operation) = operation {
        state
            .metrics
            .record(operation, response.status().as_u16(), started.elapsed());
    }
    response
}
#[derive(Debug, Error)]
pub(crate) enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication failed")]
    Unauthorized,
    #[error("node credential expired; run blaktaild reauth with a fresh join key")]
    CredentialExpired,
    #[error("permission denied")]
    Forbidden,
    #[error("resource not found")]
    NotFound,
    #[error("device authorization expired; run blaktaild up again")]
    Gone,
    #[error("too many pending device authorizations; try again later")]
    TooManyRequests,
    #[error("service unavailable")]
    Unavailable,
    #[error("precondition failed")]
    PreconditionFailed,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("database contains invalid application data")]
    CorruptData,
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::CredentialExpired => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Gone => StatusCode::GONE,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Database(_) | Self::CorruptData => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let code = match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized | Self::CredentialExpired => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Gone => "gone",
            Self::PreconditionFailed => "precondition_failed",
            Self::TooManyRequests => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::Conflict(_) => "conflict",
            Self::Database(_) | Self::CorruptData => "internal_error",
        };
        (
            status,
            Json(serde_json::json!({
                "error": self.to_string(),
                "code": code,
                "message": self.to_string(),
                "request_id": Uuid::new_v4(),
            })),
        )
            .into_response()
    }
}
#[derive(Serialize)]
struct Health {
    status: &'static str,
}
async fn liveness() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn readiness(State(state): State<AppState>) -> Response {
    match state.store.readiness().await {
        Ok(()) => (StatusCode::OK, Json(Health { status: "ready" })).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "unavailable",
            }),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDeviceAuthorization {
    name: String,
    wg_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_url: String,
    expires_at: i64,
    interval_seconds: u64,
}

#[derive(Serialize, Deserialize)]
struct DeviceAuthorizationStatus {
    status: String,
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
struct DeviceAuthorizationPreview {
    name: String,
    public_key_fingerprint: String,
    expires_at: i64,
    approved: bool,
}

struct DeviceAuthorizationPreviewRow {
    name: String,
    public_key: String,
    expires_at: i64,
    approved_at: Option<i64>,
    approved_org: Option<String>,
}

struct DeviceAuthorizationPollRow {
    expires_at: i64,
    approved_at: Option<i64>,
    consumed_at: Option<i64>,
    last_polled_at: Option<i64>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveDeviceAuthorization {
    #[serde(default)]
    tags: Vec<DeviceTag>,
}

#[derive(Serialize, Deserialize)]
struct DeviceAuthorizationApproval {
    status: String,
    expires_at: i64,
}

struct DeviceAuthorizationApprovalRow {
    id: String,
    device_code_hash: String,
    expires_at: i64,
    approved_at: Option<i64>,
    approved_org: Option<String>,
    approved_user: Option<String>,
}

async fn create_device_authorization(
    State(s): State<AppState>,
    Json(input): Json<CreateDeviceAuthorization>,
) -> Result<(StatusCode, Json<DeviceAuthorizationResponse>), ApiError> {
    let name = input.name.trim();
    let public_key = input.wg_public_key.trim();
    if name.is_empty() || public_key.is_empty() || name.chars().count() > 128 {
        return Err(ApiError::BadRequest(
            "name and wg_public_key are required; name must be at most 128 characters".into(),
        ));
    }

    let created_at = now();
    let expires_at = created_at + DEVICE_AUTH_TTL_SECS;
    sqlx::query("DELETE FROM device_authorizations WHERE expires_at<=$1")
        .bind(created_at)
        .execute(&s.store.pool)
        .await?;
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_authorizations WHERE approved_at IS NULL AND expires_at>$1",
    )
    .bind(created_at)
    .fetch_one(&s.store.pool)
    .await?;
    if pending >= MAX_PENDING_DEVICE_AUTHS {
        return Err(ApiError::TooManyRequests);
    }

    for _ in 0..5 {
        let device_code = secret("btd");
        let user_code = user_code();
        let result = sqlx::query(
            "INSERT INTO device_authorizations(id,device_code_hash,user_code_hash,requested_name,wg_public_key,expires_at) VALUES($1,$2,$3,$4,$5,$6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(hash(&device_code))
        .bind(hash(
            &normalise_user_code(&user_code).expect("generated user code is valid"),
        ))
        .bind(name)
        .bind(public_key)
        .bind(expires_at)
        .execute(&s.store.pool)
        .await;
        match result {
            Ok(_) => {
                return Ok((
                    StatusCode::CREATED,
                    Json(DeviceAuthorizationResponse {
                        device_code,
                        user_code: user_code.clone(),
                        verification_url: format!("{}/enroll?code={user_code}", s.console_url),
                        expires_at,
                        interval_seconds: DEVICE_AUTH_POLL_SECS,
                    }),
                ));
            }
            Err(ref error) if is_unique_violation(error) => {}
            Err(error) => return Err(ApiError::Database(error)),
        }
    }
    Err(ApiError::Conflict(
        "could not allocate a unique device authorization code".into(),
    ))
}

async fn poll_device_authorization(
    State(s): State<AppState>,
    UrlPath(device_code): UrlPath<String>,
) -> Result<Response, ApiError> {
    let row = sqlx::query(
        "SELECT expires_at,approved_at,consumed_at,last_polled_at
             FROM device_authorizations WHERE device_code_hash=$1",
    )
    .bind(hash(device_code.trim()))
    .fetch_optional(&s.store.pool)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>(DeviceAuthorizationPollRow {
            expires_at: row.try_get(0)?,
            approved_at: row.try_get(1)?,
            consumed_at: row.try_get(2)?,
            last_polled_at: row.try_get(3)?,
        })
    })
    .transpose()?;
    let row = row.ok_or(ApiError::Unauthorized)?;
    let current_time = now();
    if row.expires_at <= current_time || row.consumed_at.is_some() {
        return Err(ApiError::Gone);
    }
    if row
        .last_polled_at
        .is_some_and(|last| current_time < last + DEVICE_AUTH_POLL_SECS as i64)
    {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", DEVICE_AUTH_POLL_SECS.to_string())],
            Json(serde_json::json!({
                "error":"device authorization polled too quickly",
                "interval_seconds":DEVICE_AUTH_POLL_SECS,
            })),
        )
            .into_response());
    }
    sqlx::query("UPDATE device_authorizations SET last_polled_at=$1 WHERE device_code_hash=$2")
        .bind(current_time)
        .bind(hash(device_code.trim()))
        .execute(&s.store.pool)
        .await?;
    let (status, state) = if row.approved_at.is_some() {
        (StatusCode::OK, "approved")
    } else {
        (StatusCode::ACCEPTED, "pending")
    };
    Ok((
        status,
        Json(DeviceAuthorizationStatus {
            status: state.into(),
            expires_at: row.expires_at,
        }),
    )
        .into_response())
}

async fn get_device_authorization(
    State(s): State<AppState>,
    UrlPath((org_id, user_code)): UrlPath<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<DeviceAuthorizationPreview>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    let code = normalise_user_code(&user_code)
        .ok_or_else(|| ApiError::BadRequest("device code must contain eight characters".into()))?;
    let row = sqlx::query(
            "SELECT requested_name,wg_public_key,expires_at,approved_at,org_id FROM device_authorizations WHERE user_code_hash=$1",
        )
        .bind(hash(&code))
        .fetch_optional(&s.store.pool)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>(DeviceAuthorizationPreviewRow {
                name: row.try_get(0)?,
                public_key: row.try_get(1)?,
                expires_at: row.try_get(2)?,
                approved_at: row.try_get(3)?,
                approved_org: row.try_get(4)?,
            })
        })
        .transpose()?;
    let row = row.ok_or(ApiError::NotFound)?;
    if row.expires_at <= now() {
        return Err(ApiError::Gone);
    }
    if row
        .approved_org
        .as_deref()
        .is_some_and(|id| id != org_id.to_string())
    {
        return Err(ApiError::NotFound);
    }
    Ok(Json(DeviceAuthorizationPreview {
        name: row.name,
        public_key_fingerprint: hash(&row.public_key)[..12].into(),
        expires_at: row.expires_at,
        approved: row.approved_at.is_some(),
    }))
}

async fn approve_device_authorization(
    State(s): State<AppState>,
    UrlPath((org_id, user_code)): UrlPath<(Uuid, String)>,
    headers: HeaderMap,
    Json(input): Json<ApproveDeviceAuthorization>,
) -> Result<Json<DeviceAuthorizationApproval>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    let code = normalise_user_code(&user_code)
        .ok_or_else(|| ApiError::BadRequest("device code must contain eight characters".into()))?;
    let tags = if session.role == Role::Member {
        Vec::new()
    } else {
        canonical_tags(input.tags)
    };
    let acl = load_org_acl(&s.store, org_id).await?;
    authorize_tag_assignment(&acl, &session, &tags)?;
    let mut tx = s.store.pool.begin().await?;
    let approval_query = match s.store.backend {
        DatabaseBackend::Sqlite => "SELECT id,device_code_hash,expires_at,approved_at,org_id,user_id FROM device_authorizations WHERE user_code_hash=$1",
        DatabaseBackend::Postgres => "SELECT id,device_code_hash,expires_at,approved_at,org_id,user_id FROM device_authorizations WHERE user_code_hash=$1 FOR UPDATE",
    };
    let row = sqlx::query(approval_query)
        .bind(hash(&code))
        .fetch_optional(&mut *tx)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>(DeviceAuthorizationApprovalRow {
                id: row.try_get(0)?,
                device_code_hash: row.try_get(1)?,
                expires_at: row.try_get(2)?,
                approved_at: row.try_get(3)?,
                approved_org: row.try_get(4)?,
                approved_user: row.try_get(5)?,
            })
        })
        .transpose()?;
    let row = row.ok_or(ApiError::NotFound)?;
    if row.expires_at <= now() {
        return Err(ApiError::Gone);
    }
    if row.approved_at.is_some() {
        if row.approved_org.as_deref() == Some(&org_id.to_string())
            && row.approved_user.as_deref() == Some(session.user_id.as_str())
        {
            return Ok(Json(DeviceAuthorizationApproval {
                status: "approved".into(),
                expires_at: row.expires_at,
            }));
        }
        return Err(ApiError::Conflict(
            "device authorization was already approved".into(),
        ));
    }
    let join_key_id = Uuid::new_v4();
    let tags_json = serde_json::to_string(&tags).unwrap();
    let inserted = sqlx::query(
        "INSERT INTO join_keys(id,org_id,key_hash,expires_at,single_use,created_at,user_id,user_role,tags_json) SELECT $1,id,$2,$3,1,$4,$5,$6,$7 FROM orgs WHERE id=$8",
    )
    .bind(join_key_id.to_string())
    .bind(&row.device_code_hash)
    .bind(row.expires_at)
    .bind(now())
    .bind(&session.user_id)
    .bind(session.role.as_str())
    .bind(tags_json)
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(conflict("device authorization was already approved"))?
    .rows_affected();
    if inserted != 1 {
        return Err(ApiError::NotFound);
    }
    let changed = sqlx::query(
        "UPDATE device_authorizations SET approved_at=$1,org_id=$2,user_id=$3,user_role=$4,tags_json=$5 WHERE user_code_hash=$6 AND approved_at IS NULL",
    )
    .bind(now())
    .bind(org_id.to_string())
    .bind(&session.user_id)
    .bind(session.role.as_str())
    .bind(serde_json::to_string(&tags).unwrap())
    .bind(hash(&code))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::Conflict(
            "device authorization was already approved".into(),
        ));
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "join_key.minted",
        "join_key",
        Some(&join_key_id.to_string()),
        &serde_json::json!({
            "expires_at": row.expires_at,
            "single_use": true,
            "source": "browser_enrollment",
            "tags": tags,
        }),
    )
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "device_authorization.approved",
        "device_authorization",
        Some(&row.id),
        &serde_json::json!({"join_key_id": join_key_id}),
    )
    .await?;
    tx.commit().await?;
    info!(%org_id, user_id = %session.user_id, "device authorization approved");
    Ok(Json(DeviceAuthorizationApproval {
        status: "approved".into(),
        expires_at: row.expires_at,
    }))
}

#[derive(Deserialize)]
struct CreateOrg {
    id: Uuid,
    name: String,
    #[serde(default = "default_acl")]
    acl: serde_json::Value,
    #[serde(default = "default_node_key_ttl")]
    node_key_ttl_seconds: i64,
}
fn default_acl() -> serde_json::Value {
    serde_json::json!({"version": 1, "defaults": "deny", "rules": []})
}

pub(crate) struct AclRow {
    pub(crate) json: String,
    pub(crate) revision: i64,
    pub(crate) previous: Option<String>,
}

pub(crate) fn storeable_acl_json(mut value: serde_json::Value) -> Result<String, ApiError> {
    if let Some(object) = value.as_object_mut() {
        object.remove("generated");
        object.remove("etag");
        object.remove("revision");
        object.remove("has_previous");
    }
    let acl: Acl = serde_json::from_value(value.clone())
        .map_err(|e| ApiError::BadRequest(format!("invalid ACL: {e}")))?;
    acl.validate()?;
    serde_json::to_string(&value).map_err(|_| ApiError::CorruptData)
}

fn acl_document(row: &AclRow) -> Result<serde_json::Value, ApiError> {
    let mut document: serde_json::Value =
        serde_json::from_str(&row.json).map_err(|_| ApiError::CorruptData)?;
    let acl: Acl = serde_json::from_value(document.clone()).unwrap_or_default();
    if let Some(object) = document.as_object_mut() {
        object
            .entry("defaults")
            .or_insert_with(|| serde_json::Value::String(acl.defaults.as_str().into()));
        if acl.defaults == AclDefaults::SameTag {
            object.insert(
                "generated".into(),
                serde_json::json!([{
                    "kind": "legacy_same_tag",
                    "action": "allow",
                    "applies": ["same_tag", "untagged"],
                    "note": "Implicit same-tag and untagged default. Set defaults to deny to remove it."
                }]),
            );
        } else {
            object.insert("generated".into(), serde_json::json!([]));
        }
        object.insert("etag".into(), serde_json::Value::String(hash(&row.json)));
        object.insert("revision".into(), serde_json::json!(row.revision));
        object.insert(
            "has_previous".into(),
            serde_json::json!(row
                .previous
                .as_deref()
                .is_some_and(|value| !value.is_empty())),
        );
    }
    Ok(document)
}

async fn load_acl_row(store: &Store, org_id: Uuid) -> Result<AclRow, ApiError> {
    let row = sqlx::query("SELECT acl_json,acl_revision,acl_previous_json FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&store.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(AclRow {
        json: row.try_get(0)?,
        revision: row.try_get(1)?,
        previous: row.try_get(2)?,
    })
}

pub(crate) async fn load_acl_row_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
) -> Result<AclRow, ApiError> {
    let row = sqlx::query("SELECT acl_json,acl_revision,acl_previous_json FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(AclRow {
        json: row.try_get(0)?,
        revision: row.try_get(1)?,
        previous: row.try_get(2)?,
    })
}

pub(crate) async fn load_acl_document(
    store: &Store,
    org_id: Uuid,
) -> Result<serde_json::Value, ApiError> {
    acl_document(&load_acl_row(store, org_id).await?)
}

pub(crate) async fn publish_acl_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    current_json: &str,
    next_json: &str,
    revision: i64,
) -> Result<(), ApiError> {
    let changed =
        sqlx::query("UPDATE orgs SET acl_json=$1,acl_revision=$2,acl_previous_json=$3 WHERE id=$4")
            .bind(next_json)
            .bind(revision + 1)
            .bind(current_json)
            .bind(org_id.to_string())
            .execute(&mut **tx)
            .await?
            .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}
fn default_node_key_ttl() -> i64 {
    DEFAULT_NODE_KEY_TTL_SECS
}
#[derive(Serialize, Deserialize)]
struct OrgResponse {
    id: Uuid,
    name: String,
    node_key_ttl_seconds: i64,
}
async fn prepare_org(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateOrg>,
) -> Result<(StatusCode, Json<OrgResponse>), ApiError> {
    service_session(&s, &headers, input.id, "bootstrap.prepare").await?;
    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("org name must not be empty".into()));
    }
    validate_node_key_ttl(input.node_key_ttl_seconds)?;
    let mut acl_value = input.acl.clone();
    if acl_value.get("defaults").is_none() {
        if let Some(object) = acl_value.as_object_mut() {
            object.insert("defaults".into(), serde_json::json!("deny"));
        }
    }
    let acl_json = storeable_acl_json(acl_value)?;
    let current_time = now();
    sqlx::query("DELETE FROM pending_bootstrap_orgs WHERE expires_at<=$1")
        .bind(current_time)
        .execute(&s.store.pool)
        .await?;
    let active = sqlx::query("SELECT name,node_key_ttl_seconds FROM orgs WHERE id=$1")
        .bind(input.id.to_string())
        .fetch_optional(&s.store.pool)
        .await?
        .map(|row| Ok::<_, sqlx::Error>((row.try_get(0)?, row.try_get(1)?)))
        .transpose()?;
    if let Some((existing_name, existing_ttl)) = active {
        if existing_name != name || existing_ttl != input.node_key_ttl_seconds {
            return Err(ApiError::Conflict(
                "organisation id already has different bootstrap settings".into(),
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(OrgResponse {
                id: input.id,
                name: existing_name,
                node_key_ttl_seconds: existing_ttl,
            }),
        ));
    }
    let pending = sqlx::query(
        "SELECT name,acl_json,node_key_ttl_seconds FROM pending_bootstrap_orgs WHERE id=$1",
    )
    .bind(input.id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>((
            row.try_get::<String, _>(0)?,
            row.try_get::<String, _>(1)?,
            row.try_get::<i64, _>(2)?,
        ))
    })
    .transpose()?;
    if let Some((existing_name, existing_acl, existing_ttl)) = pending {
        if existing_name != name
            || existing_acl != acl_json
            || existing_ttl != input.node_key_ttl_seconds
        {
            return Err(ApiError::Conflict(
                "organisation id already has different bootstrap settings".into(),
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(OrgResponse {
                id: input.id,
                name: existing_name,
                node_key_ttl_seconds: existing_ttl,
            }),
        ));
    }
    sqlx::query(
        "INSERT INTO pending_bootstrap_orgs(id,name,acl_json,node_key_ttl_seconds,created_at,expires_at)
         VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(input.id.to_string())
    .bind(name)
    .bind(acl_json)
    .bind(input.node_key_ttl_seconds)
    .bind(current_time)
    .bind(current_time + BOOTSTRAP_RESERVATION_TTL_SECS)
    .execute(&s.store.pool)
    .await
    .map_err(conflict("org name already exists"))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(OrgResponse {
            id: input.id,
            name: name.into(),
            node_key_ttl_seconds: input.node_key_ttl_seconds,
        }),
    ))
}

async fn commit_org(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<OrgResponse>), ApiError> {
    let service = service_session(&s, &headers, org_id, "bootstrap.commit").await?;
    let active = sqlx::query("SELECT name,node_key_ttl_seconds FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&s.store.pool)
        .await?
        .map(|row| Ok::<_, sqlx::Error>((row.try_get(0)?, row.try_get(1)?)))
        .transpose()?;
    if let Some((name, node_key_ttl_seconds)) = active {
        return Ok((
            StatusCode::OK,
            Json(OrgResponse {
                id: org_id,
                name,
                node_key_ttl_seconds,
            }),
        ));
    }
    let current_time = now();
    let pending = sqlx::query(
        "SELECT name,acl_json,node_key_ttl_seconds,expires_at
         FROM pending_bootstrap_orgs WHERE id=$1",
    )
    .bind(org_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>((
            row.try_get::<String, _>(0)?,
            row.try_get::<String, _>(1)?,
            row.try_get::<i64, _>(2)?,
            row.try_get::<i64, _>(3)?,
        ))
    })
    .transpose()?;
    let (name, acl_json, node_key_ttl_seconds, expires_at) = pending.ok_or(ApiError::NotFound)?;
    if expires_at <= current_time {
        sqlx::query("DELETE FROM pending_bootstrap_orgs WHERE id=$1")
            .bind(org_id.to_string())
            .execute(&s.store.pool)
            .await?;
        return Err(ApiError::Gone);
    }
    let mut tx = s.store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO orgs(id,name,acl_json,created_at,node_key_ttl_seconds)
         VALUES($1,$2,$3,$4,$5)",
    )
    .bind(org_id.to_string())
    .bind(&name)
    .bind(acl_json)
    .bind(current_time)
    .bind(node_key_ttl_seconds)
    .execute(&mut *tx)
    .await
    .map_err(conflict("org name already exists"))?;
    sqlx::query(
        "INSERT INTO audit_events(id,org_id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details_json,created_at)
         VALUES($1,$2,$3,$4,$5,'service','bootstrap.completed','organisation',$2,$6,$7)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(org_id.to_string())
    .bind(service.user_id)
    .bind(service.name)
    .bind(service.email)
    .bind(serde_json::json!({"source":"operator_channel","result":"success"}).to_string())
    .bind(current_time)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM pending_bootstrap_orgs WHERE id=$1")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(OrgResponse {
            id: org_id,
            name,
            node_key_ttl_seconds,
        }),
    ))
}

#[derive(Clone, Deserialize, Serialize)]
struct SecurityPolicy {
    node_key_ttl_seconds: i64,
}

fn validate_node_key_ttl(seconds: i64) -> Result<(), ApiError> {
    if !(MIN_NODE_KEY_TTL_SECS..=MAX_NODE_KEY_TTL_SECS).contains(&seconds) {
        return Err(ApiError::BadRequest(format!(
            "node_key_ttl_seconds must be between {MIN_NODE_KEY_TTL_SECS} and {MAX_NODE_KEY_TTL_SECS}"
        )));
    }
    Ok(())
}
fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}

pub(crate) fn conflict(message: &'static str) -> impl FnOnce(sqlx::Error) -> ApiError {
    move |error| {
        if is_unique_violation(&error) {
            ApiError::Conflict(message.into())
        } else {
            ApiError::Database(error)
        }
    }
}

#[derive(Deserialize)]
struct MintJoinKey {
    #[serde(default = "default_expiry")]
    expires_in_seconds: i64,
    #[serde(default = "yes")]
    single_use: bool,
    #[serde(default)]
    tags: Vec<DeviceTag>,
}
fn default_expiry() -> i64 {
    3600
}
fn yes() -> bool {
    true
}
#[derive(Serialize, Deserialize)]
struct JoinKeyResponse {
    id: Uuid,
    key: String,
    expires_at: i64,
    single_use: bool,
}
async fn mint_join_key(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<MintJoinKey>,
) -> Result<(StatusCode, Json<JoinKeyResponse>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    if !(1..=2_592_000).contains(&input.expires_in_seconds) {
        return Err(ApiError::BadRequest(
            "expires_in_seconds must be between 1 and 2592000".into(),
        ));
    }
    let key = secret("btk");
    let id = Uuid::new_v4();
    let expires_at = now() + input.expires_in_seconds;
    let tags = canonical_tags(input.tags);
    let acl = load_org_acl(&s.store, org_id).await?;
    authorize_tag_assignment(&acl, &session, &tags)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query("INSERT INTO join_keys(id,org_id,key_hash,expires_at,single_use,created_at,user_id,user_role,tags_json) SELECT $1,id,$2,$3,$4,$5,$6,$7,$8 FROM orgs WHERE id=$9")
        .bind(id.to_string())
        .bind(hash(&key))
        .bind(expires_at)
        .bind(i64::from(input.single_use))
        .bind(now())
        .bind(&session.user_id)
        .bind(session.role.as_str())
        .bind(serde_json::to_string(&tags).unwrap())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "join_key.minted",
        "join_key",
        Some(&id.to_string()),
        &serde_json::json!({
            "expires_at": expires_at,
            "single_use": input.single_use,
            "source": "console",
            "tags": tags,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(JoinKeyResponse {
            id,
            key,
            expires_at,
            single_use: input.single_use,
        }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterNode {
    join_key: String,
    name: String,
    wg_public_key: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    advertised_routes: Vec<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    os_version: Option<String>,
    #[serde(default)]
    agent_version: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    ephemeral: bool,
}

struct RegistrationGrant {
    key_id: String,
    org_id: String,
    single_use: bool,
    used: bool,
    user_id: String,
    user_role: String,
    tags_json: String,
    node_key_ttl: i64,
    bound_name: Option<String>,
    bound_wg_public_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}
impl Role {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}
impl std::str::FromStr for Role {
    type Err = ();
    fn from_str(v: &str) -> Result<Self, ()> {
        match v {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            _ => Err(()),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DeviceTag {
    Office,
    Ranger,
    Store,
}
impl DeviceTag {
    fn as_str(self) -> &'static str {
        match self {
            Self::Office => "office",
            Self::Ranger => "ranger",
            Self::Store => "store",
        }
    }
}
pub(crate) fn canonical_tags(mut tags: Vec<DeviceTag>) -> Vec<DeviceTag> {
    tags.sort();
    tags.dedup();
    tags
}

fn normalise_inventory_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().chars().take(64).collect::<String>())
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
}

fn canonical_capabilities(mut capabilities: Vec<String>) -> Vec<String> {
    capabilities = capabilities
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 32
                && value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        .collect();
    capabilities.sort();
    capabilities.dedup();
    capabilities.truncate(16);
    capabilities
}
#[derive(Serialize, Deserialize)]
struct RegisterResponse {
    id: Uuid,
    org_id: Uuid,
    node_token: String,
    assigned_ip: String,
    assigned_ips: Vec<String>,
    dns_name: String,
    credential_expires_at: i64,
    /// Advertised relay endpoints plus a capability token for them.
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    relay_token: String,
    #[serde(default)]
    relay_expires_at: u64,
}
async fn register_node(
    State(s): State<AppState>,
    Json(input): Json<RegisterNode>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    if input.name.trim().is_empty() || input.wg_public_key.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "name and wg_public_key are required".into(),
        ));
    }
    if !input.allowed_ips.is_empty() {
        return Err(ApiError::BadRequest(
            "allowed_ips are assigned by the coordinator".into(),
        ));
    }
    let advertised_routes = validate_advertised_routes(input.advertised_routes)?;
    let mut tx = s.store.pool.begin().await?;
    let input_key_hash = hash(&input.join_key);
    let registration_query = match s.store.backend {
        DatabaseBackend::Sqlite => "SELECT k.id,k.org_id,k.single_use,CASE WHEN k.used_at IS NULL THEN 0 ELSE 1 END,k.user_id,k.user_role,k.tags_json,o.node_key_ttl_seconds,d.requested_name,d.wg_public_key FROM join_keys k JOIN orgs o ON o.id=k.org_id LEFT JOIN device_authorizations d ON d.device_code_hash=k.key_hash WHERE k.key_hash=$1 AND k.revoked_at IS NULL AND k.expires_at>$2",
        DatabaseBackend::Postgres => "SELECT k.id,k.org_id,k.single_use,CASE WHEN k.used_at IS NULL THEN 0 ELSE 1 END,k.user_id,k.user_role,k.tags_json,o.node_key_ttl_seconds,d.requested_name,d.wg_public_key FROM join_keys k JOIN orgs o ON o.id=k.org_id LEFT JOIN device_authorizations d ON d.device_code_hash=k.key_hash WHERE k.key_hash=$1 AND k.revoked_at IS NULL AND k.expires_at>$2 FOR UPDATE OF k",
    };
    let grant = sqlx::query(registration_query)
        .bind(&input_key_hash)
        .bind(now())
        .fetch_optional(&mut *tx)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>(RegistrationGrant {
                key_id: row.try_get(0)?,
                org_id: row.try_get(1)?,
                single_use: row.try_get::<i64, _>(2)? != 0,
                used: row.try_get::<i64, _>(3)? != 0,
                user_id: row.try_get(4)?,
                user_role: row.try_get(5)?,
                tags_json: row.try_get(6)?,
                node_key_ttl: row.try_get(7)?,
                bound_name: row.try_get(8)?,
                bound_wg_public_key: row.try_get(9)?,
            })
        })
        .transpose()?;
    let grant = grant.ok_or(ApiError::Unauthorized)?;
    if grant.single_use && grant.used {
        return Err(ApiError::Unauthorized);
    }
    if grant
        .bound_name
        .as_deref()
        .is_some_and(|name| name != input.name.trim())
        || grant
            .bound_wg_public_key
            .as_deref()
            .is_some_and(|key| key != input.wg_public_key.trim())
    {
        return Err(ApiError::BadRequest(
            "browser authorization is bound to another device identity; run blaktaild up again"
                .into(),
        ));
    }
    let id = Uuid::new_v4();
    let token = secret("btn");
    let allowed_ips = allocate_ips(&mut tx, &grant.org_id).await?;
    let assigned_ip = allowed_ips[0].clone();
    let dns_name = magic_dns_name(input.name.trim(), &grant.org_id);
    let registered_at = now();
    let credential_expires_at = registered_at + grant.node_key_ttl;
    let capabilities = serde_json::to_string(&canonical_capabilities(input.capabilities)).unwrap();
    sqlx::query("INSERT INTO nodes(id,org_id,name,wg_public_key,endpoint,allowed_ips_json,token_hash,created_at,user_id,user_role,tags_json,dns_name,advertised_routes_json,approved_routes_json,credential_expires_at,last_seen_at,os,os_version,agent_version,hostname,capabilities_json,ephemeral) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'[]',$14,$14,$15,$16,$17,$18,$19,$20)")
        .bind(id.to_string())
        .bind(&grant.org_id)
        .bind(input.name.trim())
        .bind(input.wg_public_key.trim())
        .bind(input.endpoint)
        .bind(serde_json::to_string(&allowed_ips).unwrap())
        .bind(hash(&token))
        .bind(registered_at)
        .bind(&grant.user_id)
        .bind(&grant.user_role)
        .bind(&grant.tags_json)
        .bind(&dns_name)
        .bind(serde_json::to_string(&advertised_routes).unwrap())
        .bind(credential_expires_at)
        .bind(normalise_inventory_text(input.os))
        .bind(normalise_inventory_text(input.os_version))
        .bind(normalise_inventory_text(input.agent_version))
        .bind(normalise_inventory_text(input.hostname))
        .bind(capabilities)
        .bind(i64::from(input.ephemeral))
        .execute(&mut *tx)
        .await
        .map_err(conflict("node name, DNS name, public key, or address already exists in org"))?;
    if grant.single_use {
        sqlx::query("UPDATE join_keys SET used_at=$1 WHERE id=$2")
            .bind(now())
            .bind(&grant.key_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE device_authorizations SET consumed_at=$1 WHERE device_code_hash=$2")
        .bind(now())
        .bind(input_key_hash)
        .execute(&mut *tx)
        .await?;
    bump_control_revision(&mut tx, &grant.org_id).await?;
    let org_id = Uuid::parse_str(&grant.org_id).map_err(|_| ApiError::CorruptData)?;
    webhooks::enqueue(
        &mut tx,
        org_id,
        "device.enrolled",
        &serde_json::json!({
            "device_id": id,
            "name": input.name.trim(),
            "dns_name": dns_name,
        }),
    )
    .await?;
    tx.commit().await?;
    info!(node_id=%id, org_id=%grant.org_id, "node registered");
    let (relay_token, relay_expires_at) = relay_credentials(&s, id);
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id,
            org_id: Uuid::parse_str(&grant.org_id).unwrap(),
            node_token: token,
            assigned_ip,
            assigned_ips: allowed_ips,
            dns_name,
            credential_expires_at,
            relays: s.relays.as_ref().clone(),
            relay_token,
            relay_expires_at,
        }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvertisedRoutesUpdate {
    advertised_routes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedRoutesUpdate {
    approved_routes: Vec<String>,
}

async fn update_advertised_routes(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<AdvertisedRoutesUpdate>,
) -> Result<StatusCode, ApiError> {
    let routes = validate_advertised_routes(input.advertised_routes)?;
    let token = bearer(&headers)?;
    let row = sqlx::query("SELECT credential_expires_at,approved_routes_json FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL")
        .bind(node_id.to_string())
        .bind(token)
        .fetch_optional(&s.store.pool)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>((
                row.try_get::<i64, _>(0)?,
                row.try_get::<String, _>(1)?,
            ))
        })
        .transpose()?;
    let (credential_expires_at, approved_json) = row.ok_or(ApiError::Unauthorized)?;
    if credential_expires_at <= now() {
        return Err(ApiError::CredentialExpired);
    }
    let approved: Vec<String> = serde_json::from_str(&approved_json).unwrap_or_default();
    let retained_approvals: Vec<_> = approved
        .into_iter()
        .filter(|route| routes.contains(route))
        .collect();
    sqlx::query("UPDATE nodes SET advertised_routes_json=$1,approved_routes_json=$2 WHERE id=$3")
        .bind(serde_json::to_string(&routes).unwrap())
        .bind(serde_json::to_string(&retained_approvals).unwrap())
        .bind(node_id.to_string())
        .execute(&s.store.pool)
        .await?;
    info!(%node_id, routes = routes.len(), "node route advertisements updated");
    Ok(StatusCode::NO_CONTENT)
}

async fn update_node_shares(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<shares::ShareUpdate>,
) -> Result<Json<Vec<shares::NodeShare>>, ApiError> {
    let shares = shares::canonicalise(input.shares)?;
    let token = bearer(&headers)?;
    let mut tx = s.store.pool.begin().await?;
    let row = sqlx::query(
        "SELECT org_id,credential_expires_at FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&mut *tx)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>((row.try_get::<String, _>(0)?, row.try_get::<i64, _>(1)?))
    })
    .transpose()?;
    let (org_id, credential_expires_at) = row.ok_or(ApiError::Unauthorized)?;
    if credential_expires_at <= now() {
        return Err(ApiError::CredentialExpired);
    }
    sqlx::query("UPDATE nodes SET shares_json=$1 WHERE id=$2")
        .bind(serde_json::to_string(&shares).unwrap())
        .bind(node_id.to_string())
        .execute(&mut *tx)
        .await?;
    bump_control_revision(&mut tx, org_id).await?;
    tx.commit().await?;
    info!(%node_id, shares = shares.len(), "node shares updated");
    Ok(Json(shares))
}

async fn approve_node_routes(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<ApprovedRoutesUpdate>,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    let approved = validate_advertised_routes(input.approved_routes)?;
    let approval_time = now();
    let mut tx = s.store.pool.begin().await?;
    let advertised_row = sqlx::query(
        "SELECT advertised_routes_json,approved_routes_json,credential_expires_at FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>((
            row.try_get::<String, _>(0)?,
            row.try_get::<String, _>(1)?,
            row.try_get::<i64, _>(2)?,
        ))
    })
    .transpose()?;
    let (advertised_json, current_approved_json, credential_expires_at) =
        advertised_row.ok_or(ApiError::NotFound)?;
    let current_approved: Vec<String> =
        serde_json::from_str(&current_approved_json).unwrap_or_default();
    if credential_expires_at <= approval_time
        && approved
            .iter()
            .any(|route| !current_approved.contains(route))
    {
        return Err(ApiError::Conflict(
            "cannot add route approvals to an expired node; renew it first".into(),
        ));
    }
    let advertised: Vec<String> = serde_json::from_str(&advertised_json).unwrap_or_default();
    if approved.iter().any(|route| !advertised.contains(route)) {
        return Err(ApiError::BadRequest(
            "approved routes must be a subset of the node's advertisements".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT id,credential_expires_at,approved_routes_json FROM nodes WHERE org_id=$1 AND id!=$2 AND revoked_at IS NULL",
    )
    .bind(org_id.to_string())
    .bind(node_id.to_string())
    .fetch_all(&mut *tx)
    .await?;
    let other_nodes = rows
        .iter()
        .map(|row| Ok::<_, sqlx::Error>((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?)))
        .collect::<Result<Vec<(String, i64, String)>, _>>()?;
    let other_routes = other_nodes
        .iter()
        .filter(|(_, expires_at, _)| *expires_at > approval_time)
        .flat_map(|(_, _, json)| serde_json::from_str::<Vec<String>>(json).unwrap_or_default())
        .filter(|route| route != "0.0.0.0/0")
        .collect::<Vec<_>>();
    if let Some(route) = approved.iter().find(|route| {
        route.as_str() != "0.0.0.0/0"
            && other_routes
                .iter()
                .any(|other| ipv4_routes_overlap(route, other))
    }) {
        return Err(ApiError::Conflict(format!(
            "route {route} overlaps another approved subnet router"
        )));
    }
    let approved_subnets: Vec<_> = approved
        .iter()
        .filter(|route| route.as_str() != "0.0.0.0/0")
        .collect();
    for (other_id, expires_at, routes_json) in other_nodes {
        if expires_at > approval_time {
            continue;
        }
        let mut routes: Vec<String> = serde_json::from_str(&routes_json).unwrap_or_default();
        let original_len = routes.len();
        routes.retain(|route| {
            route == "0.0.0.0/0"
                || !approved_subnets
                    .iter()
                    .any(|approved| ipv4_routes_overlap(route, approved))
        });
        if routes.len() != original_len {
            sqlx::query("UPDATE nodes SET approved_routes_json=$1 WHERE id=$2")
                .bind(serde_json::to_string(&routes).unwrap())
                .bind(other_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("UPDATE nodes SET approved_routes_json=$1 WHERE id=$2 AND org_id=$3")
        .bind(serde_json::to_string(&approved).unwrap())
        .bind(node_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "node.routes_updated",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({"approved_routes": approved}),
    )
    .await?;
    tx.commit().await?;
    info!(%node_id, %org_id, routes = approved.len(), "node routes approved");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthNode {
    join_key: String,
}

#[derive(Deserialize, Serialize)]
struct ReauthResponse {
    node_token: String,
    credential_expires_at: i64,
}

async fn reauth_node(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ReauthNode>,
) -> Result<Json<ReauthResponse>, ApiError> {
    let old_token_hash = bearer(&headers)?;
    let mut tx = s.store.pool.begin().await?;
    let org_id: String = sqlx::query_scalar(
        "SELECT org_id FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(old_token_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let reauth_query = match s.store.backend {
        DatabaseBackend::Sqlite => "SELECT k.id,k.single_use,CASE WHEN k.used_at IS NULL THEN 0 ELSE 1 END,k.user_id,k.user_role,k.tags_json,o.node_key_ttl_seconds FROM join_keys k JOIN orgs o ON o.id=k.org_id WHERE k.key_hash=$1 AND k.org_id=$2 AND k.revoked_at IS NULL AND k.expires_at>$3 AND NOT EXISTS(SELECT 1 FROM device_authorizations d WHERE d.device_code_hash=k.key_hash)",
        DatabaseBackend::Postgres => "SELECT k.id,k.single_use,CASE WHEN k.used_at IS NULL THEN 0 ELSE 1 END,k.user_id,k.user_role,k.tags_json,o.node_key_ttl_seconds FROM join_keys k JOIN orgs o ON o.id=k.org_id WHERE k.key_hash=$1 AND k.org_id=$2 AND k.revoked_at IS NULL AND k.expires_at>$3 AND NOT EXISTS(SELECT 1 FROM device_authorizations d WHERE d.device_code_hash=k.key_hash) FOR UPDATE OF k",
    };
    let join = sqlx::query(reauth_query)
        .bind(hash(&input.join_key))
        .bind(&org_id)
        .bind(now())
        .fetch_optional(&mut *tx)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>((
                row.try_get::<String, _>(0)?,
                row.try_get::<i64, _>(1)? != 0,
                row.try_get::<i64, _>(2)? != 0,
                row.try_get::<String, _>(3)?,
                row.try_get::<String, _>(4)?,
                row.try_get::<String, _>(5)?,
                row.try_get::<i64, _>(6)?,
            ))
        })
        .transpose()?;
    let (join_id, single_use, used, user_id, user_role, tags_json, ttl) =
        join.ok_or(ApiError::Unauthorized)?;
    if single_use && used {
        return Err(ApiError::Unauthorized);
    }
    let node_token = secret("btn");
    let credential_expires_at = now() + ttl;
    sqlx::query(
        "UPDATE nodes SET token_hash=$1,credential_expires_at=$2,user_id=$3,user_role=$4,tags_json=$5 WHERE id=$6",
    )
    .bind(hash(&node_token))
    .bind(credential_expires_at)
    .bind(user_id)
    .bind(user_role)
    .bind(tags_json)
    .bind(node_id.to_string())
    .execute(&mut *tx)
    .await?;
    if single_use {
        sqlx::query("UPDATE join_keys SET used_at=$1 WHERE id=$2")
            .bind(now())
            .bind(join_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    info!(%node_id, "node credential renewed");
    Ok(Json(ReauthResponse {
        node_token,
        credential_expires_at,
    }))
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct Peer {
    id: Uuid,
    name: String,
    wg_public_key: String,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    dns_name: String,
    tags: Vec<DeviceTag>,
    relay_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress: Option<PeerIngress>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PeerIngress {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    all: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tcp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    udp: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    icmp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny_tcp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny_udp: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    deny_icmp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ssh_users: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct PeersResponse {
    peers: Vec<Peer>,
    assigned_ips: Vec<String>,
    dns_name: String,
    credential_expires_at: i64,
    #[serde(default)]
    exit_node_active: bool,
    /// Advertised relay endpoints plus a refreshed capability token.
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    relay_token: String,
    #[serde(default)]
    relay_expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns: Option<org_dns::OrgDnsAgentView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    shares: Vec<shares::PublishedShare>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_updates: Option<ControlUpdatesCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ControlUpdatesCapability {
    wait_max_seconds: u64,
}

#[derive(Serialize)]
struct ControlUpdate {
    kind: &'static str,
    revision: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    added: Vec<Peer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed: Vec<Uuid>,
    #[serde(flatten)]
    snapshot: PeersResponse,
}

#[derive(Default, Deserialize)]
struct PeerSelection {
    #[serde(default)]
    exit_node: Option<String>,
    #[serde(default)]
    ipv6: bool,
    #[serde(default)]
    dns_revision: Option<i64>,
}

#[derive(Default, Deserialize)]
struct UpdateSelection {
    #[serde(default)]
    since: i64,
    #[serde(default)]
    wait: u64,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    exit_node: Option<String>,
    #[serde(default)]
    ipv6: bool,
    #[serde(default)]
    dns_revision: Option<i64>,
}

async fn list_peers(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    Query(selection): Query<PeerSelection>,
    headers: HeaderMap,
) -> Result<Json<PeersResponse>, ApiError> {
    let token = bearer(&headers)?;
    let source_row = sqlx::query("SELECT n.org_id,n.user_id,n.user_role,n.tags_json,o.acl_json,n.credential_expires_at,n.dns_name,n.allowed_ips_json,o.dns_json,o.dns_revision FROM nodes n JOIN orgs o ON o.id=n.org_id WHERE n.id=$1 AND n.token_hash=$2 AND n.revoked_at IS NULL AND n.deleted_at IS NULL")
        .bind(node_id.to_string())
        .bind(token)
        .fetch_optional(&s.store.pool)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let org: String = source_row.try_get(0)?;
    let source_user_id: String = source_row.try_get(1)?;
    let source_role: String = source_row.try_get(2)?;
    let source_tags: String = source_row.try_get(3)?;
    let acl_json: String = source_row.try_get(4)?;
    let credential_expires_at: i64 = source_row.try_get(5)?;
    let dns_name: String = source_row.try_get(6)?;
    let source_addresses: String = source_row.try_get(7)?;
    let org_dns_json: String = source_row.try_get(8).unwrap_or_default();
    let org_dns_revision: i64 = source_row.try_get(9).unwrap_or(0);
    if credential_expires_at <= now() {
        return Err(ApiError::CredentialExpired);
    }
    sqlx::query("UPDATE nodes SET last_seen_at=$1,dns_applied_revision=CASE WHEN $3>=0 THEN $3 ELSE dns_applied_revision END WHERE id=$2")
        .bind(now())
        .bind(node_id.to_string())
        .bind(selection.dns_revision.unwrap_or(-1))
        .execute(&s.store.pool)
        .await?;
    expire_ephemeral_nodes(&s.store, &org).await?;
    wg_only::expire_overlaps(&s.store.pool, &org).await?;
    let source = Subject::new(
        source_role.parse().map_err(|_| ApiError::CorruptData)?,
        serde_json::from_str(&source_tags).unwrap_or_default(),
    )
    .with_user(source_user_id);
    let acl: Acl = serde_json::from_str(&acl_json).map_err(|_| ApiError::CorruptData)?;
    let requested_exit = selection
        .exit_node
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let rows = sqlx::query("SELECT id,name,wg_public_key,endpoint,allowed_ips_json,dns_name,user_id,user_role,tags_json,CASE WHEN relay_endpoint_updated_at>$3 THEN relay_endpoint ELSE NULL END,approved_routes_json,shares_json FROM nodes WHERE org_id=$1 AND id!=$2 AND revoked_at IS NULL AND deleted_at IS NULL AND credential_expires_at>$4 ORDER BY name")
        .bind(org.clone())
        .bind(node_id.to_string())
        .bind(now() - RELAY_ENDPOINT_FRESH_SECS)
        .bind(now())
        .fetch_all(&s.store.pool)
        .await?;
    let candidates = rows
        .into_iter()
        .map(|row| {
            let id: String = row.try_get(0)?;
            let ips: String = row.try_get(4)?;
            let tags: Vec<DeviceTag> =
                serde_json::from_str(&row.try_get::<String, _>(8)?).unwrap_or_default();
            let approved: Vec<String> =
                serde_json::from_str(&row.try_get::<String, _>(10)?).unwrap_or_default();
            let dest_shares =
                shares::parse_shares(&row.try_get::<String, _>(11).unwrap_or_else(|_| "[]".into()));
            Ok::<_, ApiError>((
                Peer {
                    id: Uuid::parse_str(&id).map_err(|_| ApiError::CorruptData)?,
                    name: row.try_get(1)?,
                    wg_public_key: row.try_get(2)?,
                    endpoint: row.try_get(3)?,
                    allowed_ips: serde_json::from_str(&ips).map_err(|_| ApiError::CorruptData)?,
                    dns_name: row.try_get(5)?,
                    tags: tags.clone(),
                    relay_endpoint: row.try_get(9)?,
                    kind: String::new(),
                    ingress: None,
                },
                Subject::new(
                    row.try_get::<String, _>(7)?
                        .parse()
                        .map_err(|_| ApiError::CorruptData)?,
                    tags,
                )
                .with_user(row.try_get::<String, _>(6)?),
                approved,
                dest_shares,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut exit_node_active = false;
    let mut peers = candidates
        .into_iter()
        .filter_map(|(mut peer, destination, approved, dest_shares)| {
            if !acl.allows(&source, &destination) {
                return None;
            }
            let mut ingress = acl.peer_ingress(&destination, &source);
            shares::grant_share_ports(
                &mut ingress.tcp,
                &ingress.deny_tcp,
                ingress.all,
                &dest_shares,
            );
            peer.ingress = Some(ingress);
            let exit_matches = requested_exit.is_some_and(|requested| {
                requested == peer.id.to_string()
                    || requested == peer.name
                    || requested == peer.dns_name
            });
            for route in approved {
                if route == "0.0.0.0/0" {
                    if exit_matches {
                        peer.allowed_ips.push(route);
                        exit_node_active = true;
                    }
                } else {
                    peer.allowed_ips.push(route);
                }
            }
            if !selection.ipv6 {
                peer.allowed_ips.retain(|route| !route.contains(':'));
            }
            Some(peer)
        })
        .collect::<Vec<_>>();
    for (id, name, wg_public_key, endpoint, mut allowed_ips, tags) in
        wg_only::active_export_rows(&s.store.pool, &org).await?
    {
        let destination = Subject::new(Role::Member, tags.clone());
        if !acl.allows(&source, &destination) {
            continue;
        }
        if !selection.ipv6 {
            allowed_ips.retain(|route| !route.contains(':'));
        }
        if allowed_ips.is_empty() {
            continue;
        }
        peers.push(Peer {
            id,
            name,
            wg_public_key,
            endpoint: Some(endpoint),
            allowed_ips,
            dns_name: String::new(),
            tags,
            relay_endpoint: None,
            kind: wg_only::KIND.into(),
            ingress: Some(acl.peer_ingress(&destination, &source)),
        });
    }
    let mut assigned_ips: Vec<String> = serde_json::from_str(&source_addresses).unwrap_or_default();
    if !selection.ipv6 {
        assigned_ips.retain(|address| !address.contains(':'));
    }
    let (relay_token, relay_expires_at) = relay_credentials(&s, node_id);
    let dns = org_dns::parse_settings(&org_dns_json)
        .ok()
        .map(|settings| settings.agent_view(&org, org_dns_revision));
    let visible_ids = peers.iter().map(|peer| peer.id).collect::<BTreeSet<_>>();
    let published_shares = shares::load_published(&s.store.pool, &org, &visible_ids).await?;
    Ok(Json(PeersResponse {
        peers,
        assigned_ips,
        dns_name,
        credential_expires_at,
        exit_node_active,
        relays: s.relays.as_ref().clone(),
        relay_token,
        relay_expires_at,
        dns,
        shares: published_shares,
        control_updates: Some(ControlUpdatesCapability {
            wait_max_seconds: MAX_CONTROL_UPDATE_WAIT_SECS,
        }),
    }))
}

async fn list_updates(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    Query(selection): Query<UpdateSelection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if selection
        .version
        .is_some_and(|version| version != 1 && version != 2)
    {
        return Err(ApiError::BadRequest(
            "unsupported control update version".into(),
        ));
    }
    let token = bearer(&headers)?;
    let org: String = sqlx::query_scalar(
        "SELECT org_id FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let wait = selection.wait.min(MAX_CONTROL_UPDATE_WAIT_SECS);
    let started = Instant::now();
    loop {
        let expired = wg_only::expire_overlaps(&s.store.pool, &org).await?;
        let revision: i64 = sqlx::query_scalar("SELECT control_revision FROM orgs WHERE id=$1")
            .bind(&org)
            .fetch_optional(&s.store.pool)
            .await?
            .ok_or(ApiError::CorruptData)?;
        let changed = selection.since == 0 || revision > selection.since || expired;
        if changed || started.elapsed() >= Duration::from_secs(wait) {
            if !changed {
                return Ok(StatusCode::NO_CONTENT.into_response());
            }
            let Json(snapshot) = list_peers(
                State(s.clone()),
                UrlPath(node_id),
                Query(PeerSelection {
                    exit_node: selection.exit_node,
                    ipv6: selection.ipv6,
                    dns_revision: selection.dns_revision,
                }),
                headers,
            )
            .await?;
            let update = control_update_from_snapshot(
                &s,
                node_id,
                revision,
                snapshot,
                selection.since,
                selection.version,
                expired,
            );
            return Ok(Json(update).into_response());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn control_update_from_snapshot(
    state: &AppState,
    node_id: Uuid,
    revision: i64,
    snapshot: PeersResponse,
    since: i64,
    version: Option<u32>,
    force_snapshot: bool,
) -> ControlUpdate {
    let current_ids = snapshot
        .peers
        .iter()
        .map(|peer| peer.id)
        .collect::<BTreeSet<_>>();
    let baseline = remember_and_baseline(&state.control_views, node_id, revision, &current_ids);
    if version == Some(2) && !force_snapshot {
        if let Some((baseline_revision, previous_ids)) = baseline {
            if since > 0 && baseline_revision == since {
                let added = snapshot
                    .peers
                    .iter()
                    .filter(|peer| !previous_ids.contains(&peer.id))
                    .cloned()
                    .collect::<Vec<_>>();
                let removed = previous_ids
                    .difference(&current_ids)
                    .copied()
                    .collect::<Vec<_>>();
                if !added.is_empty() || !removed.is_empty() {
                    return ControlUpdate {
                        kind: "delta",
                        revision,
                        added,
                        removed,
                        snapshot: PeersResponse {
                            peers: Vec::new(),
                            ..snapshot
                        },
                    };
                }
            }
        }
    }
    ControlUpdate {
        kind: "snapshot",
        revision,
        added: Vec::new(),
        removed: Vec::new(),
        snapshot,
    }
}

fn remember_and_baseline(
    views: &Mutex<ControlViewMap>,
    node_id: Uuid,
    revision: i64,
    current_ids: &BTreeSet<Uuid>,
) -> Option<(i64, BTreeSet<Uuid>)> {
    let mut views = views
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let baseline = views.get(&node_id).cloned();
    if views.len() >= MAX_CONTROL_VIEWS && !views.contains_key(&node_id) {
        views.clear();
    }
    views.insert(node_id, (revision, current_ids.clone()));
    baseline
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayEndpointUpdate {
    endpoint: String,
}

async fn update_relay_endpoint(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<RelayEndpointUpdate>,
) -> Result<StatusCode, ApiError> {
    let endpoint: SocketAddr = input
        .endpoint
        .trim()
        .parse()
        .map_err(|_| ApiError::BadRequest("endpoint must be an IP socket address".into()))?;
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return Err(ApiError::BadRequest(
            "endpoint must use a unicast IP and non-zero port".into(),
        ));
    }
    let token = bearer(&headers)?;
    let expires_at: i64 = sqlx::query_scalar(
        "SELECT credential_expires_at FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&s.store.pool)
    .await?
        .ok_or(ApiError::Unauthorized)?;
    if expires_at <= now() {
        return Err(ApiError::CredentialExpired);
    }
    sqlx::query("UPDATE nodes SET relay_endpoint=$1,relay_endpoint_updated_at=$2 WHERE id=$3")
        .bind(endpoint.to_string())
        .bind(now())
        .bind(node_id.to_string())
        .execute(&s.store.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Capability token TTL for relay registration (7 days, refreshed each poll).
const RELAY_TOKEN_TTL_SECS: u64 = 604_800;
const RELAY_ENDPOINT_FRESH_SECS: i64 = 180;
fn relay_credentials(state: &AppState, node_id: Uuid) -> (String, u64) {
    if state.relays.is_empty() || state.relay_auth_secret.is_empty() {
        return (String::new(), 0);
    }
    let expires_at = (now() as u64) + RELAY_TOKEN_TTL_SECS;
    (
        relay_capability(&state.relay_auth_secret, node_id, expires_at),
        expires_at,
    )
}
/// HMAC-SHA256 capability binding a node id to an expiry, hex-encoded. Must
/// match blaktail-relay's REGISTER verification (id || expiry_be, big-endian).
fn relay_capability(secret: &[u8], node_id: Uuid, expires_at_unix: u64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(node_id.as_bytes());
    mac.update(&expires_at_unix.to_be_bytes());
    hex_encode(&mac.finalize().into_bytes())
}
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
async fn allocate_ips(
    connection: &mut AnyConnection,
    org_id: &str,
) -> Result<Vec<String>, ApiError> {
    let mut used = std::collections::HashSet::new();
    let rows =
        sqlx::query_scalar::<_, String>("SELECT allowed_ips_json FROM nodes WHERE org_id=$1")
            .bind(org_id)
            .fetch_all(connection)
            .await?;
    for row in rows {
        for ip in serde_json::from_str::<Vec<String>>(&row).unwrap_or_default() {
            used.insert(ip);
        }
    }
    let ipv4 = (1..=254)
        .map(|host| format!("100.64.0.{host}/32"))
        .find(|ip| !used.contains(ip))
        .ok_or_else(|| ApiError::Conflict("tailnet address pool exhausted".into()))?;
    let host = assigned_ipv4_host(std::slice::from_ref(&ipv4))
        .expect("coordinator-generated IPv4 address is valid");
    Ok(vec![ipv4, org_ula_address(org_id, host)])
}

fn assigned_ipv4_host(addresses: &[String]) -> Option<u8> {
    addresses.iter().find_map(|address| {
        let (address, prefix) = address.split_once('/')?;
        if prefix != "32" {
            return None;
        }
        let octets = address.parse::<Ipv4Addr>().ok()?.octets();
        (octets[..3] == [100, 64, 0] && octets[3] != 0).then_some(octets[3])
    })
}

fn org_ula_address(org_id: &str, host: u8) -> String {
    let digest = Sha256::digest(org_id.as_bytes());
    let mut octets = [0_u8; 16];
    octets[0] = 0xfd;
    octets[1..8].copy_from_slice(&digest[..7]);
    octets[15] = host;
    format!("{}/128", Ipv6Addr::from(octets))
}

fn validate_advertised_routes(routes: Vec<String>) -> Result<Vec<String>, ApiError> {
    if routes.len() > 32 {
        return Err(ApiError::BadRequest(
            "a node may advertise at most 32 routes".into(),
        ));
    }
    let mut canonical = routes
        .into_iter()
        .map(|route| canonical_ipv4_route(&route))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    canonical.dedup();
    for (index, route) in canonical.iter().enumerate() {
        if route != "0.0.0.0/0"
            && !["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                .iter()
                .any(|private| ipv4_route_is_within(route, private))
        {
            return Err(ApiError::BadRequest(format!(
                "route {route} must be an RFC1918 private subnet or 0.0.0.0/0"
            )));
        }
        if route != "0.0.0.0/0" && ipv4_routes_overlap(route, "100.64.0.0/10") {
            return Err(ApiError::BadRequest(format!(
                "route {route} overlaps the BlakTail address pool"
            )));
        }
        if route != "0.0.0.0/0"
            && canonical[index + 1..]
                .iter()
                .any(|other| other != "0.0.0.0/0" && ipv4_routes_overlap(route, other))
        {
            return Err(ApiError::BadRequest(format!(
                "advertised route {route} overlaps another advertised route"
            )));
        }
    }
    Ok(canonical)
}

pub(crate) fn canonical_ipv4_route(route: &str) -> Result<String, ApiError> {
    let route = route.trim();
    let (address, prefix) = route
        .split_once('/')
        .ok_or_else(|| ApiError::BadRequest(format!("route {route} must use CIDR notation")))?;
    let address: Ipv4Addr = address
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("route {route} must be IPv4 CIDR")))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| ApiError::BadRequest(format!("route {route} has an invalid prefix")))?;
    let mask = ipv4_mask(prefix);
    let raw = u32::from(address);
    if raw & !mask != 0 {
        return Err(ApiError::BadRequest(format!(
            "route {route} is not a network address"
        )));
    }
    if prefix != 0
        && (address.is_loopback()
            || address.is_link_local()
            || address.is_multicast()
            || address.is_broadcast())
    {
        return Err(ApiError::BadRequest(format!(
            "route {route} is not a routable network"
        )));
    }
    Ok(format!("{address}/{prefix}"))
}

pub(crate) fn ipv4_routes_overlap(left: &str, right: &str) -> bool {
    let parse = |route: &str| {
        let (address, prefix) = route.split_once('/').expect("validated CIDR");
        (
            u32::from(address.parse::<Ipv4Addr>().expect("validated IPv4")),
            prefix.parse::<u8>().expect("validated prefix"),
        )
    };
    let (left_address, left_prefix) = parse(left);
    let (right_address, right_prefix) = parse(right);
    let mask = ipv4_mask(left_prefix.min(right_prefix));
    left_address & mask == right_address & mask
}

pub(crate) fn ipv4_route_is_within(route: &str, container: &str) -> bool {
    let parse = |cidr: &str| {
        let (address, prefix) = cidr.split_once('/').expect("validated CIDR");
        (
            u32::from(address.parse::<Ipv4Addr>().expect("validated IPv4")),
            prefix.parse::<u8>().expect("validated prefix"),
        )
    };
    let (address, prefix) = parse(route);
    let (container_address, container_prefix) = parse(container);
    prefix >= container_prefix
        && address & ipv4_mask(container_prefix) == container_address & ipv4_mask(container_prefix)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
async fn revoke_node(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let changed = sqlx::query(
        "UPDATE nodes SET revoked_at=$1 WHERE id=$2 AND token_hash=$3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(node_id.to_string())
    .bind(bearer(&headers)?)
    .execute(&s.store.pool)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query(
        "UPDATE orgs SET control_revision=control_revision+1 WHERE id=(SELECT org_id FROM nodes WHERE id=$1)",
    )
    .bind(node_id.to_string())
    .execute(&s.store.pool)
    .await?;
    info!(%node_id,"node revoked");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NodeRow {
    id: Uuid,
    name: String,
    display_name: Option<String>,
    wg_public_key: String,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    advertised_routes: Vec<String>,
    approved_routes: Vec<String>,
    dns_name: String,
    user_id: String,
    user_role: String,
    tags: Vec<DeviceTag>,
    created_at: i64,
    credential_expires_at: i64,
    expired: bool,
    expires_soon: bool,
    revoked: bool,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    last_seen_at: Option<i64>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    os_version: Option<String>,
    #[serde(default)]
    agent_version: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    shares: Vec<shares::NodeShare>,
    #[serde(default)]
    dns_applied_revision: i64,
}

#[derive(Default, Deserialize)]
pub(crate) struct NodeListQuery {
    q: Option<String>,
    state: Option<String>,
    include_deleted: Option<bool>,
    limit: Option<u16>,
    before: Option<String>,
}

async fn list_nodes(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    Query(query): Query<NodeListQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<NodeRow>>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    expire_ephemeral_nodes(&s.store, &org_id.to_string()).await?;
    Ok(Json(load_nodes(&s.store, org_id, &query).await?))
}

pub(crate) async fn load_nodes(
    store: &Store,
    org_id: Uuid,
    query: &NodeListQuery,
) -> Result<Vec<NodeRow>, ApiError> {
    purge_expired_tombstones(store, org_id).await?;
    let include_deleted = query.include_deleted.unwrap_or(false);
    let limit = i64::from(query.limit.unwrap_or(200).clamp(1, 200));
    let current_time = now();
    let rows = sqlx::query(
        "SELECT id,name,wg_public_key,endpoint,allowed_ips_json,dns_name,user_id,user_role,tags_json,CAST(created_at AS BIGINT),credential_expires_at,CASE WHEN credential_expires_at<=$2 THEN 1 ELSE 0 END,CASE WHEN credential_expires_at<=$3 THEN 1 ELSE 0 END,CASE WHEN revoked_at IS NOT NULL THEN 1 ELSE 0 END,advertised_routes_json,approved_routes_json,display_name,last_seen_at,os,os_version,agent_version,hostname,capabilities_json,ephemeral,CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END,shares_json,dns_applied_revision FROM nodes WHERE org_id=$1 ORDER BY LOWER(COALESCE(NULLIF(TRIM(display_name),''),name)),name",
    )
    .bind(org_id.to_string())
    .bind(current_time)
    .bind(current_time + 14 * 24 * 60 * 60)
    .fetch_all(&store.pool)
    .await?;
    let wanted = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let state = query
        .state
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let before = query
        .before
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut nodes = rows
        .into_iter()
        .map(|row| {
            let id: String = row.try_get(0)?;
            let last_seen_at: Option<i64> = row.try_get(17)?;
            let deleted = row.try_get::<i64, _>(24)? != 0;
            Ok::<_, ApiError>(NodeRow {
                id: Uuid::parse_str(&id).map_err(|_| ApiError::CorruptData)?,
                name: row.try_get(1)?,
                display_name: row.try_get(16)?,
                wg_public_key: row.try_get(2)?,
                endpoint: row.try_get(3)?,
                allowed_ips: serde_json::from_str(&row.try_get::<String, _>(4)?)
                    .unwrap_or_default(),
                advertised_routes: serde_json::from_str(&row.try_get::<String, _>(14)?)
                    .unwrap_or_default(),
                approved_routes: serde_json::from_str(&row.try_get::<String, _>(15)?)
                    .unwrap_or_default(),
                dns_name: row.try_get(5)?,
                user_id: row.try_get(6)?,
                user_role: row.try_get(7)?,
                tags: serde_json::from_str(&row.try_get::<String, _>(8)?).unwrap_or_default(),
                created_at: row.try_get(9)?,
                credential_expires_at: row.try_get(10)?,
                expired: row.try_get::<i64, _>(11)? != 0,
                expires_soon: row.try_get::<i64, _>(12)? != 0,
                revoked: row.try_get::<i64, _>(13)? != 0,
                deleted,
                online: last_seen_at.is_some_and(|seen| current_time - seen <= NODE_ONLINE_SECS)
                    && !deleted,
                last_seen_at,
                os: row.try_get(18)?,
                os_version: row.try_get(19)?,
                agent_version: row.try_get(20)?,
                hostname: row.try_get(21)?,
                capabilities: serde_json::from_str(&row.try_get::<String, _>(22)?)
                    .unwrap_or_default(),
                ephemeral: row.try_get::<i64, _>(23)? != 0,
                shares: shares::parse_shares(
                    &row.try_get::<String, _>(25).unwrap_or_else(|_| "[]".into()),
                ),
                dns_applied_revision: row.try_get::<i64, _>(26).unwrap_or(0),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    nodes.retain(|node| {
        if !include_deleted && node.deleted {
            return false;
        }
        if let Some(state) = state.as_deref() {
            let matches = match state {
                "active" => !node.revoked && !node.deleted && !node.expired,
                "online" => node.online,
                "offline" => !node.online && !node.deleted && !node.revoked,
                "revoked" => node.revoked && !node.deleted,
                "deleted" | "tombstone" => node.deleted,
                "expired" => node.expired && !node.deleted,
                "ephemeral" => node.ephemeral,
                _ => true,
            };
            if !matches {
                return false;
            }
        }
        if let Some(wanted) = wanted.as_deref() {
            let haystack = [
                node.name.as_str(),
                node.display_name.as_deref().unwrap_or(""),
                node.dns_name.as_str(),
                node.hostname.as_deref().unwrap_or(""),
                node.os.as_deref().unwrap_or(""),
                node.agent_version.as_deref().unwrap_or(""),
                &node.id.to_string(),
                &node
                    .shares
                    .iter()
                    .map(|share| share.label.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            ]
            .join(" ")
            .to_ascii_lowercase();
            if !haystack.contains(wanted) {
                return false;
            }
        }
        true
    });
    if let Some(before) = before {
        nodes = match nodes.iter().position(|node| node.id.to_string() == before) {
            Some(position) => nodes.split_off(position + 1),
            None => Vec::new(),
        };
    }
    nodes.truncate(limit as usize);
    Ok(nodes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FriendlyNameUpdate {
    friendly_name: String,
}

fn normalise_friendly_name(value: &str) -> Result<Option<String>, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > MAX_FRIENDLY_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "friendly_name must be at most {MAX_FRIENDLY_NAME_CHARS} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "friendly_name cannot contain control characters".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

async fn update_node_friendly_name(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<FriendlyNameUpdate>,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    let friendly_name = normalise_friendly_name(&input.friendly_name)?;
    let mut tx = s.store.pool.begin().await?;
    let current = sqlx::query(
        "SELECT name,display_name FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>((
            row.try_get::<String, _>(0)?,
            row.try_get::<Option<String>, _>(1)?,
        ))
    })
    .transpose()?;
    let (technical_name, previous_friendly_name) = current.ok_or(ApiError::NotFound)?;
    if previous_friendly_name == friendly_name {
        return Ok(StatusCode::NO_CONTENT);
    }
    sqlx::query("UPDATE nodes SET display_name=$1 WHERE id=$2 AND org_id=$3")
        .bind(&friendly_name)
        .bind(node_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "node.friendly_name_updated",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({
            "friendly_name": friendly_name,
            "previous_friendly_name": previous_friendly_name,
            "technical_name": technical_name,
        }),
    )
    .await?;
    webhooks::enqueue(
        &mut tx,
        org_id,
        "device.renamed",
        &serde_json::json!({
            "device_id": node_id,
            "friendly_name": friendly_name,
        }),
    )
    .await?;
    tx.commit().await?;
    info!(%node_id, %org_id, "node friendly name updated");
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_revoke_node(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE nodes SET revoked_at=$1 WHERE id=$2 AND org_id=$3 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(now())
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "node.revoked",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    webhooks::enqueue(
        &mut tx,
        org_id,
        "device.revoked",
        &serde_json::json!({ "device_id": node_id }),
    )
    .await?;
    tx.commit().await?;
    info!(%node_id, %org_id, "node revoked by console");
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_tombstone_node(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    tombstone_node(&s.store, org_id, node_id, &session).await
}

pub(crate) async fn tombstone_node(
    store: &Store,
    org_id: Uuid,
    node_id: Uuid,
    session: &Session,
) -> Result<StatusCode, ApiError> {
    let mut tx = store.pool.begin().await?;
    let existing = sqlx::query(
        "SELECT name,wg_public_key FROM nodes WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .map(|row| Ok::<_, sqlx::Error>((row.try_get::<String, _>(0)?, row.try_get::<String, _>(1)?)))
    .transpose()?;
    let (technical_name, public_key) = existing.ok_or(ApiError::NotFound)?;
    let tombstone_name = format!("{technical_name}.deleted.{}", &node_id.to_string()[..8]);
    let tombstone_key = format!("{public_key}.deleted");
    let changed = sqlx::query(
        "UPDATE nodes SET deleted_at=$1,revoked_at=COALESCE(revoked_at,$1),name=$2,wg_public_key=$3,token_hash=$4,dns_name=$5 WHERE id=$6 AND org_id=$7 AND deleted_at IS NULL",
    )
    .bind(now())
    .bind(&tombstone_name)
    .bind(&tombstone_key)
    .bind(format!("deleted:{}", hash(&node_id.to_string())))
    .bind(format!("{}.deleted", magic_dns_name(&technical_name, &org_id.to_string())))
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "node.tombstoned",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({
            "technical_name": technical_name,
        }),
    )
    .await?;
    webhooks::enqueue(
        &mut tx,
        org_id,
        "device.deleted",
        &serde_json::json!({ "device_id": node_id }),
    )
    .await?;
    tx.commit().await?;
    info!(%node_id, %org_id, "node tombstoned");
    Ok(StatusCode::NO_CONTENT)
}

async fn expire_ephemeral_nodes(store: &Store, org_id: &str) -> Result<(), ApiError> {
    let cutoff = now() - EPHEMERAL_OFFLINE_SECS;
    let rows = sqlx::query(
        "SELECT id FROM nodes WHERE org_id=$1 AND ephemeral=1 AND deleted_at IS NULL AND (last_seen_at IS NULL OR last_seen_at<$2)",
    )
    .bind(org_id)
    .bind(cutoff)
    .fetch_all(&store.pool)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let session = Session {
        user_id: "coordinator".into(),
        role: Role::Owner,
        name: "BlakTail coordinator".into(),
        email: String::new(),
    };
    for row in rows {
        let id: String = row.try_get(0)?;
        let Ok(node_id) = Uuid::parse_str(&id) else {
            continue;
        };
        let org = Uuid::parse_str(org_id).map_err(|_| ApiError::CorruptData)?;
        let _ = tombstone_node(store, org, node_id, &session).await;
    }
    Ok(())
}

async fn get_acl(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    Ok(Json(load_acl_document(&s.store, org_id).await?))
}
async fn put_acl(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    let mut tx = s.store.pool.begin().await?;
    let current = load_acl_row_tx(&mut tx, org_id).await?;
    if let Some(expected) = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let etag = hash(&current.json);
        let quoted = format!("\"{etag}\"");
        if expected != etag && expected != quoted {
            return Err(ApiError::PreconditionFailed);
        }
    }
    let rollback = value.get("rollback").and_then(serde_json::Value::as_bool) == Some(true);
    let next = if rollback {
        current
            .previous
            .clone()
            .ok_or_else(|| ApiError::BadRequest("no previous policy revision to restore".into()))?
    } else {
        storeable_acl_json(value)?
    };
    let acl: Acl = serde_json::from_str(&next).map_err(|_| ApiError::CorruptData)?;
    publish_acl_tx(&mut tx, org_id, &current.json, &next, current.revision).await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        if rollback {
            "acl.rolled_back"
        } else {
            "acl.updated"
        },
        "acl",
        Some(&org_id.to_string()),
        &serde_json::json!({
            "rule_count": acl.rules.len(),
            "defaults": acl.defaults.as_str(),
            "sha256": hash(&next),
            "revision": current.revision + 1,
        }),
    )
    .await?;
    webhooks::enqueue(
        &mut tx,
        org_id,
        if rollback {
            "policy.rolled_back"
        } else {
            "policy.published"
        },
        &serde_json::json!({
            "revision": current.revision + 1,
            "defaults": acl.defaults.as_str(),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_dns(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<org_dns::OrgDnsResponse>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    Ok(Json(load_org_dns(&s.store, org_id).await?))
}

async fn put_dns(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<Json<org_dns::OrgDnsResponse>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    let mut tx = s.store.pool.begin().await?;
    let current = load_org_dns_tx(&mut tx, org_id).await?;
    if let Some(expected) = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let quoted = format!("\"{}\"", current.etag);
        if expected != current.etag && expected != quoted {
            return Err(ApiError::PreconditionFailed);
        }
    }
    let rollback = value
        .get("rollback")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let next = if rollback {
        load_previous_dns_tx(&mut tx, org_id).await?
    } else {
        let settings = value.get("dns").cloned().unwrap_or(value);
        org_dns::parse_settings(&settings.to_string())?
    };
    publish_org_dns(&mut tx, org_id, &current, &next).await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        if rollback {
            "dns.rolled_back"
        } else {
            "dns.updated"
        },
        "dns",
        Some(&org_id.to_string()),
        &serde_json::json!({
            "revision": current.revision + 1,
            "managed": next.managed,
            "split": next.split.len(),
            "records": next.records.len(),
        }),
    )
    .await?;
    webhooks::enqueue(
        &mut tx,
        org_id,
        if rollback {
            "dns.rolled_back"
        } else {
            "dns.published"
        },
        &serde_json::json!({
            "revision": current.revision + 1,
            "managed": next.managed,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(load_org_dns(&s.store, org_id).await?))
}

pub(crate) async fn load_org_dns(
    store: &Store,
    org_id: Uuid,
) -> Result<org_dns::OrgDnsResponse, ApiError> {
    let row = sqlx::query("SELECT dns_json,dns_revision,dns_previous_json FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&store.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut response = org_dns_from_row(org_id, row.try_get(0)?, row.try_get(1)?, row.try_get(2)?)?;
    let (applied, enrolled) = shares::dns_applied_counts(store, org_id, response.revision).await?;
    response.applied = applied;
    response.enrolled = enrolled;
    Ok(response)
}

pub(crate) async fn load_org_dns_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
) -> Result<org_dns::OrgDnsResponse, ApiError> {
    let row = sqlx::query("SELECT dns_json,dns_revision,dns_previous_json FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    org_dns_from_row(org_id, row.try_get(0)?, row.try_get(1)?, row.try_get(2)?)
}

pub(crate) async fn load_previous_dns_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
) -> Result<org_dns::OrgDnsSettings, ApiError> {
    let previous: Option<String> =
        sqlx::query_scalar("SELECT dns_previous_json FROM orgs WHERE id=$1")
            .bind(org_id.to_string())
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let previous = previous
        .ok_or_else(|| ApiError::BadRequest("no previous DNS revision to restore".into()))?;
    org_dns::parse_settings(&previous)
}

fn org_dns_from_row(
    org_id: Uuid,
    dns_json: String,
    revision: i64,
    previous: Option<String>,
) -> Result<org_dns::OrgDnsResponse, ApiError> {
    let dns = org_dns::parse_settings(&dns_json).unwrap_or_else(|_| org_dns::default_settings());
    let record_preview = dns.record_preview();
    Ok(org_dns::OrgDnsResponse {
        revision,
        etag: hash(&format!("{revision}:{dns_json}")),
        has_previous: previous.as_deref().is_some_and(|value| !value.is_empty()),
        magic_dns_suffix: org_dns::organisation_magic_dns_suffix(&org_id.to_string()),
        dns,
        record_preview,
        applied: 0,
        enrolled: 0,
    })
}

pub(crate) async fn publish_org_dns(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    current: &org_dns::OrgDnsResponse,
    next: &org_dns::OrgDnsSettings,
) -> Result<(), ApiError> {
    let next_json = serde_json::to_string(next).map_err(|_| ApiError::CorruptData)?;
    let previous_json = serde_json::to_string(&current.dns).map_err(|_| ApiError::CorruptData)?;
    let changed =
        sqlx::query("UPDATE orgs SET dns_json=$1,dns_revision=$2,dns_previous_json=$3 WHERE id=$4")
            .bind(&next_json)
            .bind(current.revision + 1)
            .bind(previous_json)
            .bind(org_id.to_string())
            .execute(&mut **tx)
            .await?
            .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    bump_control_revision(tx, org_id.to_string()).await?;
    Ok(())
}

async fn get_security_policy(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SecurityPolicy>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    let node_key_ttl_seconds =
        sqlx::query_scalar("SELECT node_key_ttl_seconds FROM orgs WHERE id=$1")
            .bind(org_id.to_string())
            .fetch_optional(&s.store.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    Ok(Json(SecurityPolicy {
        node_key_ttl_seconds,
    }))
}

async fn put_security_policy(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(policy): Json<SecurityPolicy>,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    validate_node_key_ttl(policy.node_key_ttl_seconds)?;
    let mut tx = s.store.pool.begin().await?;
    let previous: Option<i64> =
        sqlx::query_scalar("SELECT node_key_ttl_seconds FROM orgs WHERE id=$1")
            .bind(org_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
    let previous = previous.ok_or(ApiError::NotFound)?;
    let changed = sqlx::query("UPDATE orgs SET node_key_ttl_seconds=$1 WHERE id=$2")
        .bind(policy.node_key_ttl_seconds)
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "security.updated",
        "security_policy",
        Some(&org_id.to_string()),
        &serde_json::json!({
            "node_key_ttl_seconds": policy.node_key_ttl_seconds,
            "previous_node_key_ttl_seconds": previous,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Default, Deserialize)]
pub(crate) struct AuditQuery {
    limit: Option<u16>,
    before: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub(crate) struct AuditEvent {
    id: String,
    actor_user_id: String,
    actor_name: String,
    actor_email: String,
    actor_role: String,
    action: String,
    target_type: String,
    target_id: Option<String>,
    details: serde_json::Value,
    created_at: i64,
}

async fn list_audit_events(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEvent>>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    purge_expired_audit(&s.store, org_id).await?;
    Ok(Json(load_audit_events(&s.store, org_id, &query).await?))
}

pub(crate) async fn load_audit_events(
    store: &Store,
    org_id: Uuid,
    query: &AuditQuery,
) -> Result<Vec<AuditEvent>, ApiError> {
    let limit = i64::from(query.limit.unwrap_or(100).clamp(1, 200));
    let before = query
        .before
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (before_created_at, before_id) = match before {
        Some(cursor) => {
            let (created_at, id) = cursor
                .split_once(':')
                .ok_or_else(|| ApiError::BadRequest("before must be created_at:id".into()))?;
            let created_at = created_at
                .parse::<i64>()
                .map_err(|_| ApiError::BadRequest("before created_at is invalid".into()))?;
            if id.is_empty() {
                return Err(ApiError::BadRequest("before id is required".into()));
            }
            (Some(created_at), Some(id.to_owned()))
        }
        None => (None, None),
    };
    let rows = if let (Some(created_at), Some(id)) = (before_created_at, before_id) {
        sqlx::query(
            "SELECT id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details_json,created_at FROM audit_events WHERE org_id=$1 AND (created_at<$2 OR (created_at=$2 AND id<$3)) ORDER BY created_at DESC,id DESC LIMIT $4",
        )
        .bind(org_id.to_string())
        .bind(created_at)
        .bind(id)
        .bind(limit)
        .fetch_all(&store.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details_json,created_at FROM audit_events WHERE org_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2",
        )
        .bind(org_id.to_string())
        .bind(limit)
        .fetch_all(&store.pool)
        .await?
    };
    rows.into_iter()
        .map(|row| {
            let details_json: String = row.try_get(8)?;
            Ok::<_, sqlx::Error>(AuditEvent {
                id: row.try_get(0)?,
                actor_user_id: row.try_get(1)?,
                actor_name: row.try_get(2)?,
                actor_email: row.try_get(3)?,
                actor_role: row.try_get(4)?,
                action: row.try_get(5)?,
                target_type: row.try_get(6)?,
                target_id: row.try_get(7)?,
                details: serde_json::from_str(&details_json).unwrap_or_default(),
                created_at: row.try_get(9)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
}

pub(crate) async fn purge_expired_tombstones(store: &Store, org_id: Uuid) -> Result<u64, ApiError> {
    let cutoff = now() - DEFAULT_TOMBSTONE_RETENTION_SECS;
    let deleted = sqlx::query(
        "DELETE FROM nodes WHERE org_id=$1 AND deleted_at IS NOT NULL AND deleted_at<$2",
    )
    .bind(org_id.to_string())
    .bind(cutoff)
    .execute(&store.pool)
    .await?
    .rows_affected();
    Ok(deleted)
}

pub(crate) async fn purge_expired_audit(store: &Store, org_id: Uuid) -> Result<(), ApiError> {
    let retention: i64 = sqlx::query_scalar("SELECT audit_retention_seconds FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&store.pool)
        .await?
        .unwrap_or(DEFAULT_AUDIT_RETENTION_SECS);
    let cutoff = now() - retention.max(86_400);
    sqlx::query("DELETE FROM audit_events WHERE org_id=$1 AND created_at<$2")
        .bind(org_id.to_string())
        .bind(cutoff)
        .execute(&store.pool)
        .await?;
    Ok(())
}

pub(crate) async fn append_audit(
    connection: &mut AnyConnection,
    org_id: Uuid,
    session: &Session,
    action: &str,
    target_type: &str,
    target_id: Option<&str>,
    details: &serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_events(id,org_id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(org_id.to_string())
    .bind(&session.user_id)
    .bind(&session.name)
    .bind(&session.email)
    .bind(session.role.as_str())
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(details.to_string())
    .bind(now())
    .execute(connection)
    .await?;
    Ok(())
}

pub(crate) async fn bump_control_revision(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: impl AsRef<str>,
) -> Result<i64, ApiError> {
    sqlx::query("UPDATE orgs SET control_revision=control_revision+1 WHERE id=$1")
        .bind(org_id.as_ref())
        .execute(&mut **tx)
        .await?;
    sqlx::query_scalar("SELECT control_revision FROM orgs WHERE id=$1")
        .bind(org_id.as_ref())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssertionClaims {
    #[serde(rename = "sub")]
    user_id: String,
    org_id: Uuid,
    role: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    jti: String,
    #[serde(default)]
    action: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Session {
    pub(crate) user_id: String,
    pub(crate) role: Role,
    pub(crate) name: String,
    pub(crate) email: String,
}

pub(crate) async fn console_session(
    state: &AppState,
    headers: &HeaderMap,
    org_id: Uuid,
) -> Result<Session, ApiError> {
    let claims = verified_console_assertion(state, headers, org_id).await?;
    if claims.action.is_some() {
        return Err(ApiError::Unauthorized);
    }
    let role = claims.role.parse().map_err(|_| ApiError::Unauthorized)?;
    Ok(Session {
        user_id: claims.user_id,
        role,
        name: claims.name,
        email: claims.email,
    })
}

async fn service_session(
    state: &AppState,
    headers: &HeaderMap,
    org_id: Uuid,
    action: &str,
) -> Result<AssertionClaims, ApiError> {
    let claims = verified_console_assertion(state, headers, org_id).await?;
    if claims.role != "service" || claims.action.as_deref() != Some(action) {
        return Err(ApiError::Forbidden);
    }
    Ok(claims)
}

async fn verified_console_assertion(
    state: &AppState,
    headers: &HeaderMap,
    org_id: Uuid,
) -> Result<AssertionClaims, ApiError> {
    let token = bearer_value(headers)?;
    let (payload, signature) = token.split_once('.').ok_or(ApiError::Unauthorized)?;
    if signature.contains('.') {
        return Err(ApiError::Unauthorized);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ApiError::Unauthorized)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.auth_hmac_secret)
        .map_err(|_| ApiError::Unauthorized)?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| ApiError::Unauthorized)?;
    let claims: AssertionClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| ApiError::Unauthorized)?,
    )
    .map_err(|_| ApiError::Unauthorized)?;
    let current_time = now();
    if claims.iss != CONSOLE_ASSERTION_ISSUER
        || claims.aud != CONSOLE_ASSERTION_AUDIENCE
        || claims.exp <= current_time
        || claims.iat > current_time + CONSOLE_ASSERTION_CLOCK_SKEW_SECS
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > MAX_CONSOLE_ASSERTION_LIFETIME_SECS
        || claims.org_id != org_id
        || claims.user_id.trim().is_empty()
        || claims.jti.len() < 32
        || claims.jti.len() > 128
    {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("DELETE FROM console_assertion_nonces WHERE expires_at<=$1")
        .bind(current_time)
        .execute(&state.store.pool)
        .await?;
    sqlx::query("INSERT INTO console_assertion_nonces(jti_hash,expires_at) VALUES($1,$2)")
        .bind(hash(&claims.jti))
        .bind(claims.exp)
        .execute(&state.store.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::Unauthorized
            } else {
                ApiError::Database(error)
            }
        })?;
    Ok(claims)
}

fn magic_dns_name(name: &str, org_id: &str) -> String {
    let prefix: String = org_id
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(8)
        .collect();
    let prefix = if prefix.len() == 8 {
        prefix
    } else {
        hash(org_id)[..8].into()
    };
    format!("{}.{}.blaktail", dns_label(name), prefix)
}
fn dns_label(name: &str) -> String {
    let s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let truncated: String = s.trim_matches('-').chars().take(63).collect();
    let label = truncated.trim_matches('-');
    if label.is_empty() {
        "node".into()
    } else {
        label.into()
    }
}

fn default_policy_version() -> u32 {
    1
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AclDefaults {
    #[default]
    SameTag,
    Deny,
}

impl AclDefaults {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SameTag => "same_tag",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Acl {
    #[serde(default = "default_policy_version")]
    version: u32,
    #[serde(default)]
    pub(crate) defaults: AclDefaults,
    #[serde(default)]
    groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    tag_owners: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    hosts: BTreeMap<String, String>,
    #[serde(default)]
    rules: Vec<AclRule>,
    #[serde(default)]
    ssh: Vec<AclSshRule>,
    #[serde(default)]
    tests: Vec<AclTest>,
    #[serde(default)]
    #[allow(dead_code)]
    generated: serde_json::Value,
    #[serde(default)]
    #[allow(dead_code)]
    etag: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    revision: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    has_previous: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AclTest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    src_role: Option<Role>,
    #[serde(default)]
    src_tags: Vec<DeviceTag>,
    #[serde(default)]
    src_user: String,
    #[serde(default)]
    src_email: String,
    #[serde(default)]
    dst_role: Option<Role>,
    #[serde(default)]
    dst_tags: Vec<DeviceTag>,
    #[serde(default)]
    dst_user: String,
    #[serde(default)]
    dst_email: String,
    #[serde(default)]
    dst_host: String,
    #[serde(default)]
    dst_port: Option<u16>,
    #[serde(default)]
    protocol: Option<AclProtocol>,
    #[serde(default)]
    ssh_user: String,
    allow: bool,
}

impl Default for Acl {
    fn default() -> Self {
        Self {
            version: 1,
            defaults: AclDefaults::SameTag,
            groups: BTreeMap::new(),
            tag_owners: BTreeMap::new(),
            hosts: BTreeMap::new(),
            rules: Vec::new(),
            ssh: Vec::new(),
            tests: Vec::new(),
            generated: serde_json::Value::Null,
            etag: None,
            revision: None,
            has_previous: None,
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AclRule {
    action: Action,
    #[serde(default)]
    src_roles: Vec<Role>,
    #[serde(default)]
    src_tags: Vec<DeviceTag>,
    #[serde(default)]
    src_groups: Vec<String>,
    #[serde(default)]
    dst_roles: Vec<Role>,
    #[serde(default)]
    dst_tags: Vec<DeviceTag>,
    #[serde(default)]
    dst_groups: Vec<String>,
    #[serde(default)]
    dst_hosts: Vec<String>,
    #[serde(default)]
    dst_ports: Vec<String>,
    #[serde(default)]
    protocols: Vec<AclProtocol>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AclSshRule {
    action: AclSshAction,
    #[serde(default)]
    src_roles: Vec<Role>,
    #[serde(default)]
    src_tags: Vec<DeviceTag>,
    #[serde(default)]
    src_groups: Vec<String>,
    #[serde(default)]
    dst_roles: Vec<Role>,
    #[serde(default)]
    dst_tags: Vec<DeviceTag>,
    #[serde(default)]
    dst_groups: Vec<String>,
    users: Vec<String>,
    #[serde(default)]
    check_period_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum AclSshAction {
    Allow,
    Deny,
    Check,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Action {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum AclProtocol {
    Tcp,
    Udp,
    Icmp,
}
struct Subject {
    role: Role,
    tags: Vec<DeviceTag>,
    user_id: String,
    email: String,
}
impl Subject {
    fn new(role: Role, tags: Vec<DeviceTag>) -> Self {
        Self {
            role,
            tags,
            user_id: String::new(),
            email: String::new(),
        }
    }
    fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = user_id.into();
        self
    }
}
async fn load_org_acl(store: &Store, org_id: Uuid) -> Result<Acl, ApiError> {
    let acl: String = sqlx::query_scalar("SELECT acl_json FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&store.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    serde_json::from_str(&acl).map_err(|_| ApiError::CorruptData)
}

fn authorize_tag_assignment(
    acl: &Acl,
    session: &Session,
    tags: &[DeviceTag],
) -> Result<(), ApiError> {
    for tag in tags {
        let Some(owners) = acl.tag_owners.get(tag.as_str()) else {
            continue;
        };
        if session.role == Role::Owner {
            continue;
        }
        let allowed = owners.iter().any(|owner| {
            let owner = owner.trim();
            (!session.user_id.is_empty() && owner.eq_ignore_ascii_case(session.user_id.trim()))
                || (!session.email.is_empty() && owner.eq_ignore_ascii_case(session.email.trim()))
                || owner.eq_ignore_ascii_case(session.role.as_str())
        });
        if !allowed {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

impl Acl {
    fn validate(&self) -> Result<(), ApiError> {
        if self.version != 1 {
            return Err(ApiError::BadRequest(format!(
                "unsupported policy version {}",
                self.version
            )));
        }
        if self.tag_owners.len() > 16 {
            return Err(ApiError::BadRequest(
                "ACL tag owners are limited to 16 tags".into(),
            ));
        }
        for (tag, owners) in &self.tag_owners {
            if serde_json::from_value::<DeviceTag>(serde_json::Value::String(tag.clone())).is_err()
            {
                return Err(ApiError::BadRequest(format!(
                    "ACL tag owner key {tag:?} is not a known tag"
                )));
            }
            if owners.is_empty() {
                return Err(ApiError::BadRequest(format!(
                    "ACL tag {tag} must list at least one owner"
                )));
            }
            if owners.iter().any(|owner| owner.trim().is_empty()) {
                return Err(ApiError::BadRequest(format!(
                    "ACL tag {tag} has an empty owner"
                )));
            }
        }
        if self.tests.len() > 128 {
            return Err(ApiError::BadRequest(
                "ACL tests are limited to 128 assertions".into(),
            ));
        }
        if self.hosts.len() > 64 {
            return Err(ApiError::BadRequest(
                "ACL hosts are limited to 64 named addresses".into(),
            ));
        }
        for (name, target) in &self.hosts {
            if !valid_acl_group_name(name) {
                return Err(ApiError::BadRequest(format!(
                    "ACL host name {name:?} must be 1-32 lowercase letters, digits, or hyphens"
                )));
            }
            parse_acl_host_target(target)?;
        }
        if self.groups.len() > 64 {
            return Err(ApiError::BadRequest(
                "ACL groups are limited to 64 named sets".into(),
            ));
        }
        for (name, members) in &self.groups {
            if !valid_acl_group_name(name) {
                return Err(ApiError::BadRequest(format!(
                    "ACL group name {name:?} must be 1-32 lowercase letters, digits, or hyphens"
                )));
            }
            if members.is_empty() {
                return Err(ApiError::BadRequest(format!(
                    "ACL group {name} must include at least one person"
                )));
            }
            if members.len() > 256 {
                return Err(ApiError::BadRequest(format!(
                    "ACL group {name} is limited to 256 people"
                )));
            }
            if members.iter().any(|member| member.trim().is_empty()) {
                return Err(ApiError::BadRequest(format!(
                    "ACL group {name} has an empty member"
                )));
            }
        }
        if self.rules.iter().any(|r| {
            r.src_roles.is_empty()
                && r.src_tags.is_empty()
                && r.src_groups.is_empty()
                && r.dst_roles.is_empty()
                && r.dst_tags.is_empty()
                && r.dst_groups.is_empty()
                && r.dst_hosts.is_empty()
        }) {
            return Err(ApiError::BadRequest(
                "ACL rules must select a source or destination".into(),
            ));
        }
        for rule in &self.rules {
            for name in rule.src_groups.iter().chain(rule.dst_groups.iter()) {
                if !self.groups.contains_key(name) {
                    return Err(ApiError::BadRequest(format!(
                        "ACL rule refers to unknown group {name}"
                    )));
                }
            }
            for name in &rule.dst_hosts {
                if !self.hosts.contains_key(name) {
                    return Err(ApiError::BadRequest(format!(
                        "ACL rule refers to unknown host {name}"
                    )));
                }
            }
            if rule.dst_ports.len() > 16 {
                return Err(ApiError::BadRequest(
                    "ACL rules are limited to 16 destination port ranges".into(),
                ));
            }
            for spec in &rule.dst_ports {
                parse_acl_port_spec(spec)?;
            }
            if rule.protocols.contains(&AclProtocol::Icmp) && !rule.dst_ports.is_empty() {
                return Err(ApiError::BadRequest(
                    "ACL ICMP rules cannot name destination ports".into(),
                ));
            }
        }
        if self.ssh.len() > 32 {
            return Err(ApiError::BadRequest(
                "ACL SSH rules are limited to 32 entries".into(),
            ));
        }
        if self.ssh.iter().any(|rule| {
            rule.src_roles.is_empty()
                && rule.src_tags.is_empty()
                && rule.src_groups.is_empty()
                && rule.dst_roles.is_empty()
                && rule.dst_tags.is_empty()
                && rule.dst_groups.is_empty()
        }) {
            return Err(ApiError::BadRequest(
                "ACL SSH rules must select a source or destination".into(),
            ));
        }
        for rule in &self.ssh {
            for name in rule.src_groups.iter().chain(rule.dst_groups.iter()) {
                if !self.groups.contains_key(name) {
                    return Err(ApiError::BadRequest(format!(
                        "ACL SSH rule refers to unknown group {name}"
                    )));
                }
            }
            if rule.users.is_empty() || rule.users.len() > 16 {
                return Err(ApiError::BadRequest(
                    "ACL SSH rules must name 1-16 operating-system users".into(),
                ));
            }
            for user in &rule.users {
                if !valid_ssh_os_user(user) {
                    return Err(ApiError::BadRequest(format!(
                        "ACL SSH user {user:?} must be * or a 1-32 character login"
                    )));
                }
            }
            match (rule.action, rule.check_period_secs) {
                (AclSshAction::Check, Some(period))
                    if !(1..=7 * 24 * 60 * 60).contains(&period) =>
                {
                    return Err(ApiError::BadRequest(
                        "ACL SSH check period must be 1-604800 seconds".into(),
                    ));
                }
                (AclSshAction::Check, _) => {}
                (_, Some(_)) => {
                    return Err(ApiError::BadRequest(
                        "ACL SSH check period is only valid on check actions".into(),
                    ));
                }
                _ => {}
            }
        }
        for (index, test) in self.tests.iter().enumerate() {
            if !test.dst_host.is_empty() && !self.hosts.contains_key(&test.dst_host) {
                return Err(ApiError::BadRequest(format!(
                    "ACL test refers to unknown host {}",
                    test.dst_host
                )));
            }
            if test.dst_port == Some(0) {
                return Err(ApiError::BadRequest(
                    "ACL test destination port must be 1-65535".into(),
                ));
            }
            if test.protocol == Some(AclProtocol::Icmp) && test.dst_port.is_some() {
                return Err(ApiError::BadRequest(
                    "ACL ICMP tests cannot name a destination port".into(),
                ));
            }
            if !test.ssh_user.is_empty()
                && (test.dst_port.is_some() || test.protocol.is_some() || !test.dst_host.is_empty())
            {
                return Err(ApiError::BadRequest(
                    "ACL SSH tests cannot name a host, port, or protocol".into(),
                ));
            }
            if !test.ssh_user.is_empty() && !valid_ssh_os_user(&test.ssh_user) {
                return Err(ApiError::BadRequest(format!(
                    "ACL SSH test user {:?} must be * or a 1-32 character login",
                    test.ssh_user
                )));
            }
            let src = Subject {
                email: test.src_email.clone(),
                ..Subject::new(test.src_role.unwrap_or(Role::Member), test.src_tags.clone())
                    .with_user(test.src_user.clone())
            };
            let dst = Subject {
                email: test.dst_email.clone(),
                ..Subject::new(test.dst_role.unwrap_or(Role::Member), test.dst_tags.clone())
                    .with_user(test.dst_user.clone())
            };
            let allowed = if test.ssh_user.is_empty() {
                self.allows_flow(
                    &src,
                    &dst,
                    test.dst_port,
                    test.protocol,
                    (!test.dst_host.is_empty()).then_some(test.dst_host.as_str()),
                )
            } else {
                self.allows_ssh(&src, &dst, &test.ssh_user)
            };
            if allowed != test.allow {
                let label = if test.name.is_empty() {
                    format!("#{}", index + 1)
                } else {
                    test.name.clone()
                };
                return Err(ApiError::BadRequest(format!(
                    "ACL test {label} expected allow={} but evaluator returned {allowed}",
                    test.allow
                )));
            }
        }
        Ok(())
    }
    fn allows(&self, s: &Subject, d: &Subject) -> bool {
        let ingress = self.peer_ingress(s, d);
        ingress.all || ingress.icmp || !ingress.tcp.is_empty() || !ingress.udp.is_empty()
    }

    fn allows_flow(
        &self,
        s: &Subject,
        d: &Subject,
        port: Option<u16>,
        protocol: Option<AclProtocol>,
        host: Option<&str>,
    ) -> bool {
        let matching: Vec<_> = self
            .rules
            .iter()
            .filter(|r| self.rule_matches(r, s, d, port, protocol, host))
            .collect();
        if matching.iter().any(|r| r.action == Action::Deny) {
            return false;
        }
        if matching.iter().any(|r| r.action == Action::Allow) {
            return true;
        }
        if host.is_some() {
            return false;
        }
        match self.defaults {
            AclDefaults::Deny => false,
            AclDefaults::SameTag => {
                if s.tags.is_empty() && d.tags.is_empty() {
                    return true;
                }
                s.tags.iter().any(|t| d.tags.contains(t))
            }
        }
    }

    fn rule_matches(
        &self,
        rule: &AclRule,
        s: &Subject,
        d: &Subject,
        port: Option<u16>,
        protocol: Option<AclProtocol>,
        host: Option<&str>,
    ) -> bool {
        if !selector(
            &rule.src_roles,
            &rule.src_tags,
            &rule.src_groups,
            s,
            &self.groups,
        ) {
            return false;
        }
        match host {
            Some(name) => {
                if !rule.dst_hosts.is_empty() && !rule.dst_hosts.iter().any(|item| item == name) {
                    return false;
                }
                if !selector(
                    &rule.dst_roles,
                    &rule.dst_tags,
                    &rule.dst_groups,
                    d,
                    &self.groups,
                ) {
                    return false;
                }
            }
            None => {
                if !rule.dst_hosts.is_empty() {
                    return false;
                }
                if !selector(
                    &rule.dst_roles,
                    &rule.dst_tags,
                    &rule.dst_groups,
                    d,
                    &self.groups,
                ) {
                    return false;
                }
            }
        }
        port_spec_matches(&rule.dst_ports, port) && protocol_matches(&rule.protocols, protocol)
    }

    fn allows_ssh(&self, s: &Subject, d: &Subject, user: &str) -> bool {
        let matching: Vec<_> = self
            .ssh
            .iter()
            .filter(|rule| self.ssh_rule_matches(rule, s, d, user))
            .collect();
        if matching
            .iter()
            .any(|rule| rule.action == AclSshAction::Deny)
        {
            return false;
        }
        matching
            .iter()
            .any(|rule| matches!(rule.action, AclSshAction::Allow | AclSshAction::Check))
    }

    fn peer_ingress(&self, s: &Subject, d: &Subject) -> PeerIngress {
        let ssh_users = self.ssh_users_for(s, d);
        let matching: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| self.rule_matches(rule, s, d, None, None, None))
            .collect();
        let unrestricted = |rule: &&AclRule| rule.dst_ports.is_empty() && rule.protocols.is_empty();
        if matching
            .iter()
            .any(|rule| rule.action == Action::Deny && unrestricted(rule))
        {
            return PeerIngress {
                ssh_users,
                ..PeerIngress::default()
            };
        }
        let all = self.implicit_default_allows(s, d)
            || matching
                .iter()
                .any(|rule| rule.action == Action::Allow && unrestricted(rule));
        let mut tcp = BTreeSet::new();
        let mut udp = BTreeSet::new();
        let mut icmp = all;
        let mut deny_tcp = BTreeSet::new();
        let mut deny_udp = BTreeSet::new();
        let mut deny_icmp = false;
        if !all {
            for rule in matching.iter().filter(|rule| rule.action == Action::Allow) {
                Self::collect_service_specs(rule, &mut tcp, &mut udp, &mut icmp);
            }
        }
        for rule in matching.iter().filter(|rule| rule.action == Action::Deny) {
            let mut denied_icmp = false;
            let mut denied_tcp = BTreeSet::new();
            let mut denied_udp = BTreeSet::new();
            Self::collect_service_specs(rule, &mut denied_tcp, &mut denied_udp, &mut denied_icmp);
            deny_tcp.extend(denied_tcp);
            deny_udp.extend(denied_udp);
            deny_icmp |= denied_icmp;
        }
        if deny_icmp {
            icmp = false;
        }
        if !all && !ssh_users.is_empty() && !specs_cover(&deny_tcp, 22) && !specs_cover(&tcp, 22) {
            tcp.insert("22".into());
        }
        PeerIngress {
            all,
            tcp: tcp.into_iter().collect(),
            udp: udp.into_iter().collect(),
            icmp,
            deny_tcp: deny_tcp.into_iter().collect(),
            deny_udp: deny_udp.into_iter().collect(),
            deny_icmp,
            ssh_users,
        }
    }

    fn implicit_default_allows(&self, s: &Subject, d: &Subject) -> bool {
        match self.defaults {
            AclDefaults::Deny => false,
            AclDefaults::SameTag => {
                (s.tags.is_empty() && d.tags.is_empty())
                    || s.tags.iter().any(|tag| d.tags.contains(tag))
            }
        }
    }

    fn collect_service_specs(
        rule: &AclRule,
        tcp: &mut BTreeSet<String>,
        udp: &mut BTreeSet<String>,
        icmp: &mut bool,
    ) {
        let all_protocols = rule.protocols.is_empty();
        let tcp_ok = all_protocols || rule.protocols.contains(&AclProtocol::Tcp);
        let udp_ok = all_protocols || rule.protocols.contains(&AclProtocol::Udp);
        let icmp_ok = all_protocols || rule.protocols.contains(&AclProtocol::Icmp);
        if rule.dst_ports.is_empty() {
            if tcp_ok {
                tcp.insert("1-65535".into());
            }
            if udp_ok {
                udp.insert("1-65535".into());
            }
            if icmp_ok {
                *icmp = true;
            }
            return;
        }
        for spec in &rule.dst_ports {
            if tcp_ok {
                tcp.insert(spec.clone());
            }
            if udp_ok {
                udp.insert(spec.clone());
            }
        }
    }

    fn ssh_users_for(&self, s: &Subject, d: &Subject) -> Vec<String> {
        let mut allow = BTreeSet::new();
        let mut deny = BTreeSet::new();
        let mut allow_star = false;
        let mut deny_star = false;
        for rule in &self.ssh {
            if !self.ssh_subjects_match(rule, s, d) {
                continue;
            }
            let star = rule.users.iter().any(|user| user == "*");
            match rule.action {
                AclSshAction::Deny => {
                    deny_star |= star;
                    deny.extend(
                        rule.users
                            .iter()
                            .filter(|user| user.as_str() != "*")
                            .cloned(),
                    );
                }
                AclSshAction::Allow | AclSshAction::Check => {
                    allow_star |= star;
                    allow.extend(
                        rule.users
                            .iter()
                            .filter(|user| user.as_str() != "*")
                            .cloned(),
                    );
                }
            }
        }
        if deny_star {
            return Vec::new();
        }
        if allow_star {
            return vec!["*".into()];
        }
        allow.difference(&deny).cloned().collect()
    }

    fn ssh_subjects_match(&self, rule: &AclSshRule, s: &Subject, d: &Subject) -> bool {
        selector(
            &rule.src_roles,
            &rule.src_tags,
            &rule.src_groups,
            s,
            &self.groups,
        ) && selector(
            &rule.dst_roles,
            &rule.dst_tags,
            &rule.dst_groups,
            d,
            &self.groups,
        )
    }

    fn ssh_rule_matches(&self, rule: &AclSshRule, s: &Subject, d: &Subject, user: &str) -> bool {
        if !selector(
            &rule.src_roles,
            &rule.src_tags,
            &rule.src_groups,
            s,
            &self.groups,
        ) {
            return false;
        }
        if !selector(
            &rule.dst_roles,
            &rule.dst_tags,
            &rule.dst_groups,
            d,
            &self.groups,
        ) {
            return false;
        }
        rule.users
            .iter()
            .any(|allowed| allowed == "*" || allowed == user)
    }
}

fn valid_ssh_os_user(user: &str) -> bool {
    if user == "*" {
        return true;
    }
    let mut chars = user.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    user.len() <= 32
        && (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}
fn parse_acl_port_spec(value: &str) -> Result<(u16, u16), ApiError> {
    let value = value.trim();
    if value == "*" {
        return Ok((1, 65535));
    }
    let (start, end) = if let Some((start, end)) = value.split_once('-') {
        (start, end)
    } else {
        (value, value)
    };
    let start: u16 = start.parse().map_err(|_| {
        ApiError::BadRequest(format!("ACL port {value:?} must be 1-65535 or a range"))
    })?;
    let end: u16 = end.parse().map_err(|_| {
        ApiError::BadRequest(format!("ACL port {value:?} must be 1-65535 or a range"))
    })?;
    if start == 0 || end == 0 || start > end {
        return Err(ApiError::BadRequest(format!(
            "ACL port {value:?} must be 1-65535 or a start-end range"
        )));
    }
    Ok((start, end))
}

fn specs_cover(specs: &BTreeSet<String>, port: u16) -> bool {
    specs.iter().any(|spec| {
        parse_acl_port_spec(spec).is_ok_and(|(start, end)| (start..=end).contains(&port))
    })
}

fn port_spec_matches(specs: &[String], port: Option<u16>) -> bool {
    if specs.is_empty() {
        return true;
    }
    let Some(port) = port else {
        return true;
    };
    specs.iter().any(|spec| {
        parse_acl_port_spec(spec).is_ok_and(|(start, end)| (start..=end).contains(&port))
    })
}

fn protocol_matches(protocols: &[AclProtocol], protocol: Option<AclProtocol>) -> bool {
    match protocol {
        None => true,
        Some(wanted) => protocols.is_empty() || protocols.contains(&wanted),
    }
}

fn parse_acl_host_target(value: &str) -> Result<(), ApiError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.contains("blaktail") {
        return Err(ApiError::BadRequest(
            "ACL hosts cannot be empty or use .blaktail names".into(),
        ));
    }
    if value == "0.0.0.0/0" || value == "::/0" {
        return Err(ApiError::BadRequest(
            "ACL hosts cannot name a default route".into(),
        ));
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return require_private_host_ip(address, &value);
    }
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        ApiError::BadRequest(format!(
            "ACL host {value} must be an IPv4/IPv6 address or CIDR"
        ))
    })?;
    let address: IpAddr = address.parse().map_err(|_| {
        ApiError::BadRequest(format!(
            "ACL host {value} must be an IPv4/IPv6 address or CIDR"
        ))
    })?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("ACL host {value} has an invalid prefix")))?;
    match address {
        IpAddr::V4(ip) => {
            if prefix > 32 {
                return Err(ApiError::BadRequest(format!(
                    "ACL host {value} has an invalid prefix"
                )));
            }
            let mask = ipv4_mask(prefix);
            if u32::from(ip) & !mask != 0 {
                return Err(ApiError::BadRequest(format!(
                    "ACL host {value} is not a network address"
                )));
            }
            require_private_host_ip(address, &value)
        }
        IpAddr::V6(ip) => {
            if prefix > 128 {
                return Err(ApiError::BadRequest(format!(
                    "ACL host {value} has an invalid prefix"
                )));
            }
            if prefix < 128 {
                let bits = u128::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                if bits & !mask != 0 {
                    return Err(ApiError::BadRequest(format!(
                        "ACL host {value} is not a network address"
                    )));
                }
            }
            require_private_host_ip(address, &value)
        }
    }
}

fn require_private_host_ip(address: IpAddr, value: &str) -> Result<(), ApiError> {
    let private = match address {
        IpAddr::V4(ip) => ip.is_private() || matches!(ip.octets(), [100, 64..=127, _, _]),
        IpAddr::V6(ip) => (ip.octets()[0] & 0xfe) == 0xfc,
    };
    if address.is_unspecified() || address.is_multicast() || address.is_loopback() || !private {
        return Err(ApiError::BadRequest(format!(
            "ACL host {value} must be a private IPv4 or unique-local IPv6 address"
        )));
    }
    Ok(())
}

fn valid_acl_group_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z'))
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
fn selector(
    roles: &[Role],
    tags: &[DeviceTag],
    groups: &[String],
    s: &Subject,
    named: &BTreeMap<String, Vec<String>>,
) -> bool {
    (roles.is_empty() || roles.contains(&s.role))
        && (tags.is_empty() || tags.iter().any(|t| s.tags.contains(t)))
        && (groups.is_empty()
            || groups.iter().any(|name| {
                named
                    .get(name)
                    .is_some_and(|members| subject_in_group(s, members))
            }))
}
fn subject_in_group(subject: &Subject, members: &[String]) -> bool {
    members.iter().any(|member| {
        let member = member.trim();
        if member.is_empty() {
            return false;
        }
        (!subject.user_id.is_empty() && member.eq_ignore_ascii_case(subject.user_id.trim()))
            || (!subject.email.is_empty() && member.eq_ignore_ascii_case(subject.email.trim()))
    })
}
fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    Ok(hash(bearer_value(headers)?))
}
pub(crate) fn bearer_value(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty())
        .ok_or(ApiError::Unauthorized)
}
pub(crate) fn now() -> i64 {
    Utc::now().timestamp()
}
pub(crate) fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub(crate) fn secret(prefix: &str) -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(b))
}

fn user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let characters: String = random
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect();
    format!("{}-{}", &characters[..4], &characters[4..])
}

fn normalise_user_code(value: &str) -> Option<String> {
    let code: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    (code.len() == 8).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request},
    };
    use tower::ServiceExt;
    const TEST_SECRET: &[u8] = b"test-only-hmac-secret-at-least-32-bytes";
    const TEST_RELAY_SECRET: &[u8] = b"separate-test-relay-secret-32-bytes";

    #[test]
    fn relay_capability_matches_relay_protocol() {
        let node_id = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        let expires_at = 2_000_000_000;
        assert_eq!(
            relay_capability(TEST_RELAY_SECRET, node_id, expires_at),
            hex_encode(&blaktail_relay::mint_token(
                TEST_RELAY_SECRET,
                node_id.as_bytes(),
                expires_at,
            ))
        );
    }
    #[test]
    fn route_validation_rejects_host_bits_tailnet_and_overlap() {
        assert_eq!(
            validate_advertised_routes(vec![
                "10.2.0.0/16".into(),
                "0.0.0.0/0".into(),
                "10.2.0.0/16".into(),
            ])
            .unwrap(),
            vec!["0.0.0.0/0", "10.2.0.0/16"]
        );
        for invalid in [
            "10.2.0.1/16",
            "100.64.2.0/24",
            "128.0.0.0/1",
            "192.0.2.0/24",
            "224.0.0.0/4",
        ] {
            assert!(validate_advertised_routes(vec![invalid.into()]).is_err());
        }
        assert!(
            validate_advertised_routes(vec!["10.2.0.0/16".into(), "10.2.3.0/24".into(),]).is_err()
        );
    }
    fn signed_session(org_id: Uuid, user_id: &str, role: Role, exp: i64) -> String {
        assertion_template(AssertionClaims {
            user_id: user_id.into(),
            org_id,
            role: role.as_str().into(),
            name: user_id.into(),
            email: format!("{user_id}@example.com"),
            iss: CONSOLE_ASSERTION_ISSUER.into(),
            aud: CONSOLE_ASSERTION_AUDIENCE.into(),
            iat: exp - MAX_CONSOLE_ASSERTION_LIFETIME_SECS,
            exp,
            jti: String::new(),
            action: None,
        })
    }
    fn signed_service(org_id: Uuid, action: &str) -> String {
        let current_time = now();
        assertion_template(AssertionClaims {
            user_id: "operator-cli".into(),
            org_id,
            role: "service".into(),
            name: "BlakTail operator".into(),
            email: String::new(),
            iss: CONSOLE_ASSERTION_ISSUER.into(),
            aud: CONSOLE_ASSERTION_AUDIENCE.into(),
            iat: current_time,
            exp: current_time + MAX_CONSOLE_ASSERTION_LIFETIME_SECS,
            jti: String::new(),
            action: Some(action.into()),
        })
    }
    fn assertion_template(claims: AssertionClaims) -> String {
        format!(
            "test:{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        )
    }
    fn sign_test_assertion(template: &str) -> String {
        let encoded = template
            .strip_prefix("test:")
            .expect("test assertion template");
        let mut claims: AssertionClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        claims.jti = Uuid::new_v4().to_string();
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET).unwrap();
        mac.update(payload.as_bytes());
        format!(
            "{payload}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }
    async fn call(
        r: &Router,
        m: Method,
        u: &str,
        b: serde_json::Value,
        t: Option<&str>,
    ) -> Response {
        let mut q = Request::builder()
            .method(m)
            .uri(u)
            .header("content-type", "application/json");
        if let Some(t) = t {
            let token = if t.starts_with("test:") {
                sign_test_assertion(t)
            } else {
                t.to_owned()
            };
            q = q.header(AUTHORIZATION, format!("Bearer {token}"))
        }
        r.clone()
            .oneshot(q.body(Body::from(b.to_string())).unwrap())
            .await
            .unwrap()
    }
    async fn body<T: serde::de::DeserializeOwned>(r: Response) -> T {
        serde_json::from_slice(&to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    async fn create_test_org(router: &Router, name: &str) -> OrgResponse {
        let id = Uuid::new_v4();
        let service = signed_service(id, "bootstrap.prepare");
        let response = call(
            router,
            Method::POST,
            "/v1/orgs",
            serde_json::json!({"id":id,"name":name,"acl":{"version":1,"defaults":"same_tag","rules":[]}}),
            Some(&service),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let service = signed_service(id, "bootstrap.commit");
        let response = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{id}/bootstrap-commit"),
            serde_json::json!({}),
            Some(&service),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        body(response).await
    }

    async fn register_test_node(
        router: &Router,
        org_id: Uuid,
        session: &str,
        name: &str,
        public_key: &str,
        advertised_routes: &[&str],
    ) -> RegisterResponse {
        let key: JoinKeyResponse = body(
            call(
                router,
                Method::POST,
                &format!("/v1/orgs/{org_id}/join-keys"),
                serde_json::json!({"expires_in_seconds":60}),
                Some(session),
            )
            .await,
        )
        .await;
        let response = call(
            router,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key":key.key,
                "name":name,
                "wg_public_key":public_key,
                "advertised_routes":advertised_routes,
            }),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        body(response).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_replicas_share_state_and_serialize_single_use_keys() {
        let Ok(database_url) = std::env::var("BLAKTAIL_COORD_TEST_DATABASE_URL") else {
            return;
        };
        assert!(
            database_url.contains("/blaktail_coord_test"),
            "PostgreSQL integration tests require a dedicated blaktail_coord_test database"
        );

        let cleanup = connect_postgres(&database_url).await.unwrap();
        sqlx::raw_sql(
            "DROP TABLE IF EXISTS wireguard_only_peers,api_idempotency,api_clients,pending_bootstrap_orgs,console_assertion_nonces,audit_events,nodes,device_authorizations,join_keys,orgs,coordinator_schema_migrations CASCADE",
        )
        .execute(&cleanup)
        .await
        .unwrap();
        cleanup.close().await;

        let (first_migration, second_migration) = tokio::join!(
            Store::migrate_postgres(&database_url),
            Store::migrate_postgres(&database_url)
        );
        first_migration.unwrap().pool.close().await;
        second_migration.unwrap().pool.close().await;

        let first = Store::open_existing_postgres(&database_url).await.unwrap();
        let second = Store::open_existing_postgres(&database_url).await.unwrap();
        let first_router = app(first.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let second_router = app(second.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&first_router, "postgres-ha-org").await;
        let owner = signed_session(org.id, "owner-ha", Role::Owner, now() + 60);
        let join_key: JoinKeyResponse = body(
            call(
                &first_router,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", org.id),
                serde_json::json!({"expires_in_seconds":60,"single_use":true}),
                Some(&owner),
            )
            .await,
        )
        .await;

        let first_registration = call(
            &first_router,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key":join_key.key,
                "name":"postgres-node-a",
                "wg_public_key":"postgres-key-a"
            }),
            None,
        );
        let second_registration = call(
            &second_router,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key":join_key.key,
                "name":"postgres-node-b",
                "wg_public_key":"postgres-key-b"
            }),
            None,
        );
        let (first_response, second_response) =
            tokio::join!(first_registration, second_registration);
        let mut statuses = [first_response.status(), second_response.status()];
        statuses.sort();
        assert_eq!(statuses, [StatusCode::CREATED, StatusCode::UNAUTHORIZED]);

        let nodes: Vec<NodeRow> = body(
            call(
                &second_router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(nodes.len(), 1);

        drop(first_router);
        first.pool.close().await;
        assert_eq!(
            call(
                &second_router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::OK
        );

        drop(second_router);
        second.pool.close().await;
        let cleanup = connect_postgres(&database_url).await.unwrap();
        sqlx::raw_sql(
            "DROP TABLE IF EXISTS wireguard_only_peers,api_idempotency,api_clients,pending_bootstrap_orgs,console_assertion_nonces,audit_events,nodes,device_authorizations,join_keys,orgs,coordinator_schema_migrations CASCADE",
        )
        .execute(&cleanup)
        .await
        .unwrap();
        cleanup.close().await;
    }

    #[tokio::test]
    async fn metrics_and_audit_cover_security_mutations() {
        let store = Store::memory().await.unwrap();
        let metrics = Arc::new(CoordMetrics::default());
        let router = app_with_relays_console_and_metrics(
            store.clone(),
            "ap-southeast-2".into(),
            TEST_SECRET,
            TEST_RELAY_SECRET,
            vec![],
            DEFAULT_CONSOLE_URL.into(),
            metrics.clone(),
        );
        let org = create_test_org(&router, "observable-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let node = register_test_node(
            &router,
            org.id,
            &owner,
            "router-one",
            "router-key",
            &["10.4.0.0/24"],
        )
        .await;

        assert_eq!(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/nodes/{}/routes", org.id, node.id),
                serde_json::json!({"approved_routes":["10.4.0.0/24"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::json!({"rules":[{"action":"allow","src_roles":["owner"]}]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/security", org.id),
                serde_json::json!({"node_key_ttl_seconds":86400}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &format!("/v1/orgs/{}/nodes/{}", org.id, node.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        let audit: Vec<AuditEvent> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/audit", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        let actions = audit
            .iter()
            .map(|event| event.action.as_str())
            .collect::<Vec<_>>();
        for action in [
            "join_key.minted",
            "node.routes_updated",
            "acl.updated",
            "security.updated",
            "node.revoked",
        ] {
            assert!(actions.contains(&action), "missing audit action {action}");
        }
        assert!(audit
            .iter()
            .filter(|event| event.actor_role != "service")
            .all(|event| event.actor_email == "owner-1@example.com"));
        assert!(audit.iter().any(|event| {
            event.action == "bootstrap.completed"
                && event.actor_role == "service"
                && event.details["source"] == "operator_channel"
        }));
        assert!(!serde_json::to_string(&audit).unwrap().contains("btk_"));

        let metrics_response = metrics_app(store, metrics)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics_response.status(), StatusCode::OK);
        let metrics_text = String::from_utf8(
            to_bytes(metrics_response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(metrics_text.contains(
            "blaktail_coord_requests_total{operation=\"register\",result=\"success\"} 1"
        ));
        assert!(metrics_text
            .contains("blaktail_coord_requests_total{operation=\"peers\",result=\"success\"} 1"));
        assert!(metrics_text
            .contains("blaktail_coord_requests_total{operation=\"revoke\",result=\"success\"} 1"));
        assert!(metrics_text.contains("blaktail_coord_active_nodes 0"));
    }

    #[tokio::test]
    async fn friendly_names_are_admin_scoped_audited_and_do_not_change_network_identity() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "friendly-name-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let node =
            register_test_node(&router, org.id, &owner, "field-tablet-01", "key-1", &[]).await;
        let path = format!("/v1/orgs/{}/nodes/{}/friendly-name", org.id, node.id);

        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                serde_json::json!({"friendly_name":"Ranger Mary's tablet"}),
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                serde_json::json!({"friendly_name":"x".repeat(MAX_FRIENDLY_NAME_CHARS + 1)}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                serde_json::json!({"friendly_name":"line\nbreak"}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                serde_json::json!({"friendly_name":"  Ranger Mary's tablet  "}),
                Some(&admin),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                serde_json::json!({"friendly_name":"Ranger Mary's tablet"}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        let renamed: Vec<NodeRow> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(renamed[0].name, "field-tablet-01");
        assert_eq!(
            renamed[0].display_name.as_deref(),
            Some("Ranger Mary's tablet")
        );
        assert_eq!(renamed[0].dns_name, node.dns_name);

        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                serde_json::json!({"friendly_name":""}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let cleared: Vec<NodeRow> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(cleared[0].display_name, None);

        let audit: Vec<AuditEvent> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/audit", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        let name_updates = audit
            .iter()
            .filter(|event| event.action == "node.friendly_name_updated")
            .collect::<Vec<_>>();
        assert_eq!(name_updates.len(), 2);
        assert!(name_updates
            .iter()
            .any(|event| event.details["friendly_name"] == serde_json::Value::Null));
        assert!(name_updates
            .iter()
            .any(|event| event.details["friendly_name"] == "Ranger Mary's tablet"));
    }

    #[tokio::test]
    async fn ipv6_addresses_are_org_scoped_and_capability_gated() {
        fn ipv6(response: &RegisterResponse) -> Ipv6Addr {
            response
                .assigned_ips
                .iter()
                .find_map(|address| address.split('/').next()?.parse().ok())
                .expect("dual-stack registration includes IPv6")
        }

        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org_a = create_test_org(&router, "ipv6-org-a").await;
        let org_b = create_test_org(&router, "ipv6-org-b").await;
        let owner_a = signed_session(org_a.id, "owner-a", Role::Owner, now() + 60);
        let owner_b = signed_session(org_b.id, "owner-b", Role::Owner, now() + 60);
        let node_a = register_test_node(&router, org_a.id, &owner_a, "a", "key-a", &[]).await;
        let node_b = register_test_node(&router, org_a.id, &owner_a, "b", "key-b", &[]).await;
        let node_c = register_test_node(&router, org_b.id, &owner_b, "c", "key-c", &[]).await;

        assert_eq!(node_a.assigned_ips.len(), 2);
        assert_eq!(node_a.assigned_ip, node_a.assigned_ips[0]);
        let address_a = ipv6(&node_a).octets();
        let address_b = ipv6(&node_b).octets();
        let address_c = ipv6(&node_c).octets();
        assert_eq!(address_a[0], 0xfd);
        assert_eq!(&address_a[..8], &address_b[..8]);
        assert_ne!(&address_a[..8], &address_c[..8]);
        assert_ne!(address_a, address_b);

        let legacy: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node_a.id),
                serde_json::Value::Null,
                Some(&node_a.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(legacy.assigned_ips, vec![node_a.assigned_ip.clone()]);
        assert_eq!(legacy.peers[0].allowed_ips.len(), 1);

        let dual_stack: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers?ipv6=true", node_a.id),
                serde_json::Value::Null,
                Some(&node_a.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(dual_stack.assigned_ips, node_a.assigned_ips);
        assert_eq!(dual_stack.peers[0].allowed_ips, node_b.assigned_ips);

        let mut tx = store.pool.begin().await.unwrap();
        sqlx::query("UPDATE nodes SET allowed_ips_json=$1 WHERE id=$2")
            .bind(serde_json::to_string(&vec![node_b.assigned_ip.clone()]).unwrap())
            .bind(node_b.id.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        backfill_ipv6_addresses(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        let restored: String = sqlx::query_scalar("SELECT allowed_ips_json FROM nodes WHERE id=$1")
            .bind(node_b.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&restored).unwrap(),
            node_b.assigned_ips
        );
    }

    #[tokio::test]
    async fn only_approved_routes_are_distributed_and_exit_nodes_are_opt_in() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "routing-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let injection_key: JoinKeyResponse = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", org.id),
                serde_json::json!({"expires_in_seconds":60}),
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(
            call(
                &router,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key":injection_key.key,
                    "name":"address-injector",
                    "wg_public_key":"address-injector-key",
                    "allowed_ips":["10.0.0.1/32"],
                }),
                None,
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let subnet_router = register_test_node(
            &router,
            org.id,
            &owner,
            "router-one",
            "router-key",
            &["10.1.0.0/24", "0.0.0.0/0"],
        )
        .await;
        let client =
            register_test_node(&router, org.id, &owner, "client-one", "client-key", &[]).await;

        let before: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", client.id),
                serde_json::Value::Null,
                Some(&client.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(before.peers[0].allowed_ips, vec!["100.64.0.1/32"]);
        assert!(!before.exit_node_active);

        let nodes: Vec<NodeRow> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        let listed_router = nodes
            .iter()
            .find(|node| node.id == subnet_router.id)
            .unwrap();
        assert_eq!(
            listed_router.advertised_routes,
            vec!["0.0.0.0/0", "10.1.0.0/24"]
        );
        assert!(listed_router.approved_routes.is_empty());

        let approval_path = format!("/v1/orgs/{}/nodes/{}/routes", org.id, subnet_router.id);
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &approval_path,
                serde_json::json!({"approved_routes":["10.1.0.0/24"]}),
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &approval_path,
                serde_json::json!({"approved_routes":["10.1.0.0/24","0.0.0.0/0"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        let routed: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", client.id),
                serde_json::Value::Null,
                Some(&client.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(
            routed.peers[0].allowed_ips,
            vec!["100.64.0.1/32", "10.1.0.0/24"]
        );
        assert!(!routed.exit_node_active);

        let exited: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers?exit_node=router-one", client.id),
                serde_json::Value::Null,
                Some(&client.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(
            exited.peers[0].allowed_ips,
            vec!["100.64.0.1/32", "0.0.0.0/0", "10.1.0.0/24"]
        );
        assert!(exited.exit_node_active);
        let missing_exit: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers?exit_node=missing", client.id),
                serde_json::Value::Null,
                Some(&client.node_token),
            )
            .await,
        )
        .await;
        assert!(!missing_exit.exit_node_active);
        assert!(!missing_exit.peers[0]
            .allowed_ips
            .contains(&"0.0.0.0/0".into()));

        assert_eq!(
            call(
                &router,
                Method::PUT,
                &approval_path,
                serde_json::json!({"approved_routes":["10.2.0.0/24"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let overlapping = register_test_node(
            &router,
            org.id,
            &owner,
            "router-two",
            "router-key-two",
            &["10.1.0.0/25"],
        )
        .await;
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/nodes/{}/routes", org.id, overlapping.id),
                serde_json::json!({"approved_routes":["10.1.0.0/25"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );

        assert_eq!(
            call(
                &router,
                Method::PUT,
                &approval_path,
                serde_json::json!({"approved_routes":["10.1.0.0/24"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        sqlx::query("UPDATE nodes SET credential_expires_at=$1 WHERE id=$2")
            .bind(now() - 1)
            .bind(subnet_router.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &approval_path,
                serde_json::json!({"approved_routes":["10.1.0.0/24","0.0.0.0/0"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/nodes/{}/routes", org.id, overlapping.id),
                serde_json::json!({"approved_routes":["10.1.0.0/25"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let expired_approvals: String =
            sqlx::query_scalar("SELECT approved_routes_json FROM nodes WHERE id=$1")
                .bind(subnet_router.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(expired_approvals, "[]");
        sqlx::query("UPDATE nodes SET credential_expires_at=$1 WHERE id=$2")
            .bind(now() + 60)
            .bind(subnet_router.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/nodes/{}/routes", subnet_router.id),
                serde_json::json!({"advertised_routes":["10.2.0.0/24"]}),
                Some(&subnet_router.node_token),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let after_update: Vec<NodeRow> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        let listed_router = after_update
            .iter()
            .find(|node| node.id == subnet_router.id)
            .unwrap();
        assert_eq!(listed_router.advertised_routes, vec!["10.2.0.0/24"]);
        assert!(listed_router.approved_routes.is_empty());
    }

    #[tokio::test]
    async fn browser_enrollment_is_expiring_single_use_and_bound_to_device() {
        let store = Store::memory().await.unwrap();
        let r = app_with_relays_and_console(
            store.clone(),
            "ap-southeast-2".into(),
            TEST_SECRET,
            TEST_RELAY_SECRET,
            vec![],
            "https://console.example.org.au/".into(),
        );
        let org = create_test_org(&r, "browser-org").await;
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let existing_key: JoinKeyResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", org.id),
                serde_json::json!({"expires_in_seconds":60}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let existing: RegisterResponse = body(
            call(
                &r,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key": existing_key.key,
                    "name": "existing-node",
                    "wg_public_key": "existing-public-key"
                }),
                None,
            )
            .await,
        )
        .await;
        let started_response = call(
            &r,
            Method::POST,
            "/v1/device-authorizations",
            serde_json::json!({"name":"ssh-node","wg_public_key":"browser-public-key"}),
            None,
        )
        .await;
        assert_eq!(started_response.status(), StatusCode::CREATED);
        let started: DeviceAuthorizationResponse = body(started_response).await;
        assert_eq!(
            started.verification_url,
            format!(
                "https://console.example.org.au/enroll?code={}",
                started.user_code
            )
        );
        assert_eq!(started.interval_seconds, DEVICE_AUTH_POLL_SECS);
        assert!(started.expires_at > now());

        assert_eq!(
            call(
                &r,
                Method::GET,
                &format!("/v1/device-authorizations/{}", started.device_code),
                serde_json::Value::Null,
                None,
            )
            .await
            .status(),
            StatusCode::ACCEPTED
        );
        let throttled = call(
            &r,
            Method::GET,
            &format!("/v1/device-authorizations/{}", started.device_code),
            serde_json::Value::Null,
            None,
        )
        .await;
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            throttled.headers().get("retry-after").unwrap(),
            DEVICE_AUTH_POLL_SECS.to_string().as_str()
        );
        let preview: DeviceAuthorizationPreview = body(
            call(
                &r,
                Method::GET,
                &format!(
                    "/v1/orgs/{}/device-authorizations/{}",
                    org.id, started.user_code
                ),
                serde_json::Value::Null,
                Some(&member),
            )
            .await,
        )
        .await;
        assert_eq!(preview.name, "ssh-node");
        assert_eq!(
            preview.public_key_fingerprint,
            &hash("browser-public-key")[..12]
        );
        assert!(!preview.approved);

        let approval: DeviceAuthorizationApproval = body(
            call(
                &r,
                Method::POST,
                &format!(
                    "/v1/orgs/{}/device-authorizations/{}",
                    org.id, started.user_code
                ),
                serde_json::json!({"tags":["office"]}),
                Some(&member),
            )
            .await,
        )
        .await;
        assert_eq!(approval.status, "approved");
        assert_eq!(approval.expires_at, started.expires_at);
        sqlx::query("UPDATE device_authorizations SET last_polled_at=$1 WHERE device_code_hash=$2")
            .bind(now() - DEVICE_AUTH_POLL_SECS as i64)
            .bind(hash(&started.device_code))
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            call(
                &r,
                Method::POST,
                &format!("/v1/nodes/{}/reauth", existing.id),
                serde_json::json!({"join_key":started.device_code}),
                Some(&existing.node_token),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &r,
                Method::GET,
                &format!("/v1/device-authorizations/{}", started.device_code),
                serde_json::Value::Null,
                None,
            )
            .await
            .status(),
            StatusCode::OK
        );

        let wrong_identity = call(
            &r,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key": started.device_code,
                "name": "different-node",
                "wg_public_key": "browser-public-key"
            }),
            None,
        )
        .await;
        assert_eq!(wrong_identity.status(), StatusCode::BAD_REQUEST);
        let registered_response = call(
            &r,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key": started.device_code,
                "name": "ssh-node",
                "wg_public_key": "browser-public-key"
            }),
            None,
        )
        .await;
        assert_eq!(registered_response.status(), StatusCode::CREATED);
        let registered: RegisterResponse = body(registered_response).await;
        assert_eq!(registered.assigned_ip, "100.64.0.2/32");
        assert_eq!(
            call(
                &r,
                Method::GET,
                &format!("/v1/device-authorizations/{}", started.device_code),
                serde_json::Value::Null,
                None,
            )
            .await
            .status(),
            StatusCode::GONE
        );
        assert_eq!(
            call(
                &r,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key": started.device_code,
                    "name": "ssh-node",
                    "wg_public_key": "browser-public-key"
                }),
                None,
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );

        let row = sqlx::query("SELECT user_role,tags_json FROM nodes WHERE id=$1")
            .bind(registered.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let role: String = row.try_get(0).unwrap();
        let tags: String = row.try_get(1).unwrap();
        assert_eq!(role, "member");
        assert_eq!(tags, "[]");
        let browser_audit = sqlx::query_scalar::<_, String>(
            "SELECT action FROM audit_events WHERE org_id=$1 ORDER BY action",
        )
        .bind(org.id.to_string())
        .fetch_all(&store.pool)
        .await
        .unwrap();
        assert!(browser_audit.contains(&"device_authorization.approved".into()));
        assert!(browser_audit.contains(&"join_key.minted".into()));
        let raw_secrets: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_authorizations d JOIN join_keys k ON k.key_hash=d.device_code_hash WHERE d.device_code_hash=$1 OR k.key_hash=$1",
        )
        .bind(started.device_code)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(raw_secrets, 0);
    }

    #[tokio::test]
    async fn expired_browser_enrollment_cannot_be_polled_or_approved() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "expired-browser-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let started: DeviceAuthorizationResponse = body(
            call(
                &r,
                Method::POST,
                "/v1/device-authorizations",
                serde_json::json!({"name":"late-node","wg_public_key":"late-key"}),
                None,
            )
            .await,
        )
        .await;
        sqlx::query("UPDATE device_authorizations SET expires_at=$1 WHERE device_code_hash=$2")
            .bind(now() - 1)
            .bind(hash(&started.device_code))
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            call(
                &r,
                Method::GET,
                &format!("/v1/device-authorizations/{}", started.device_code),
                serde_json::Value::Null,
                None,
            )
            .await
            .status(),
            StatusCode::GONE
        );
        assert_eq!(
            call(
                &r,
                Method::POST,
                &format!(
                    "/v1/orgs/{}/device-authorizations/{}",
                    org.id, started.user_code
                ),
                serde_json::json!({}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::GONE
        );
    }

    #[tokio::test]
    async fn two_nodes_and_revocation() {
        let store = Store::memory().await.unwrap();
        let r = app_with_relays(
            store.clone(),
            "ap-southeast-2".into(),
            TEST_SECRET,
            TEST_RELAY_SECRET,
            vec!["relay.example.org:3478".into()],
        );
        let o = create_test_org(&r, "org").await;
        assert_eq!(o.node_key_ttl_seconds, DEFAULT_NODE_KEY_TTL_SECS);
        let token = signed_session(o.id, "owner-1", Role::Owner, now() + 60);
        let mut ns = vec![];
        for n in 1..=2 {
            let k: JoinKeyResponse = body(
                call(
                    &r,
                    Method::POST,
                    &format!("/v1/orgs/{}/join-keys", o.id),
                    serde_json::json!({"expires_in_seconds":60}),
                    Some(&token),
                )
                .await,
            )
            .await;
            let x=call(&r,Method::POST,"/v1/nodes/register",serde_json::json!({"join_key":k.key,"name":format!("node-{n}"),"wg_public_key":format!("key-{n}")}),None).await;
            assert_eq!(x.status(), StatusCode::CREATED);
            ns.push(body::<RegisterResponse>(x).await)
        }
        for node in &ns {
            assert!(node.credential_expires_at >= now() + DEFAULT_NODE_KEY_TTL_SECS - 1);
            assert!(node.dns_name.ends_with(".blaktail"));
            assert_eq!(node.relays, vec!["relay.example.org:3478"]);
            assert_eq!(
                node.relay_token,
                relay_capability(TEST_RELAY_SECRET, node.id, node.relay_expires_at)
            );
            assert_ne!(
                node.relay_token,
                relay_capability(TEST_SECRET, node.id, node.relay_expires_at)
            );
        }
        let collision_key: JoinKeyResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", o.id),
                serde_json::json!({"expires_in_seconds":60}),
                Some(&token),
            )
            .await,
        )
        .await;
        assert_eq!(
            call(
                &r,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key": collision_key.key,
                    "name": "node 1",
                    "wg_public_key": "distinct-key"
                }),
                None,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(
                &r,
                Method::PUT,
                &format!("/v1/nodes/{}/relay-endpoint", ns[0].id),
                serde_json::json!({"endpoint":"198.51.100.1:40001"}),
                Some("wrong-node-token"),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        for endpoint in ["relay.example.org:3478", "0.0.0.0:3478", "224.0.0.1:3478"] {
            assert_eq!(
                call(
                    &r,
                    Method::PUT,
                    &format!("/v1/nodes/{}/relay-endpoint", ns[0].id),
                    serde_json::json!({"endpoint": endpoint}),
                    Some(&ns[0].node_token),
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for (index, node) in ns.iter().enumerate() {
            assert_eq!(
                call(
                    &r,
                    Method::PUT,
                    &format!("/v1/nodes/{}/relay-endpoint", node.id),
                    serde_json::json!({
                        "endpoint": format!("198.51.100.{}:{}", index + 1, 40_001 + index)
                    }),
                    Some(&node.node_token),
                )
                .await
                .status(),
                StatusCode::NO_CONTENT
            );
        }
        for (i, n) in ns.iter().enumerate() {
            let p: PeersResponse = body(
                call(
                    &r,
                    Method::GET,
                    &format!("/v1/nodes/{}/peers", n.id),
                    serde_json::Value::Null,
                    Some(&n.node_token),
                )
                .await,
            )
            .await;
            assert_eq!(p.peers[0].wg_public_key, format!("key-{}", 2 - i));
            assert_eq!(
                p.peers[0].allowed_ips,
                vec![format!("100.64.0.{}/32", 2 - i)]
            );
            assert_eq!(p.relays, vec!["relay.example.org:3478"]);
            assert_eq!(
                p.relay_token,
                relay_capability(TEST_RELAY_SECRET, n.id, p.relay_expires_at)
            );
            assert_eq!(
                p.peers[0].relay_endpoint,
                Some(format!("198.51.100.{}:{}", 2 - i, 40_002 - i))
            );
            assert_eq!(p.credential_expires_at, n.credential_expires_at);
            assert_eq!(p.dns_name, n.dns_name);
        }

        let policy: SecurityPolicy = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/security", o.id),
                serde_json::Value::Null,
                Some(&token),
            )
            .await,
        )
        .await;
        assert_eq!(policy.node_key_ttl_seconds, DEFAULT_NODE_KEY_TTL_SECS);
        assert_eq!(
            call(
                &r,
                Method::PUT,
                &format!("/v1/orgs/{}/security", o.id),
                serde_json::json!({"node_key_ttl_seconds": MIN_NODE_KEY_TTL_SECS}),
                Some(&token),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        sqlx::query("UPDATE nodes SET credential_expires_at=$1 WHERE id=$2")
            .bind(now() - 1)
            .bind(ns[0].id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let expired = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{}/peers", ns[0].id),
            serde_json::Value::Null,
            Some(&ns[0].node_token),
        )
        .await;
        assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
        let expired_body: serde_json::Value = body(expired).await;
        assert!(expired_body["error"]
            .as_str()
            .unwrap()
            .contains("blaktaild reauth"));
        let peers_after_expiry: PeersResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", ns[1].id),
                serde_json::Value::Null,
                Some(&ns[1].node_token),
            )
            .await,
        )
        .await;
        assert!(peers_after_expiry.peers.is_empty());

        let renewal_key: JoinKeyResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", o.id),
                serde_json::json!({"expires_in_seconds":60}),
                Some(&token),
            )
            .await,
        )
        .await;
        let old_token = ns[0].node_token.clone();
        let renewed: ReauthResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/nodes/{}/reauth", ns[0].id),
                serde_json::json!({"join_key": renewal_key.key}),
                Some(&old_token),
            )
            .await,
        )
        .await;
        assert_ne!(renewed.node_token, old_token);
        assert!(renewed.credential_expires_at >= now() + MIN_NODE_KEY_TTL_SECS - 1);
        assert_eq!(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", ns[0].id),
                serde_json::Value::Null,
                Some(&old_token),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        ns[0].node_token = renewed.node_token;
        ns[0].credential_expires_at = renewed.credential_expires_at;
        let peers_after_renewal: PeersResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", ns[1].id),
                serde_json::Value::Null,
                Some(&ns[1].node_token),
            )
            .await,
        )
        .await;
        assert_eq!(peers_after_renewal.peers[0].id, ns[0].id);
        let preserved_ip: String =
            sqlx::query_scalar("SELECT allowed_ips_json FROM nodes WHERE id=$1")
                .bind(ns[0].id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&preserved_ip).unwrap()[0],
            ns[0].assigned_ip
        );

        sqlx::query("UPDATE nodes SET relay_endpoint_updated_at=$1 WHERE id=$2")
            .bind(now() - RELAY_ENDPOINT_FRESH_SECS - 1)
            .bind(ns[0].id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let stale: PeersResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", ns[1].id),
                serde_json::Value::Null,
                Some(&ns[1].node_token),
            )
            .await,
        )
        .await;
        assert_eq!(stale.peers[0].relay_endpoint, None);
        let n = &ns[1];
        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("/v1/nodes/{}", n.id),
                serde_json::Value::Null,
                Some(&n.node_token)
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let n = &ns[0];
        let p: PeersResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", n.id),
                serde_json::Value::Null,
                Some(&n.node_token),
            )
            .await,
        )
        .await;
        assert!(p.peers.is_empty())
    }
    #[tokio::test]
    async fn public_health_is_minimal_and_readiness_checks_database() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let v: serde_json::Value =
            body(call(&r, Method::GET, "/health", serde_json::Value::Null, None).await).await;
        assert_eq!(v, serde_json::json!({"status":"ready"}));
        assert!(!v.to_string().contains("ap-southeast-2"));
        let live: serde_json::Value =
            body(call(&r, Method::GET, "/livez", serde_json::Value::Null, None).await).await;
        assert_eq!(live, serde_json::json!({"status":"ok"}));

        sqlx::raw_sql("ALTER TABLE orgs RENAME TO orgs_unavailable")
            .execute(&store.pool)
            .await
            .unwrap();
        let response = call(&r, Method::GET, "/readyz", serde_json::Value::Null, None).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let unavailable: serde_json::Value = body(response).await;
        assert_eq!(unavailable, serde_json::json!({"status":"unavailable"}));
        assert!(!unavailable.to_string().contains("database"));
        assert_eq!(
            call(&r, Method::GET, "/livez", serde_json::Value::Null, None)
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn private_diagnostics_require_bearer_token() {
        const DIAGNOSTICS_TOKEN: &str = "coordinator-diagnostics-token-at-least-32-bytes";
        let router = metrics_app_with_token(
            Store::memory().await.unwrap(),
            Arc::new(CoordMetrics::default()),
            Some(DIAGNOSTICS_TOKEN.as_bytes().to_vec()),
        );
        assert_eq!(
            call(
                &router,
                Method::GET,
                "/metrics",
                serde_json::Value::Null,
                None,
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = call(
            &router,
            Method::GET,
            "/diagnostics/readiness",
            serde_json::Value::Null,
            Some(DIAGNOSTICS_TOKEN),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value = body(response).await;
        assert_eq!(value["database"], "ok");
        assert_eq!(value["schema_version"], CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn role_and_tag_matrix_defaults_to_same_tag_only() {
        let acl = Acl::default();
        let roles = [Role::Owner, Role::Admin, Role::Member];
        let tags = [DeviceTag::Office, DeviceTag::Ranger, DeviceTag::Store];
        for source_role in roles {
            for source_tag in tags {
                for dest_role in roles {
                    for dest_tag in tags {
                        let source = Subject::new(source_role, vec![source_tag]);
                        let dest = Subject::new(dest_role, vec![dest_tag]);
                        assert_eq!(
                            acl.allows(&source, &dest),
                            source_tag == dest_tag,
                            "{source_role:?}/{source_tag:?} -> {dest_role:?}/{dest_tag:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn policy_defaults_deny_closes_implicit_same_tag() {
        let acl: Acl = serde_json::from_value(serde_json::json!({
            "defaults": "deny",
            "rules": []
        }))
        .unwrap();
        let office = Subject::new(Role::Member, vec![DeviceTag::Office]);
        let other_office = Subject::new(Role::Owner, vec![DeviceTag::Office]);
        let untagged = Subject::new(Role::Member, vec![]);
        assert!(!acl.allows(&office, &other_office));
        assert!(!acl.allows(&untagged, &untagged));
        let report = check_policy_document(r#"{"defaults":"deny","rules":[]}"#).unwrap();
        assert_eq!(report.defaults, "deny");
        assert_eq!(
            check_policy_document(r#"{"rules":[]}"#).unwrap().defaults,
            "same_tag"
        );
    }

    #[test]
    fn explicit_deny_wins_and_roles_can_allow_cross_tag() {
        let acl: Acl = serde_json::from_value(serde_json::json!({"rules":[
            {"action":"allow","src_roles":["owner","admin"],"dst_tags":["store"]},
            {"action":"deny","src_tags":["ranger"],"dst_tags":["store"]}
        ]}))
        .unwrap();
        let store = Subject::new(Role::Member, vec![DeviceTag::Store]);
        assert!(acl.allows(&Subject::new(Role::Owner, vec![DeviceTag::Office]), &store));
        assert!(acl.allows(&Subject::new(Role::Admin, vec![DeviceTag::Office]), &store));
        assert!(!acl.allows(&Subject::new(Role::Owner, vec![DeviceTag::Ranger]), &store));
        assert!(!acl.allows(&Subject::new(Role::Member, vec![DeviceTag::Office]), &store));
    }

    #[test]
    fn named_groups_match_people_and_unknown_groups_fail_validation() {
        let acl: Acl = serde_json::from_value(serde_json::json!({
            "groups": {
                "rangers": ["alice@example.test", "alice-user"],
                "stores": ["store-owner"]
            },
            "rules": [
                {"action":"allow","src_groups":["rangers"],"dst_groups":["stores"]},
                {"action":"deny","src_groups":["rangers"],"dst_tags":["office"]}
            ]
        }))
        .unwrap();
        acl.validate().unwrap();
        let ranger = Subject {
            email: "alice@example.test".into(),
            ..Subject::new(Role::Member, vec![DeviceTag::Ranger]).with_user("alice-user")
        };
        let store = Subject::new(Role::Owner, vec![DeviceTag::Store]).with_user("store-owner");
        let office = Subject::new(Role::Member, vec![DeviceTag::Office]).with_user("other");
        assert!(acl.allows(&ranger, &store));
        assert!(acl.allows(
            &Subject {
                email: "ALICE@example.test".into(),
                ..Subject::new(Role::Member, vec![])
            },
            &store
        ));
        assert!(!acl.allows(&ranger, &office));
        assert!(!acl.allows(
            &Subject::new(Role::Owner, vec![DeviceTag::Office]).with_user("nobody"),
            &store
        ));

        let unknown: Acl = serde_json::from_value(serde_json::json!({
            "groups": {"rangers":["alice-user"]},
            "rules":[{"action":"allow","src_groups":["missing"],"dst_tags":["store"]}]
        }))
        .unwrap();
        assert!(unknown.validate().is_err());
        let unnamed: Acl = serde_json::from_value(serde_json::json!({
            "groups": {"Rangers":["alice-user"]},
            "rules":[{"action":"allow","src_groups":["Rangers"],"dst_tags":["store"]}]
        }))
        .unwrap();
        assert!(unnamed.validate().is_err());
    }

    #[test]
    fn policy_tests_and_tag_owners_validate_offline() {
        let document = serde_json::json!({
            "version": 1,
            "groups": {"rangers":["alice-user"]},
            "tag_owners": {"office":["alice-user","admin"]},
            "rules":[{"action":"allow","src_groups":["rangers"],"dst_tags":["store"]}],
            "tests":[
                {
                    "name":"ranger reaches store",
                    "src_user":"alice-user",
                    "dst_tags":["store"],
                    "allow": true
                },
                {
                    "name":"office stays isolated",
                    "src_tags":["office"],
                    "dst_tags":["store"],
                    "allow": false
                }
            ]
        });
        let report = check_policy_document(&document.to_string()).unwrap();
        assert_eq!(report.tests, 2);
        assert_eq!(report.tag_owners, 1);
        let inverted = serde_json::json!({
            "rules":[{"action":"allow","src_tags":["office"],"dst_tags":["store"]}],
            "tests":[{"src_tags":["office"],"dst_tags":["store"],"allow":false}]
        });
        assert!(check_policy_document(&inverted.to_string()).is_err());
        assert!(check_policy_document(r#"{"version":2,"rules":[]}"#).is_err());
        assert!(
            check_policy_document(r#"{"tag_owners":{"unknown":["alice"]},"rules":[]}"#).is_err()
        );
    }

    #[test]
    fn policy_ports_hosts_and_protocols_validate_offline() {
        let document = serde_json::json!({
            "version": 1,
            "groups": {"rangers":["alice-user"]},
            "hosts": {
                "wiki": "10.0.0.10",
                "printers": "10.0.0.0/24",
                "ula": "fd12:3456:789a::/48"
            },
            "rules":[
                {
                    "action":"allow",
                    "src_groups":["rangers"],
                    "dst_tags":["store"],
                    "dst_ports":["22","80-443"],
                    "protocols":["tcp"]
                },
                {
                    "action":"allow",
                    "src_groups":["rangers"],
                    "dst_hosts":["wiki"],
                    "dst_ports":["443"],
                    "protocols":["tcp"]
                }
            ],
            "tests":[
                {
                    "name":"ssh to store",
                    "src_user":"alice-user",
                    "dst_tags":["store"],
                    "dst_port": 22,
                    "protocol":"tcp",
                    "allow": true
                },
                {
                    "name":"dns to store stays denied",
                    "src_user":"alice-user",
                    "dst_tags":["store"],
                    "dst_port": 53,
                    "protocol":"udp",
                    "allow": false
                },
                {
                    "name":"wiki https",
                    "src_user":"alice-user",
                    "dst_host":"wiki",
                    "dst_port": 443,
                    "protocol":"tcp",
                    "allow": true
                },
                {
                    "name":"wiki ssh denied",
                    "src_user":"alice-user",
                    "dst_host":"wiki",
                    "dst_port": 22,
                    "protocol":"tcp",
                    "allow": false
                }
            ]
        });
        let report = check_policy_document(&document.to_string()).unwrap();
        assert_eq!(report.hosts, 3);
        assert_eq!(report.tests, 4);
        assert!(check_policy_document(
            r#"{"hosts":{"wiki":"example.com"},"rules":[{"action":"allow","dst_hosts":["wiki"]}]}"#
        )
        .is_err());
        assert!(check_policy_document(
            r#"{"hosts":{"wiki":"10.0.0.10"},"rules":[{"action":"allow","dst_hosts":["missing"]}]}"#
        )
        .is_err());
        assert!(check_policy_document(
            r#"{"rules":[{"action":"allow","src_tags":["office"],"dst_ports":["0"]}]}"#
        )
        .is_err());
        assert!(check_policy_document(r#"{"hosts":{"open":"0.0.0.0/0"},"rules":[]}"#).is_err());
        let peer_rule: Acl = serde_json::from_value(serde_json::json!({
            "groups": {"rangers":["alice-user"]},
            "hosts": {"wiki":"10.0.0.10"},
            "rules":[
                {"action":"allow","src_groups":["rangers"],"dst_tags":["store"],"dst_ports":["22"]},
                {"action":"allow","src_groups":["rangers"],"dst_hosts":["wiki"]}
            ]
        }))
        .unwrap();
        let ranger = Subject::new(Role::Member, vec![]).with_user("alice-user");
        let store = Subject::new(Role::Member, vec![DeviceTag::Store]);
        assert!(peer_rule.allows(&ranger, &store));
        assert!(!peer_rule.allows_flow(&ranger, &store, Some(53), Some(AclProtocol::Udp), None));
        assert!(peer_rule.allows_flow(
            &ranger,
            &Subject::new(Role::Member, vec![]),
            Some(443),
            Some(AclProtocol::Tcp),
            Some("wiki")
        ));
    }

    #[test]
    fn policy_ssh_rules_validate_offline_and_fail_closed() {
        let document = serde_json::json!({
            "version": 1,
            "groups": {"rangers":["alice-user"]},
            "ssh":[
                {
                    "action":"allow",
                    "src_groups":["rangers"],
                    "dst_tags":["store"],
                    "users":["ubuntu","deploy"]
                },
                {
                    "action":"check",
                    "src_groups":["rangers"],
                    "dst_tags":["office"],
                    "users":["*"],
                    "check_period_secs": 3600
                },
                {
                    "action":"deny",
                    "src_groups":["rangers"],
                    "dst_tags":["store"],
                    "users":["root"]
                }
            ],
            "tests":[
                {
                    "name":"ranger ssh deploy",
                    "src_user":"alice-user",
                    "dst_tags":["store"],
                    "ssh_user":"deploy",
                    "allow": true
                },
                {
                    "name":"ranger ssh root denied",
                    "src_user":"alice-user",
                    "dst_tags":["store"],
                    "ssh_user":"root",
                    "allow": false
                },
                {
                    "name":"ranger ssh office with check",
                    "src_user":"alice-user",
                    "dst_tags":["office"],
                    "ssh_user":"ubuntu",
                    "allow": true
                },
                {
                    "name":"same-tag ssh stays denied",
                    "src_tags":["store"],
                    "dst_tags":["store"],
                    "ssh_user":"ubuntu",
                    "allow": false
                }
            ]
        });
        let report = check_policy_document(&document.to_string()).unwrap();
        assert_eq!(report.ssh, 3);
        assert_eq!(report.tests, 4);
        let acl: Acl = serde_json::from_value(document).unwrap();
        let ranger = Subject::new(Role::Member, vec![]).with_user("alice-user");
        let store = Subject::new(Role::Member, vec![DeviceTag::Store]);
        assert!(acl.allows_ssh(&ranger, &store, "ubuntu"));
        assert!(!acl.allows_ssh(&ranger, &store, "root"));
        assert!(!acl.allows_ssh(
            &Subject::new(Role::Member, vec![DeviceTag::Store]),
            &store,
            "ubuntu"
        ));
        assert!(
            check_policy_document(r#"{"ssh":[{"action":"allow","users":["ubuntu"]}]}"#).is_err()
        );
        assert!(check_policy_document(
            r#"{"ssh":[{"action":"allow","src_tags":["office"],"users":[]}]}"#
        )
        .is_err());
        assert!(check_policy_document(
            r#"{"ssh":[{"action":"allow","src_tags":["office"],"users":["ubuntu"],"check_period_secs":60}]}"#
        )
        .is_err());
        assert!(check_policy_document(
            r#"{"ssh":[{"action":"allow","src_tags":["office"],"users":["ubuntu"]}],"tests":[{"ssh_user":"ubuntu","dst_port":22,"allow":true}]}"#
        )
        .is_err());
        assert!(check_policy_document(
            r#"{"ssh":[{"action":"allow","src_tags":["office"],"users":["ubuntu"],"tty":true}]}"#
        )
        .is_err());
    }

    #[test]
    fn peer_ingress_compiles_ports_denies_and_ssh_users() {
        let same_tag = Acl::default();
        let office = Subject::new(Role::Member, vec![DeviceTag::Office]);
        let store = Subject::new(Role::Member, vec![DeviceTag::Store]);
        let other_office = Subject::new(Role::Owner, vec![DeviceTag::Office]);
        let same = same_tag.peer_ingress(&office, &other_office);
        assert!(same.all);
        assert!(same.icmp);
        assert!(same.ssh_users.is_empty());
        assert!(!same_tag.peer_ingress(&office, &store).all);

        let restricted: Acl = serde_json::from_value(serde_json::json!({
            "defaults": "deny",
            "groups": {"crew":["alice-user"]},
            "rules":[
                {
                    "action":"allow",
                    "src_groups":["crew"],
                    "dst_tags":["store"],
                    "dst_ports":["8080"],
                    "protocols":["tcp"]
                },
                {
                    "action":"deny",
                    "src_groups":["crew"],
                    "dst_tags":["store"],
                    "dst_ports":["8081"],
                    "protocols":["tcp"]
                }
            ],
            "ssh":[
                {
                    "action":"allow",
                    "src_groups":["crew"],
                    "dst_tags":["store"],
                    "users":["blaktail"]
                },
                {
                    "action":"deny",
                    "src_groups":["crew"],
                    "dst_tags":["store"],
                    "users":["intruder"]
                }
            ]
        }))
        .unwrap();
        let ranger = Subject::new(Role::Member, vec![]).with_user("alice-user");
        let ingress = restricted.peer_ingress(&ranger, &store);
        assert!(!ingress.all);
        assert_eq!(ingress.tcp, vec!["22", "8080"]);
        assert!(ingress.udp.is_empty());
        assert!(!ingress.icmp);
        assert_eq!(ingress.deny_tcp, vec!["8081"]);
        assert_eq!(ingress.ssh_users, vec!["blaktail"]);
        assert!(restricted.allows(&ranger, &store));
        assert!(restricted.allows_flow(&ranger, &store, Some(8080), Some(AclProtocol::Tcp), None));
        assert!(!restricted.allows_flow(&ranger, &store, Some(8081), Some(AclProtocol::Tcp), None));
        assert!(restricted.allows_ssh(&ranger, &store, "blaktail"));
        assert!(!restricted.allows_ssh(&ranger, &store, "intruder"));
    }

    #[test]
    fn wireguard_only_adjacent_service_is_decided_on_the_managed_side() {
        let acl: Acl = serde_json::from_value(serde_json::json!({
            "defaults": "deny",
            "rules":[{
                "action":"allow",
                "src_tags":["office"],
                "dst_tags":["office"],
                "dst_ports":["8080"],
                "protocols":["tcp"]
            }]
        }))
        .unwrap();
        let agent = Subject::new(Role::Owner, vec![DeviceTag::Office]);
        let unmanaged = Subject::new(Role::Member, vec![DeviceTag::Office]);
        assert!(
            acl.allows(&agent, &unmanaged),
            "managed agent must still receive the exported peer"
        );
        let ingress = acl.peer_ingress(&unmanaged, &agent);
        assert!(!ingress.all);
        assert_eq!(ingress.tcp, vec!["8080"]);
        assert!(acl.allows_flow(&unmanaged, &agent, Some(8080), Some(AclProtocol::Tcp), None));
        assert!(!acl.allows_flow(&unmanaged, &agent, Some(8081), Some(AclProtocol::Tcp), None));
    }

    #[tokio::test]
    async fn policy_only_revision_sends_snapshot_so_ingress_updates() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "wg-only-ingress-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let office = register_test_node(&router, org.id, &owner, "office", "office-key", &[]).await;
        sqlx::query("UPDATE nodes SET tags_json=$1 WHERE id=$2")
            .bind(r#"["office"]"#)
            .bind(office.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let created: crate::wg_only::WireGuardOnlyPeer = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/wireguard-only-peers", org.id),
                serde_json::json!({
                    "name": "vanilla",
                    "kind": "wireguard_only",
                    "wg_public_key": "vanillaPublicKeyExample+/=",
                    "endpoint": "203.0.113.20:51820",
                    "allowed_ips": ["10.8.0.2/32"],
                    "tags": ["office"]
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        let first: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/updates?since=0&wait=0&version=2", office.id),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(first["kind"], "snapshot");
        let revision = first["revision"].as_i64().unwrap();
        let first_peer = first["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["id"] == created.id.to_string())
            .unwrap();
        assert_eq!(first_peer["ingress"]["all"], true);

        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::json!({
                    "defaults": "deny",
                    "rules": [{
                        "action": "allow",
                        "src_tags": ["office"],
                        "dst_tags": ["office"],
                        "dst_ports": ["8080"],
                        "protocols": ["tcp"]
                    }]
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        let second: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!(
                    "/v1/nodes/{}/updates?since={revision}&wait=0&version=2",
                    office.id
                ),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(second["kind"], "snapshot");
        let second_peer = second["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["id"] == created.id.to_string())
            .unwrap();
        assert_ne!(second_peer["ingress"]["all"], true);
        assert_eq!(second_peer["ingress"]["tcp"], serde_json::json!(["8080"]));
    }

    #[tokio::test]
    async fn tag_owners_reject_admin_assignment_unless_listed() {
        let store = Store::memory().await.unwrap();
        let r = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "tag-owners-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
        assert_eq!(
            call(
                &r,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::json!({
                    "tag_owners": {"office":["owner-1"]},
                    "rules":[]
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", org.id),
                serde_json::json!({"expires_in_seconds":60,"tags":["office"]}),
                Some(&admin),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", org.id),
                serde_json::json!({"expires_in_seconds":60,"tags":["office"]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn organisation_bootstrap_requires_scoped_service_assertion_and_rejects_replay() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org_id = Uuid::new_v4();
        let request = serde_json::json!({"id":org_id,"name":"bootstrap-auth"});
        assert_eq!(
            call(&r, Method::POST, "/v1/orgs", request.clone(), None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let owner = signed_session(org_id, "owner-1", Role::Owner, now() + 60);
        assert_eq!(
            call(&r, Method::POST, "/v1/orgs", request.clone(), Some(&owner),)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let service = signed_service(org_id, "bootstrap.prepare");
        let raw_service = sign_test_assertion(&service);
        assert_eq!(
            call(
                &r,
                Method::POST,
                "/v1/orgs",
                request.clone(),
                Some(&raw_service),
            )
            .await
            .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            call(
                &r,
                Method::POST,
                "/v1/orgs",
                request.clone(),
                Some(&raw_service),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&r, Method::POST, "/v1/orgs", request, Some(&service),)
                .await
                .status(),
            StatusCode::OK
        );
        let row = sqlx::query(
            "SELECT (SELECT count(*) FROM orgs),
                (SELECT count(*) FROM pending_bootstrap_orgs)",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        let active: i64 = row.try_get(0).unwrap();
        let pending: i64 = row.try_get(1).unwrap();
        assert_eq!((active, pending), (0, 1));

        let commit_path = format!("/v1/orgs/{org_id}/bootstrap-commit");
        assert_eq!(
            call(&r, Method::POST, &commit_path, serde_json::json!({}), None,)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let wrong_action = signed_service(org_id, "bootstrap.prepare");
        assert_eq!(
            call(
                &r,
                Method::POST,
                &commit_path,
                serde_json::json!({}),
                Some(&wrong_action),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let commit = signed_service(org_id, "bootstrap.commit");
        assert_eq!(
            call(
                &r,
                Method::POST,
                &commit_path,
                serde_json::json!({}),
                Some(&commit),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let row = sqlx::query(
            "SELECT (SELECT count(*) FROM orgs),
                (SELECT count(*) FROM pending_bootstrap_orgs)",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        let active: i64 = row.try_get(0).unwrap();
        let pending: i64 = row.try_get(1).unwrap();
        assert_eq!((active, pending), (1, 0));

        let commit_retry = signed_service(org_id, "bootstrap.commit");
        assert_eq!(
            call(
                &r,
                Method::POST,
                &commit_path,
                serde_json::json!({}),
                Some(&commit_retry),
            )
            .await
            .status(),
            StatusCode::OK
        );
        let completion_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
             WHERE org_id=$1 AND action='bootstrap.completed'",
        )
        .bind(org_id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(completion_events, 1);

        let expired_id = Uuid::new_v4();
        let expired_request = serde_json::json!({"id":expired_id,"name":"expired-bootstrap"});
        let expired_prepare = signed_service(expired_id, "bootstrap.prepare");
        assert_eq!(
            call(
                &r,
                Method::POST,
                "/v1/orgs",
                expired_request,
                Some(&expired_prepare),
            )
            .await
            .status(),
            StatusCode::ACCEPTED
        );
        sqlx::query("UPDATE pending_bootstrap_orgs SET expires_at=$1 WHERE id=$2")
            .bind(now() - 1)
            .bind(expired_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let expired_commit = signed_service(expired_id, "bootstrap.commit");
        assert_eq!(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{expired_id}/bootstrap-commit"),
                serde_json::json!({}),
                Some(&expired_commit),
            )
            .await
            .status(),
            StatusCode::GONE
        );
    }

    #[tokio::test]
    async fn console_auth_fails_closed_for_missing_forged_and_expired_assertions() {
        let r = app(
            Store::memory().await.unwrap(),
            "ap-southeast-2".into(),
            TEST_SECRET,
        );
        let o = create_test_org(&r, "auth-tests").await;
        let path = format!("/v1/orgs/{}/join-keys", o.id);
        assert_eq!(
            call(&r, Method::POST, &path, serde_json::json!({}), None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let expired = signed_session(o.id, "owner-1", Role::Owner, now() - 1);
        assert_eq!(
            call(
                &r,
                Method::POST,
                &path,
                serde_json::json!({}),
                Some(&expired)
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        for (issuer, audience) in [
            ("not-the-console", CONSOLE_ASSERTION_AUDIENCE),
            (CONSOLE_ASSERTION_ISSUER, "not-the-coordinator"),
        ] {
            let current_time = now();
            let malformed_claims = assertion_template(AssertionClaims {
                user_id: "owner-1".into(),
                org_id: o.id,
                role: "owner".into(),
                name: "Owner".into(),
                email: "owner-1@example.com".into(),
                iss: issuer.into(),
                aud: audience.into(),
                iat: current_time,
                exp: current_time + MAX_CONSOLE_ASSERTION_LIFETIME_SECS,
                jti: String::new(),
                action: None,
            });
            assert_eq!(
                call(
                    &r,
                    Method::POST,
                    &path,
                    serde_json::json!({}),
                    Some(&malformed_claims),
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let template = signed_session(o.id, "owner-1", Role::Owner, now() + 60);
        let mut forged = sign_test_assertion(&template).into_bytes();
        let last = forged.len() - 1;
        forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
        let forged = String::from_utf8(forged).unwrap();
        assert_eq!(
            call(
                &r,
                Method::POST,
                &path,
                serde_json::json!({}),
                Some(&forged)
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let replay_template = signed_session(o.id, "owner-1", Role::Owner, now() + 60);
        let replay = sign_test_assertion(&replay_template);
        assert_eq!(
            call(
                &r,
                Method::POST,
                &path,
                serde_json::json!({}),
                Some(&replay),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            call(
                &r,
                Method::POST,
                &path,
                serde_json::json!({}),
                Some(&replay),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn management_route_permission_matrix_fails_closed() {
        let r = app(
            Store::memory().await.unwrap(),
            "ap-southeast-2".into(),
            TEST_SECRET,
        );
        let o = create_test_org(&r, "roles").await;
        let owner = signed_session(o.id, "owner-1", Role::Owner, now() + 60);
        let admin = signed_session(o.id, "admin-1", Role::Admin, now() + 60);
        let member = signed_session(o.id, "member-1", Role::Member, now() + 60);
        let roles = [&owner, &admin, &member];

        for (name, method, path, value, authorised_status) in [
            (
                "device authorization preview",
                Method::GET,
                format!("/v1/orgs/{}/device-authorizations/ABCDEFGH", o.id),
                serde_json::Value::Null,
                StatusCode::NOT_FOUND,
            ),
            (
                "node list",
                Method::GET,
                format!("/v1/orgs/{}/nodes", o.id),
                serde_json::Value::Null,
                StatusCode::OK,
            ),
            (
                "ACL read",
                Method::GET,
                format!("/v1/orgs/{}/acl", o.id),
                serde_json::Value::Null,
                StatusCode::OK,
            ),
            (
                "security policy read",
                Method::GET,
                format!("/v1/orgs/{}/security", o.id),
                serde_json::Value::Null,
                StatusCode::OK,
            ),
            (
                "audit read",
                Method::GET,
                format!("/v1/orgs/{}/audit", o.id),
                serde_json::Value::Null,
                StatusCode::OK,
            ),
        ] {
            for token in roles {
                assert_eq!(
                    call(&r, method.clone(), &path, value.clone(), Some(token))
                        .await
                        .status(),
                    authorised_status,
                    "{name} role access"
                );
            }
            for denied in [None, Some("malformed")] {
                assert_eq!(
                    call(&r, method.clone(), &path, value.clone(), denied)
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED,
                    "{name} authentication boundary"
                );
            }
        }

        let missing_node = Uuid::new_v4();
        for (name, method, path, value, expected) in [
            (
                "join-key mint",
                Method::POST,
                format!("/v1/orgs/{}/join-keys", o.id),
                serde_json::json!({"expires_in_seconds":60}),
                [
                    StatusCode::CREATED,
                    StatusCode::CREATED,
                    StatusCode::FORBIDDEN,
                ],
            ),
            (
                "device authorization approval",
                Method::POST,
                format!("/v1/orgs/{}/device-authorizations/ABCDEFGH", o.id),
                serde_json::json!({}),
                [
                    StatusCode::NOT_FOUND,
                    StatusCode::NOT_FOUND,
                    StatusCode::NOT_FOUND,
                ],
            ),
            (
                "friendly-name update",
                Method::PUT,
                format!("/v1/orgs/{}/nodes/{missing_node}/friendly-name", o.id),
                serde_json::json!({"friendly_name":"Field laptop"}),
                [
                    StatusCode::NOT_FOUND,
                    StatusCode::NOT_FOUND,
                    StatusCode::FORBIDDEN,
                ],
            ),
            (
                "route approval",
                Method::PUT,
                format!("/v1/orgs/{}/nodes/{missing_node}/routes", o.id),
                serde_json::json!({"approved_routes":[]}),
                [
                    StatusCode::NOT_FOUND,
                    StatusCode::NOT_FOUND,
                    StatusCode::FORBIDDEN,
                ],
            ),
            (
                "ACL update",
                Method::PUT,
                format!("/v1/orgs/{}/acl", o.id),
                serde_json::json!({"rules":[]}),
                [
                    StatusCode::NO_CONTENT,
                    StatusCode::NO_CONTENT,
                    StatusCode::FORBIDDEN,
                ],
            ),
            (
                "security policy update",
                Method::PUT,
                format!("/v1/orgs/{}/security", o.id),
                serde_json::json!({"node_key_ttl_seconds": MIN_NODE_KEY_TTL_SECS}),
                [
                    StatusCode::NO_CONTENT,
                    StatusCode::NO_CONTENT,
                    StatusCode::FORBIDDEN,
                ],
            ),
            (
                "node revocation",
                Method::DELETE,
                format!("/v1/orgs/{}/nodes/{missing_node}", o.id),
                serde_json::Value::Null,
                [
                    StatusCode::NOT_FOUND,
                    StatusCode::NOT_FOUND,
                    StatusCode::FORBIDDEN,
                ],
            ),
            (
                "node tombstone",
                Method::POST,
                format!("/v1/orgs/{}/nodes/{missing_node}/tombstone", o.id),
                serde_json::Value::Null,
                [
                    StatusCode::NOT_FOUND,
                    StatusCode::NOT_FOUND,
                    StatusCode::FORBIDDEN,
                ],
            ),
            (
                "api client create",
                Method::POST,
                format!("/v1/orgs/{}/api-clients", o.id),
                serde_json::json!({"name":"ci","scopes":["status:read"]}),
                [
                    StatusCode::CREATED,
                    StatusCode::FORBIDDEN,
                    StatusCode::FORBIDDEN,
                ],
            ),
        ] {
            for (index, token) in roles.into_iter().enumerate() {
                assert_eq!(
                    call(&r, method.clone(), &path, value.clone(), Some(token))
                        .await
                        .status(),
                    expected[index],
                    "{name} role access"
                );
            }
            for denied in [None, Some("malformed")] {
                assert_eq!(
                    call(&r, method.clone(), &path, value.clone(), denied)
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED,
                    "{name} authentication boundary"
                );
            }
        }
    }

    #[tokio::test]
    async fn deny_rule_removes_matching_node_from_peer_response() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let o = create_test_org(&r, "filtered").await;
        let token = signed_session(o.id, "owner-1", Role::Owner, now() + 60);
        let mut nodes = vec![];
        for n in 1..=2 {
            let k: JoinKeyResponse = body(
                call(
                    &r,
                    Method::POST,
                    &format!("/v1/orgs/{}/join-keys", o.id),
                    serde_json::json!({"tags":["office"]}),
                    Some(&token),
                )
                .await,
            )
            .await;
            let response=call(&r,Method::POST,"/v1/nodes/register",serde_json::json!({"join_key":k.key,"name":format!("office-{n}"),"wg_public_key":format!("office-key-{n}")}),None).await;
            nodes.push(body::<RegisterResponse>(response).await);
        }
        assert_eq!(call(&r,Method::PUT,&format!("/v1/orgs/{}/acl",o.id),serde_json::json!({"rules":[{"action":"deny","src_tags":["office"],"dst_tags":["office"]}]}),Some(&token)).await.status(),StatusCode::NO_CONTENT);
        let peers: PeersResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", nodes[0].id),
                serde_json::Value::Null,
                Some(&nodes[0].node_token),
            )
            .await,
        )
        .await;
        assert!(peers.peers.is_empty());
    }

    #[tokio::test]
    async fn policy_get_shows_generated_legacy_default_and_admin_can_roll_back() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "policy-defaults-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let document: serde_json::Value = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(document["defaults"], "same_tag");
        assert_eq!(document["generated"][0]["kind"], "legacy_same_tag");
        assert_eq!(document["revision"], 1);
        assert_eq!(document["has_previous"], false);
        let etag = document["etag"].as_str().unwrap().to_owned();

        let writer: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"policy-writer","scopes":["policy:write","devices:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let admin =
            |method: Method, uri: &'static str, token: String, payload: serde_json::Value| {
                let router = r.clone();
                let org_id = org.id;
                async move {
                    router
                        .oneshot(
                            Request::builder()
                                .method(method)
                                .uri(uri)
                                .header(AUTHORIZATION, format!("Bearer {token}"))
                                .header("x-blaktail-organisation", org_id.to_string())
                                .header("content-type", "application/json")
                                .body(Body::from(payload.to_string()))
                                .unwrap(),
                        )
                        .await
                        .unwrap()
                }
            };
        assert_eq!(
            admin(
                Method::PUT,
                "/api/v1/policy",
                writer.token.clone(),
                serde_json::json!({"acl":{"defaults":"deny","rules":[]}}),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin(
                Method::PUT,
                "/api/v1/policy",
                writer.token.clone(),
                serde_json::json!({
                    "etag": etag,
                    "acl": {
                        "defaults": "deny",
                        "rules": [{"action":"allow","src_tags":["office"],"dst_tags":["store"]}]
                    }
                }),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let published: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/policy",
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(published["data"]["acl"]["defaults"], "deny");
        assert_eq!(published["data"]["acl"]["generated"], serde_json::json!([]));
        assert_eq!(published["data"]["has_previous"], true);
        assert_eq!(published["data"]["revision"], 2);
        let published_etag = published["data"]["etag"].as_str().unwrap().to_owned();
        assert_eq!(
            admin(
                Method::PUT,
                "/api/v1/policy",
                writer.token.clone(),
                serde_json::json!({"etag": published_etag, "rollback": true}),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let restored: serde_json::Value = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(restored["defaults"], "same_tag");
        assert_eq!(restored["generated"][0]["kind"], "legacy_same_tag");
        assert_eq!(restored["revision"], 3);
        assert_eq!(restored["rules"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn webhooks_block_ssrf_and_deliver_signed_policy_events() {
        let received = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received_loop = received.clone();
        tokio::spawn(async move {
            let hook = {
                let received = received_loop;
                move |headers: HeaderMap, body: String| {
                    let received = received.clone();
                    async move {
                        let signature = headers
                            .get("x-blaktail-signature")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        received.lock().unwrap().push((signature, body));
                        StatusCode::NO_CONTENT
                    }
                }
            };
            let server = axum::Router::new().route("/hook", axum::routing::post(hook));
            axum::serve(listener, server).await.ok();
        });

        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "webhook-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let writer: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({
                    "name": "webhook-writer",
                    "scopes": ["webhooks:write", "policy:write", "devices:read"]
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        let admin = |method: Method, uri: String, token: String, payload: serde_json::Value| {
            let router = r.clone();
            let org_id = org.id;
            async move {
                router
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(uri)
                            .header(AUTHORIZATION, format!("Bearer {token}"))
                            .header("x-blaktail-organisation", org_id.to_string())
                            .header("content-type", "application/json")
                            .body(Body::from(payload.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            admin(
                Method::POST,
                "/api/v1/webhooks".into(),
                writer.token.clone(),
                serde_json::json!({"name":"meta","url":"https://169.254.169.254/latest"}),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let created: crate::webhooks::WebhookDestination = body(
            admin(
                Method::POST,
                "/api/v1/webhooks".into(),
                writer.token.clone(),
                serde_json::json!({
                    "name": "inventory",
                    "url": format!("http://{addr}/hook")
                }),
            )
            .await,
        )
        .await;
        assert!(created.secret.as_deref().unwrap().starts_with("btw_"));
        let stored: String =
            sqlx::query_scalar("SELECT signing_secret FROM webhook_destinations WHERE id=$1")
                .bind(created.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(stored.starts_with("bte1."));
        assert!(!stored.contains(created.secret.as_deref().unwrap()));
        let policy: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/policy".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(
            admin(
                Method::PUT,
                "/api/v1/policy".into(),
                writer.token.clone(),
                serde_json::json!({
                    "etag": policy["data"]["etag"],
                    "acl": {"defaults":"deny","rules":[]}
                }),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while received.lock().unwrap().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let deliveries = received.lock().unwrap().clone();
        assert_eq!(deliveries.len(), 1);
        assert!(deliveries[0].0.starts_with("t="));
        assert!(deliveries[0].1.contains("policy.published") || deliveries[0].1.contains("deny"));
        let listed: serde_json::Value = body(
            admin(
                Method::GET,
                format!("/api/v1/webhooks/{}/deliveries", created.id),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(listed["data"][0]["event_type"], "policy.published");
        assert!(listed["data"][0]["delivered_at"].as_i64().is_some());
    }

    #[tokio::test]
    async fn console_can_create_and_list_webhooks_members_cannot() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "console-webhooks").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let created: crate::webhooks::WebhookDestination = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::json!({"name":"inventory","url":"https://example.com/hook"}),
                Some(&owner),
            )
            .await,
        )
        .await;
        assert!(created.secret.as_deref().unwrap().starts_with("btw_"));
        let stored: String =
            sqlx::query_scalar("SELECT signing_secret FROM webhook_destinations WHERE id=$1")
                .bind(created.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(stored.starts_with("bte1."));
        assert!(!stored.contains(created.secret.as_deref().unwrap()));
        let listed: Vec<crate::webhooks::WebhookDestination> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(listed.len(), 1);
        assert!(listed[0].secret.is_none());
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::json!({"name":"nope","url":"https://example.com/other"}),
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
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
    }

    #[tokio::test]
    async fn device_lifecycle_writes_webhook_outbox_events() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "device-webhooks").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let dest: crate::webhooks::WebhookDestination = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::json!({"name":"inventory","url":"https://example.com/hook"}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let node = register_test_node(&router, org.id, &owner, "office-1", "office-key", &[]).await;
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/nodes/{}/friendly-name", org.id, node.id),
                serde_json::json!({"friendly_name":"Front desk"}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
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
        let deliveries: Vec<crate::webhooks::WebhookDelivery> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/webhooks/{}/deliveries", org.id, dest.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        let types: Vec<_> = deliveries
            .iter()
            .map(|delivery| delivery.event_type.as_str())
            .collect();
        assert!(types.contains(&"device.enrolled"));
        assert!(types.contains(&"device.renamed"));
        assert!(types.contains(&"device.deleted"));
    }

    #[tokio::test]
    async fn console_owner_enqueues_membership_webhook_events() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "membership-webhooks").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let dest: crate::webhooks::WebhookDestination = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::json!({"name":"inventory","url":"https://example.com/hook"}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let accepted = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/webhooks/events", org.id),
            serde_json::json!({
                "event_type": "membership.updated",
                "payload": {
                    "membership_id": "mem-1",
                    "role": "admin",
                    "status": "active"
                }
            }),
            Some(&owner),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks/events", org.id),
                serde_json::json!({
                    "event_type": "membership.updated",
                    "payload": {"membership_id": "mem-1", "role": "member"}
                }),
                Some(&admin),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks/events", org.id),
                serde_json::json!({
                    "event_type": "membership.updated",
                    "payload": {"membership_id": "mem-1"}
                }),
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks/events", org.id),
                serde_json::json!({
                    "event_type": "device.enrolled",
                    "payload": {"membership_id": "mem-1"}
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks/events", org.id),
                serde_json::json!({
                    "event_type": "membership.updated",
                    "payload": {"role": "admin"}
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let deliveries: Vec<crate::webhooks::WebhookDelivery> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/webhooks/{}/deliveries", org.id, dest.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].event_type, "membership.updated");
    }

    #[tokio::test]
    async fn webhook_delivery_matrix_handles_timeout_429_and_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let server = axum::Router::new()
                .route(
                    "/too-many",
                    axum::routing::post(|| async { StatusCode::TOO_MANY_REQUESTS }),
                )
                .route(
                    "/hang",
                    axum::routing::post(|| async {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        StatusCode::NO_CONTENT
                    }),
                )
                .route(
                    "/redirect",
                    axum::routing::post(|| async {
                        (
                            StatusCode::FOUND,
                            [(
                                axum::http::header::LOCATION,
                                "https://example.com/elsewhere",
                            )],
                        )
                    }),
                );
            axum::serve(listener, server).await.ok();
        });

        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "webhook-matrix").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let too_many: crate::webhooks::WebhookDestination = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::json!({"name":"too-many","url": format!("http://{addr}/too-many")}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let hang: crate::webhooks::WebhookDestination = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::json!({"name":"hang","url": format!("http://{addr}/hang")}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let redirect: crate::webhooks::WebhookDestination = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/webhooks", org.id),
                serde_json::json!({"name":"redirect","url": format!("http://{addr}/redirect")}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let _node =
            register_test_node(&router, org.id, &owner, "office-1", "office-key", &[]).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut hang_error = None;
        let mut too_many_attempts = 0;
        let mut redirect_error = None;
        while tokio::time::Instant::now() < deadline {
            let listed = |destination_id: uuid::Uuid| {
                let router = router.clone();
                let owner = owner.clone();
                let org_id = org.id;
                async move {
                    let deliveries: Vec<crate::webhooks::WebhookDelivery> = body(
                        call(
                            &router,
                            Method::GET,
                            &format!("/v1/orgs/{org_id}/webhooks/{destination_id}/deliveries"),
                            serde_json::Value::Null,
                            Some(&owner),
                        )
                        .await,
                    )
                    .await;
                    deliveries
                }
            };
            let too_many_row = listed(too_many.id).await;
            let hang_row = listed(hang.id).await;
            let redirect_row = listed(redirect.id).await;
            too_many_attempts = too_many_row.first().map(|row| row.attempts).unwrap_or(0);
            hang_error = hang_row.first().and_then(|row| row.last_error.clone());
            redirect_error = redirect_row.first().and_then(|row| row.last_error.clone());
            if too_many_attempts >= 1 && hang_error.is_some() && redirect_error.is_some() {
                assert!(too_many_row[0].delivered_at.is_none());
                assert!(hang_row[0].delivered_at.is_none());
                assert!(redirect_row[0].delivered_at.is_none());
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            too_many_attempts >= 1,
            "429 destination did not retry, attempts={too_many_attempts}"
        );
        let hang_error = hang_error.expect("hang destination produced no error");
        let hang_error = hang_error.to_ascii_lowercase();
        assert!(
            hang_error.contains("timeout")
                || hang_error.contains("timed out")
                || hang_error.contains("error sending request"),
            "{hang_error}"
        );
        let redirect_error = redirect_error.expect("redirect destination produced no error");
        assert!(redirect_error.contains("302"), "{redirect_error}");
    }

    #[tokio::test]
    async fn named_groups_allow_cross_tag_peers_for_listed_people() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let o = create_test_org(&r, "grouped").await;
        let alice = signed_session(o.id, "alice", Role::Owner, now() + 60);
        let bob = signed_session(o.id, "bob", Role::Admin, now() + 60);
        let alice_key: JoinKeyResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", o.id),
                serde_json::json!({"tags":["ranger"]}),
                Some(&alice),
            )
            .await,
        )
        .await;
        let bob_key: JoinKeyResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", o.id),
                serde_json::json!({"tags":["store"]}),
                Some(&bob),
            )
            .await,
        )
        .await;
        let alice_node: RegisterResponse = body(
            call(
                &r,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key": alice_key.key,
                    "name": "ranger-1",
                    "wg_public_key": "ranger-key"
                }),
                None,
            )
            .await,
        )
        .await;
        let bob_node: RegisterResponse = body(
            call(
                &r,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key": bob_key.key,
                    "name": "store-1",
                    "wg_public_key": "store-key"
                }),
                None,
            )
            .await,
        )
        .await;
        assert_eq!(
            call(
                &r,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", o.id),
                serde_json::json!({
                    "groups": {"field":["alice"],"shops":["bob"]},
                    "rules":[{"action":"allow","src_groups":["field"],"dst_groups":["shops"]}]
                }),
                Some(&alice),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &r,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", o.id),
                serde_json::json!({
                    "groups": {"field":["alice"]},
                    "rules":[{"action":"allow","src_groups":["missing"],"dst_tags":["store"]}]
                }),
                Some(&alice),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let from_alice: PeersResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", alice_node.id),
                serde_json::Value::Null,
                Some(&alice_node.node_token),
            )
            .await,
        )
        .await;
        let from_bob: PeersResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers", bob_node.id),
                serde_json::Value::Null,
                Some(&bob_node.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(from_alice.peers.len(), 1);
        assert_eq!(from_alice.peers[0].name, "store-1");
        assert!(from_bob.peers.is_empty());
    }

    #[tokio::test]
    async fn peer_snapshot_includes_compiled_ingress() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "ingress-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let office =
            register_test_node(&router, org.id, &owner, "office-1", "office-key", &[]).await;
        register_test_node(&router, org.id, &owner, "store-1", "store-key", &[]).await;
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::json!({
                    "defaults":"deny",
                    "groups":{"crew":["owner-1"]},
                    "rules":[{
                        "action":"allow",
                        "src_groups":["crew"],
                        "dst_groups":["crew"],
                        "dst_ports":["8080"],
                        "protocols":["tcp"]
                    }],
                    "ssh":[{
                        "action":"allow",
                        "src_groups":["crew"],
                        "dst_groups":["crew"],
                        "users":["blaktail"]
                    }]
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let from_office: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", office.id),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(from_office.peers.len(), 1);
        assert_eq!(from_office.peers[0].name, "store-1");
        let ingress = from_office.peers[0].ingress.as_ref().expect("ingress");
        assert!(!ingress.all);
        assert_eq!(ingress.tcp, vec!["22", "8080"]);
        assert_eq!(ingress.ssh_users, vec!["blaktail"]);
        assert!(!ingress.icmp);
    }

    #[tokio::test]
    async fn node_can_publish_overlay_shares_visible_to_allowed_peers() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "share-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let office =
            register_test_node(&router, org.id, &owner, "office-1", "office-key", &[]).await;
        let store_node =
            register_test_node(&router, org.id, &owner, "store-1", "store-key", &[]).await;
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::json!({
                    "defaults":"deny",
                    "groups":{"crew":["owner-1"]},
                    "rules":[{
                        "action":"allow",
                        "src_groups":["crew"],
                        "dst_groups":["crew"],
                        "dst_ports":["22"],
                        "protocols":["tcp"]
                    }]
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let published: Vec<crate::shares::NodeShare> = body(
            call(
                &router,
                Method::PUT,
                &format!("/v1/nodes/{}/shares", store_node.id),
                serde_json::json!({
                    "shares":[{
                        "label":"Files",
                        "path":"/srv/shared",
                        "port":5647,
                        "read_only":true,
                        "enabled":true
                    }]
                }),
                Some(&store_node.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(published[0].label, "files");
        let from_office: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers?dns_revision=3", office.id),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(from_office.shares.len(), 1);
        assert_eq!(from_office.shares[0].label, "files");
        assert_eq!(from_office.shares[0].port, 5647);
        assert_eq!(from_office.shares[0].node_id, store_node.id);
        let ingress = from_office.peers[0].ingress.as_ref().expect("ingress");
        assert!(ingress.tcp.contains(&"5647".into()));
        let listed: Vec<NodeRow> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        let store_row = listed
            .iter()
            .find(|node| node.id == store_node.id)
            .expect("store");
        assert_eq!(store_row.shares[0].path, "/srv/shared");
        let dns: crate::org_dns::OrgDnsResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/dns", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(dns.enrolled, 2);
        assert_eq!(dns.applied, 1);
    }

    #[tokio::test]
    async fn console_can_list_and_revoke_nodes() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let o = create_test_org(&r, "console-org").await;
        let token = signed_session(o.id, "owner-1", Role::Owner, now() + 60);
        let key: JoinKeyResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", o.id),
                serde_json::json!({}),
                Some(&token),
            )
            .await,
        )
        .await;
        let node: RegisterResponse = body(
            call(
                &r,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key": key.key,
                    "name": "laptop",
                    "wg_public_key": "wg-laptop"
                }),
                None,
            )
            .await,
        )
        .await;
        let listed: Vec<NodeRow> = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", o.id),
                serde_json::Value::Null,
                Some(&token),
            )
            .await,
        )
        .await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "laptop");
        assert!(!listed[0].revoked);
        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("/v1/orgs/{}/nodes/{}", o.id, node.id),
                serde_json::Value::Null,
                Some(&token),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let after: Vec<NodeRow> = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", o.id),
                serde_json::Value::Null,
                Some(&token),
            )
            .await,
        )
        .await;
        assert!(after[0].revoked);
        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("/v1/orgs/{}/nodes/{}", o.id, node.id),
                serde_json::Value::Null,
                None,
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn magic_dns_is_stable_and_safe() {
        assert_eq!(
            magic_dns_name("Alice's Laptop", "12345678-0000-0000-0000-000000000000"),
            "alice-s-laptop.12345678.blaktail"
        );
        assert_eq!(dns_label(&"a".repeat(100)).len(), 63);
        assert!(!dns_label(&format!("{}-suffix", "a".repeat(62))).ends_with('-'));
    }

    #[tokio::test]
    async fn existing_database_gains_credential_expiry_without_losing_nodes() {
        let path =
            std::env::temp_dir().join(format!("blaktail-migration-{}.sqlite3", Uuid::new_v4()));
        let created_at = now() - 100;
        {
            let pool = connect_sqlite(&path, true).await.unwrap();
            sqlx::raw_sql(
                "CREATE TABLE orgs(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,acl_json TEXT NOT NULL,created_at TEXT NOT NULL);
                 CREATE TABLE nodes(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,wg_public_key TEXT NOT NULL,endpoint TEXT,allowed_ips_json TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,revoked_at TEXT,UNIQUE(org_id,name),UNIQUE(org_id,wg_public_key));",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO orgs(id,name,acl_json,created_at) VALUES('org','Org','{\"rules\":[]}',$1)",
            )
            .bind(created_at)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO nodes(id,org_id,name,wg_public_key,allowed_ips_json,token_hash,created_at) VALUES('node','org','Node','key','[\"100.64.0.1/32\"]','hash',$1)",
            )
            .bind(created_at)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO nodes(id,org_id,name,wg_public_key,allowed_ips_json,token_hash,created_at) VALUES('node-2','org','Node@','key-2','[\"100.64.0.2/32\"]','hash-2',$1)",
            )
            .bind(created_at + 1)
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;
        }
        let store = Store::open(&path).await.unwrap();
        let row = sqlx::query(
            "SELECT o.node_key_ttl_seconds,n.credential_expires_at FROM orgs o JOIN nodes n ON n.org_id=o.id WHERE n.id='node'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        let ttl: i64 = row.try_get(0).unwrap();
        let expires: i64 = row.try_get(1).unwrap();
        assert_eq!(ttl, DEFAULT_NODE_KEY_TTL_SECS);
        assert_eq!(expires, created_at + DEFAULT_NODE_KEY_TTL_SECS);
        let display_name: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM nodes WHERE id='node'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(display_name, None);
        let dns_names = sqlx::query_scalar::<_, String>("SELECT dns_name FROM nodes ORDER BY id")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert_eq!(dns_names.len(), 2);
        assert!(dns_names.iter().all(|name| !name.is_empty()));
        assert_ne!(dns_names[0], dns_names[1]);
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        store.pool.close().await;

        let reopened = Store::open(&path).await.unwrap();
        let node_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(&reopened.pool)
            .await
            .unwrap();
        assert_eq!(node_count, 2);
        reopened.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn fresh_database_records_schema_version() {
        let store = Store::memory().await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let audit_table: String = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        assert_eq!(audit_table, "audit_events");
        let wg_table: String = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='wireguard_only_peers'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(wg_table, "wireguard_only_peers");
    }

    #[tokio::test]
    async fn service_open_refuses_unmigrated_database_without_mutation() {
        let path =
            std::env::temp_dir().join(format!("blaktail-unmigrated-{}.sqlite3", Uuid::new_v4()));
        connect_sqlite(&path, true).await.unwrap().close().await;
        assert!(matches!(
            Store::open_existing(&path).await,
            Err(StoreError::InvalidMigrationPlan {
                expected: CURRENT_SCHEMA_VERSION,
                found: 0,
            })
        ));
        let pool = connect_sqlite(&path, false).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        let tables: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(version, 0);
        assert_eq!(tables, 0);
        pool.close().await;

        Store::open(&path).await.unwrap().pool.close().await;
        Store::open_existing(&path)
            .await
            .unwrap()
            .pool
            .close()
            .await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn newer_database_schema_is_rejected_without_mutation() {
        let path = std::env::temp_dir().join(format!(
            "blaktail-future-migration-{}.sqlite3",
            Uuid::new_v4()
        ));
        let pool = connect_sqlite(&path, true).await.unwrap();
        // Must stay one past CURRENT_SCHEMA_VERSION so open() rejects a future database.
        assert_eq!(CURRENT_SCHEMA_VERSION, 18);
        sqlx::raw_sql("PRAGMA user_version=19")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let result = Store::open(&path).await;
        assert!(matches!(
            result,
            Err(StoreError::UnsupportedSchema {
                found,
                supported
            }) if found == CURRENT_SCHEMA_VERSION + 1 && supported == CURRENT_SCHEMA_VERSION
        ));
        let pool = connect_sqlite(&path, false).await.unwrap();
        let table_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(table_count, 0);
        pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn audit_pagination_retention_and_device_inventory_contracts() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "inventory-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let first =
            register_test_node(&r, org.id, &owner, "field-laptop", "inventory-key-1", &[]).await;
        let join: JoinKeyResponse = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", org.id),
                serde_json::json!({"expires_in_seconds":60}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let register_with_posture = call(
            &r,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key": join.key,
                "name": "ranger-tablet",
                "wg_public_key": "inventory-key-2",
                "os": "linux",
                "os_version": "6.8",
                "agent_version": "0.1.0",
                "hostname": "ranger-tablet",
                "capabilities": ["ssh", "wireguard"],
                "ephemeral": false
            }),
            None,
        )
        .await;
        assert_eq!(register_with_posture.status(), StatusCode::CREATED);
        let second: RegisterResponse = body(register_with_posture).await;
        assert_eq!(
            call(
                &r,
                Method::GET,
                &format!("/v1/nodes/{}/peers?ipv6=true", second.id),
                serde_json::Value::Null,
                Some(&second.node_token),
            )
            .await
            .status(),
            StatusCode::OK
        );

        let listed: Vec<NodeRow> = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/nodes?q=ranger&state=online", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, second.id);
        assert_eq!(listed[0].os.as_deref(), Some("linux"));
        assert_eq!(listed[0].agent_version.as_deref(), Some("0.1.0"));
        assert!(listed[0].online);
        assert!(listed[0].capabilities.contains(&"ssh".into()));

        assert_eq!(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/nodes/{}/tombstone", org.id, first.id),
                serde_json::Value::Null,
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/nodes/{}/tombstone", org.id, first.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let hidden: Vec<NodeRow> = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/nodes", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert!(hidden.iter().all(|node| node.id != first.id));
        let tombstones: Vec<NodeRow> = body(
            call(
                &r,
                Method::GET,
                &format!(
                    "/v1/orgs/{}/nodes?include_deleted=true&state=deleted",
                    org.id
                ),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(tombstones.len(), 1);
        assert!(tombstones[0].deleted);

        let first_page: Vec<AuditEvent> = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/audit?limit=1", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(first_page.len(), 1);
        let cursor = format!("{}:{}", first_page[0].created_at, first_page[0].id);
        let second_page: Vec<AuditEvent> = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/audit?limit=200&before={cursor}", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert!(second_page.iter().all(|event| event.id != first_page[0].id));
        sqlx::query("UPDATE audit_events SET created_at=$1 WHERE org_id=$2")
            .bind(now() - DEFAULT_AUDIT_RETENTION_SECS - 10)
            .bind(org.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let retained: Vec<AuditEvent> = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/audit", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert!(retained.is_empty());
    }

    #[tokio::test]
    async fn admin_api_tokens_are_scoped_hashed_and_tenant_bound() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "admin-api-org").await;
        let other = create_test_org(&r, "admin-api-other").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let other_owner = signed_session(other.id, "owner-2", Role::Owner, now() + 60);
        let created: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"github-actions","scopes":["devices:read","status:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        assert!(created.token.starts_with("bta_"));
        let stored_hash: String =
            sqlx::query_scalar("SELECT token_hash FROM api_clients WHERE id=$1")
                .bind(created.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_ne!(stored_hash, created.token);
        assert_eq!(stored_hash, hash(&created.token));

        let status = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {}", created.token))
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        let response = r.clone().oneshot(status).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let forbidden_write = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/keys")
            .header(AUTHORIZATION, format!("Bearer {}", created.token))
            .header("content-type", "application/json")
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from(r#"{"expires_in_seconds":60}"#))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(forbidden_write).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let cross_tenant = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {}", created.token))
            .header("x-blaktail-organisation", other.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(cross_tenant).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let node = register_test_node(&r, org.id, &owner, "api-node", "admin-api-key", &[]).await;
        let node_as_api = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {}", node.node_token))
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(node_as_api).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("/v1/orgs/{}/api-clients/{}", org.id, created.id),
                serde_json::Value::Null,
                Some(&other_owner),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("/v1/orgs/{}/api-clients/{}", org.id, created.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let revoked = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {}", created.token))
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(revoked).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        for path in [
            "/api/v1/status",
            "/api/v1/devices",
            "/api/v1/keys",
            "/api/v1/policy",
            "/api/v1/dns",
            "/api/v1/audit",
        ] {
            let response = r
                .clone()
                .oneshot(
                    Request::builder()
                        .method(if path == "/api/v1/keys" {
                            Method::POST
                        } else {
                            Method::GET
                        })
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must not be anonymous"
            );
        }
    }

    #[tokio::test]
    async fn oauth_client_credentials_exchanges_automation_secret() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "oauth-client-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let created: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"terraform","scopes":["devices:read","status:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let form = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope=status:read",
            created.id, created.token
        );
        let granted = r
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(granted.status(), StatusCode::OK);
        let token: serde_json::Value = body(granted).await;
        let access_token = token["access_token"].as_str().unwrap().to_string();
        assert_ne!(access_token, created.token);
        assert!(access_token.starts_with("bto_"));
        assert_eq!(token["token_type"], "Bearer");
        assert_eq!(token["scope"], "devices:read status:read");
        assert_eq!(token["organisation_id"], org.id.to_string());
        assert_eq!(token["expires_in"].as_i64().unwrap(), 3600);
        let stored_hash: String =
            sqlx::query_scalar("SELECT token_hash FROM oauth_access_tokens WHERE token_prefix=$1")
                .bind(access_token.chars().take(11).collect::<String>())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(stored_hash, crate::hash(&access_token));
        assert_ne!(stored_hash, access_token);

        let status = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(status).await.unwrap().status(),
            StatusCode::OK
        );
        let bootstrap = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {}", created.token))
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(bootstrap).await.unwrap().status(),
            StatusCode::OK
        );

        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", created.id, created.token));
        let via_basic = r
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth/token")
                    .header(AUTHORIZATION, format!("Basic {basic}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(via_basic.status(), StatusCode::OK);
        let via_basic_token: serde_json::Value = body(via_basic).await;
        let second_access = via_basic_token["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(second_access, access_token);
        assert!(second_access.starts_with("bto_"));

        let denied = r
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=client_credentials&client_id={}&client_secret={}&scope=policy:write",
                        created.id, created.token
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
        let denied_body: serde_json::Value = body(denied).await;
        assert_eq!(denied_body["error"], "invalid_scope");

        let unsupported = r
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&client_id={}&client_secret={}",
                        created.id, created.token
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);

        let forged = r
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=client_credentials&client_id={}&client_secret=bta_forged",
                        created.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            forged.headers().get("www-authenticate").unwrap(),
            "Basic realm=\"BlakTail\""
        );

        sqlx::query("UPDATE oauth_access_tokens SET expires_at=$1 WHERE token_hash=$2")
            .bind(now() - 1)
            .bind(crate::hash(&access_token))
            .execute(&store.pool)
            .await
            .unwrap();
        let expired = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(expired).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("/v1/orgs/{}/api-clients/{}", org.id, created.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let after_revoke = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/status")
            .header(AUTHORIZATION, format!("Bearer {second_access}"))
            .header("x-blaktail-organisation", org.id.to_string())
            .body(Body::from("null"))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(after_revoke).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn admin_api_key_mint_is_idempotent_and_uses_error_envelope() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "admin-idem-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let created: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"deploy","scopes":["keys:write","status:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let mint = |ttl: i64| {
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/keys")
                .header(AUTHORIZATION, format!("Bearer {}", created.token))
                .header("x-blaktail-organisation", org.id.to_string())
                .header("content-type", "application/json")
                .header("idempotency-key", "release-key-1")
                .body(Body::from(format!(r#"{{"expires_in_seconds":{ttl}}}"#)))
                .unwrap()
        };
        let first = r.clone().oneshot(mint(60)).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body: serde_json::Value = body(first).await;
        let second = r.clone().oneshot(mint(60)).await.unwrap();
        assert_eq!(second.status(), StatusCode::CREATED);
        let second_body: serde_json::Value = body(second).await;
        assert_eq!(first_body["data"]["id"], second_body["data"]["id"]);
        let conflict = r.clone().oneshot(mint(120)).await.unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let denied = r
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/status")
                    .body(Body::from("null"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let envelope: serde_json::Value = body(denied).await;
        assert_eq!(envelope["code"], "unauthorized");
        assert!(envelope["request_id"].as_str().is_some());
    }

    #[tokio::test]
    async fn admin_api_provider_contract_manages_device_lifecycle() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "provider-contract-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let writer: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({
                    "name": "terraform-provider",
                    "scopes": [
                        "status:read",
                        "devices:read",
                        "devices:write",
                        "keys:write",
                        "policy:write",
                        "dns:write",
                        "audit:read"
                    ]
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        let reader: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({
                    "name": "readonly-provider",
                    "scopes": ["status:read", "devices:read"]
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        let admin = |method: Method, uri: String, token: String, payload: serde_json::Value| {
            let router = r.clone();
            let org_id = org.id;
            async move {
                router
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(uri)
                            .header(AUTHORIZATION, format!("Bearer {token}"))
                            .header("x-blaktail-organisation", org_id.to_string())
                            .header("content-type", "application/json")
                            .body(Body::from(payload.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        };

        let status: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/status".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(status["api"], "v1");
        assert_eq!(status["organisation_id"], org.id.to_string());

        let listed: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/devices".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert!(listed["data"].as_array().unwrap().is_empty());

        let minted = admin(
            Method::POST,
            "/api/v1/keys".into(),
            writer.token.clone(),
            serde_json::json!({"expires_in_seconds": 60}),
        )
        .await;
        assert_eq!(minted.status(), StatusCode::CREATED);
        let minted: serde_json::Value = body(minted).await;
        let join_key = minted["data"]["key"].as_str().unwrap().to_owned();
        assert!(join_key.starts_with("btk_"));

        let registered: RegisterResponse = body(
            call(
                &r,
                Method::POST,
                "/v1/nodes/register",
                serde_json::json!({
                    "join_key": join_key,
                    "name": "provider-node",
                    "wg_public_key": "provider-contract-key",
                    "advertised_routes": []
                }),
                None,
            )
            .await,
        )
        .await;
        assert_eq!(registered.org_id, org.id);

        let listed: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/devices".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(listed["data"][0]["id"], registered.id.to_string());
        assert_eq!(listed["data"][0]["name"], "provider-node");
        assert_eq!(listed["data"][0]["wg_public_key"], "provider-contract-key");

        let got: serde_json::Value = body(
            admin(
                Method::GET,
                format!("/api/v1/devices/{}", registered.id),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(got["data"]["dns_name"], registered.dns_name);

        let renamed = admin(
            Method::PUT,
            format!("/api/v1/devices/{}/friendly-name", registered.id),
            writer.token.clone(),
            serde_json::json!({"friendly_name": "Ranger tablet"}),
        )
        .await;
        assert_eq!(renamed.status(), StatusCode::NO_CONTENT);
        let got: serde_json::Value = body(
            admin(
                Method::GET,
                format!("/api/v1/devices/{}", registered.id),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(got["data"]["display_name"], "Ranger tablet");
        assert_eq!(got["data"]["name"], "provider-node");
        assert_eq!(got["data"]["wg_public_key"], "provider-contract-key");

        let policy: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/policy".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        let policy_etag = policy["data"]["etag"].as_str().unwrap();
        let published_policy = admin(
            Method::PUT,
            "/api/v1/policy".into(),
            writer.token.clone(),
            serde_json::json!({
                "etag": policy_etag,
                "acl": {
                    "version": 1,
                    "groups": {"rangers": ["alice-user"]},
                    "tag_owners": {},
                    "rules": [{
                        "action": "allow",
                        "src_groups": ["rangers"],
                        "dst_tags": ["store"]
                    }],
                    "tests": []
                }
            }),
        )
        .await;
        assert_eq!(published_policy.status(), StatusCode::NO_CONTENT);
        let stale_policy = admin(
            Method::PUT,
            "/api/v1/policy".into(),
            writer.token.clone(),
            serde_json::json!({"etag": policy_etag, "acl": {"rules": []}}),
        )
        .await;
        assert_eq!(stale_policy.status(), StatusCode::PRECONDITION_FAILED);

        let dns: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/dns".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(dns["data"]["revision"], 0);
        let published_dns = admin(
            Method::PUT,
            "/api/v1/dns".into(),
            writer.token.clone(),
            serde_json::json!({
                "etag": dns["data"]["etag"],
                "dns": {
                    "managed": true,
                    "split": [{"suffix": "internal.example", "resolvers": ["10.0.0.53"]}],
                    "records": [{"name": "wiki.internal.example", "type": "A", "value": "10.0.0.10"}]
                }
            }),
        )
        .await;
        assert_eq!(published_dns.status(), StatusCode::OK);
        let published_dns: serde_json::Value = body(published_dns).await;
        assert_eq!(published_dns["data"]["revision"], 1);

        assert_eq!(
            admin(
                Method::PUT,
                "/api/v1/policy".into(),
                reader.token.clone(),
                serde_json::json!({"acl": {"rules": []}}),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin(
                Method::PUT,
                "/api/v1/dns".into(),
                reader.token.clone(),
                serde_json::json!({"rollback": true}),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin(
                Method::PUT,
                format!("/api/v1/devices/{}/friendly-name", registered.id),
                reader.token.clone(),
                serde_json::json!({"friendly_name": "should-fail"}),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin(
                Method::POST,
                format!("/api/v1/devices/{}/tombstone", registered.id),
                reader.token.clone(),
                serde_json::Value::Null,
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        let tombstoned = admin(
            Method::POST,
            format!("/api/v1/devices/{}/tombstone", registered.id),
            writer.token.clone(),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(tombstoned.status(), StatusCode::NO_CONTENT);
        let listed: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/devices".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert!(listed["data"].as_array().unwrap().is_empty());
        let tombstone: serde_json::Value = body(
            admin(
                Method::GET,
                format!("/api/v1/devices/{}", registered.id),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(tombstone["data"]["deleted"], true);
        assert_ne!(tombstone["data"]["name"], "provider-node");
        assert_ne!(tombstone["data"]["wg_public_key"], "provider-contract-key");

        let audit: serde_json::Value = body(
            admin(
                Method::GET,
                "/api/v1/audit".into(),
                writer.token.clone(),
                serde_json::Value::Null,
            )
            .await,
        )
        .await;
        let actions: Vec<&str> = audit["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["action"].as_str())
            .collect();
        for action in [
            "join_key.minted",
            "node.friendly_name_updated",
            "acl.updated",
            "dns.updated",
            "node.tombstoned",
        ] {
            assert!(actions.contains(&action), "missing audit action {action}");
        }
        assert_eq!(
            admin(
                Method::GET,
                "/api/v1/audit".into(),
                reader.token.clone(),
                serde_json::Value::Null,
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn device_inventory_paginates_ten_thousand_duplicate_labels() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "inventory-10k-org").await;
        let other = create_test_org(&r, "inventory-10k-other").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let created_at = now();
        let expires = created_at + 86_400;
        let mut tx = store.pool.begin().await.unwrap();
        for index in 0..10_000 {
            let octet_hi = 1 + index / 254;
            let octet_lo = 1 + index % 254;
            let name = format!("node-{index:05}");
            sqlx::query(
                "INSERT INTO nodes(id,org_id,name,display_name,wg_public_key,allowed_ips_json,token_hash,created_at,user_id,user_role,tags_json,dns_name,advertised_routes_json,approved_routes_json,credential_expires_at,capabilities_json,ephemeral) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'[]',$11,'[]','[]',$12,'[]',0)",
            )
            .bind(Uuid::from_u128(index as u128 + 1).to_string())
            .bind(org.id.to_string())
            .bind(&name)
            .bind("Ranger tablet")
            .bind(format!("key-{index:05}"))
            .bind(format!(r#"["100.64.{octet_hi}.{octet_lo}/32"]"#))
            .bind(format!("hash-{index:05}"))
            .bind(created_at)
            .bind("owner-1")
            .bind("owner")
            .bind(magic_dns_name(&name, &org.id.to_string()))
            .bind(expires)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO nodes(id,org_id,name,display_name,wg_public_key,allowed_ips_json,token_hash,created_at,user_id,user_role,tags_json,dns_name,advertised_routes_json,approved_routes_json,credential_expires_at,capabilities_json,ephemeral) VALUES($1,$2,'foreign','Ranger tablet','foreign-key','[\"100.64.200.1/32\"]','foreign-hash',$3,'owner-1','owner','[]',$4,'[]','[]',$5,'[]',0)",
        )
        .bind(Uuid::from_u128(99_999).to_string())
        .bind(other.id.to_string())
        .bind(created_at)
        .bind(magic_dns_name("foreign", &other.id.to_string()))
        .bind(expires)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let reader: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"inventory","scopes":["devices:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let mut seen = std::collections::HashSet::new();
        let mut before = None;
        loop {
            let uri = match &before {
                Some(id) => format!("/api/v1/devices?limit=200&before={id}"),
                None => "/api/v1/devices?limit=200".into(),
            };
            let page: serde_json::Value = body(
                r.clone()
                    .oneshot(
                        Request::builder()
                            .method(Method::GET)
                            .uri(uri)
                            .header(AUTHORIZATION, format!("Bearer {}", reader.token))
                            .header("x-blaktail-organisation", org.id.to_string())
                            .body(Body::from("null"))
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            )
            .await;
            let nodes = page["data"].as_array().unwrap();
            if nodes.is_empty() {
                break;
            }
            for node in nodes {
                assert_eq!(node["display_name"], "Ranger tablet");
                assert_ne!(node["name"], "foreign");
                assert!(seen.insert(node["id"].as_str().unwrap().to_owned()));
            }
            before = nodes
                .last()
                .and_then(|node| node["id"].as_str())
                .map(ToOwned::to_owned);
            if nodes.len() < 200 {
                break;
            }
        }
        assert_eq!(seen.len(), 10_000);
        let search: serde_json::Value = body(
            r.clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/api/v1/devices?q=node-00001")
                        .header(AUTHORIZATION, format!("Bearer {}", reader.token))
                        .header("x-blaktail-organisation", org.id.to_string())
                        .body(Body::from("null"))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(search["data"].as_array().unwrap().len(), 1);
        assert_eq!(search["data"][0]["name"], "node-00001");
    }

    #[tokio::test]
    async fn org_dns_settings_publish_rollback_and_reject_leaks() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "dns-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let initial: crate::org_dns::OrgDnsResponse = body(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{}/dns", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(initial.revision, 0);
        assert!(initial.dns.managed);
        assert_eq!(
            call(
                &r,
                Method::PUT,
                &format!("/v1/orgs/{}/dns", org.id),
                serde_json::json!({
                    "dns": {
                        "managed": true,
                        "split": [{"suffix":"internal.example","resolvers":["10.0.0.53"]}],
                        "records": [{"name":"wiki.internal.example","type":"A","value":"10.0.0.10"}]
                    }
                }),
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &r,
                Method::PUT,
                &format!("/v1/orgs/{}/dns", org.id),
                serde_json::json!({
                    "dns": {
                        "split": [{"suffix":"abc.blaktail","resolvers":["1.1.1.1"]}]
                    }
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let published: crate::org_dns::OrgDnsResponse = body(
            call(
                &r,
                Method::PUT,
                &format!("/v1/orgs/{}/dns", org.id),
                serde_json::json!({
                    "dns": {
                        "managed": true,
                        "global_resolvers": ["1.1.1.1"],
                        "split": [{"suffix":"internal.example","resolvers":["10.0.0.53"]}],
                        "search_domains": ["internal.example"],
                        "records": [
                            {"name":"wiki.internal.example","type":"A","value":"10.0.0.10"},
                            {"name":"wiki.internal.example","type":"AAAA","value":"fd00::10"}
                        ]
                    }
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(published.revision, 1);
        assert_eq!(published.dns.split[0].suffix, "internal.example");
        let stale = Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/orgs/{}/dns", org.id))
            .header(
                AUTHORIZATION,
                format!("Bearer {}", sign_test_assertion(&owner)),
            )
            .header("content-type", "application/json")
            .header("if-match", initial.etag)
            .body(Body::from(
                r#"{"dns":{"managed":true,"global_resolvers":["8.8.8.8"]}}"#,
            ))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(stale).await.unwrap().status(),
            StatusCode::PRECONDITION_FAILED
        );
        let writer: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"dns-writer","scopes":["dns:write","devices:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let reader: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"dns-reader","scopes":["devices:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let forbidden = Request::builder()
            .method(Method::PUT)
            .uri("/api/v1/dns")
            .header(AUTHORIZATION, format!("Bearer {}", reader.token))
            .header("x-blaktail-organisation", org.id.to_string())
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"etag":"{}","dns":{{"managed":false}}}}"#,
                published.etag
            )))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(forbidden).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let rolled = Request::builder()
            .method(Method::PUT)
            .uri("/api/v1/dns")
            .header(AUTHORIZATION, format!("Bearer {}", writer.token))
            .header("x-blaktail-organisation", org.id.to_string())
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"etag":"{}","rollback":true}}"#,
                published.etag
            )))
            .unwrap();
        let rolled = r.clone().oneshot(rolled).await.unwrap();
        assert_eq!(rolled.status(), StatusCode::OK);
        let rolled_body: serde_json::Value = body(rolled).await;
        assert_eq!(rolled_body["data"]["revision"], 2);
        assert!(rolled_body["data"]["dns"]["split"]
            .as_array()
            .unwrap()
            .is_empty());
        let node = register_test_node(&r, org.id, &owner, "dns-node", "dns-join", &[]).await;
        let peers = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/nodes/{}/peers", node.id))
            .header(AUTHORIZATION, format!("Bearer {}", node.node_token))
            .body(Body::from("null"))
            .unwrap();
        let peers: serde_json::Value = body(r.clone().oneshot(peers).await.unwrap()).await;
        assert_eq!(peers["dns"]["revision"], 2);
        assert_eq!(
            peers["dns"]["magic_dns_suffix"],
            crate::org_dns::organisation_magic_dns_suffix(&org.id.to_string())
        );
    }

    #[test]
    fn admin_api_rate_limiter_bounds_a_client_window() {
        let limiter = ApiRateLimiter::default();
        assert!(limiter.allow("client-a", 1_000, 2, 60));
        assert!(limiter.allow("client-a", 1_001, 2, 60));
        assert!(!limiter.allow("client-a", 1_002, 2, 60));
        assert!(limiter.allow("client-b", 1_002, 2, 60));
        assert!(limiter.allow("client-a", 1_061, 2, 60));
    }

    #[tokio::test]
    async fn admin_api_rejects_oversized_bodies_and_rate_limits_tokens() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&r, "admin-limits-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let created: crate::admin::ApiClientCreated = body(
            call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"limits","scopes":["status:read"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let oversized = Request::builder()
            .method(Method::PUT)
            .uri("/api/v1/policy")
            .header(AUTHORIZATION, format!("Bearer {}", created.token))
            .header("x-blaktail-organisation", org.id.to_string())
            .header("content-type", "application/json")
            .body(Body::from("x".repeat(ADMIN_API_MAX_BODY_BYTES + 1)))
            .unwrap();
        assert_eq!(
            r.clone().oneshot(oversized).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let mut last = StatusCode::OK;
        for _ in 0..(ADMIN_API_RATE_LIMIT + 1) {
            last = r
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/api/v1/status")
                        .header(AUTHORIZATION, format!("Bearer {}", created.token))
                        .header("x-blaktail-organisation", org.id.to_string())
                        .body(Body::from("null"))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status();
            if last == StatusCode::TOO_MANY_REQUESTS {
                break;
            }
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn wireguard_only_peers_are_exported_revoked_and_rejected_for_members() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "wg-only-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let node =
            register_test_node(&router, org.id, &owner, "office-one", "office-key", &[]).await;
        sqlx::query("UPDATE nodes SET tags_json=$1 WHERE id=$2")
            .bind(r#"["office"]"#)
            .bind(node.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let create = serde_json::json!({
            "name": "site-router",
            "kind": "wireguard_only",
            "wg_public_key": "siteRouterPublicKeyExample+/=",
            "endpoint": "203.0.113.10:51820",
            "allowed_ips": ["10.8.0.0/24"],
            "tags": ["office"]
        });
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/wireguard-only-peers", org.id),
                create.clone(),
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/wireguard-only-peers", org.id),
                serde_json::json!({
                    "name": "default-route",
                    "kind": "wireguard_only",
                    "wg_public_key": "anotherPublicKeyExample+/=",
                    "endpoint": "203.0.113.11:51820",
                    "allowed_ips": ["0.0.0.0/0"]
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/wireguard-only-peers", org.id),
                serde_json::json!({
                    "name": "private-key",
                    "kind": "wireguard_only",
                    "wg_public_key": "-----BEGIN PRIVATE KEY-----",
                    "endpoint": "203.0.113.11:51820",
                    "allowed_ips": ["10.8.0.0/24"]
                }),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let created: crate::wg_only::WireGuardOnlyPeer = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/wireguard-only-peers", org.id),
                create,
                Some(&admin),
            )
            .await,
        )
        .await;
        assert_eq!(created.kind, "wireguard_only");
        assert_eq!(created.wg_public_key, "siteRouterPublicKeyExample+/=");
        assert!(!serde_json::to_string(&created)
            .unwrap()
            .to_ascii_uppercase()
            .contains("PRIVATE"));

        let peers: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        let exported = peers
            .peers
            .iter()
            .find(|peer| peer.kind == "wireguard_only")
            .expect("policy-selected unmanaged peer is exported");
        assert_eq!(exported.id, created.id);
        assert_eq!(exported.endpoint.as_deref(), Some("203.0.113.10:51820"));
        assert_eq!(exported.allowed_ips, vec!["10.8.0.0/24"]);
        assert_eq!(exported.dns_name, "");
        assert_eq!(exported.relay_endpoint, None);

        let tagged: crate::wg_only::WireGuardOnlyPeer = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/wireguard-only-peers", org.id),
                serde_json::json!({
                    "name": "store-router",
                    "kind": "wireguard_only",
                    "wg_public_key": "storeRouterPublicKeyExample+/=",
                    "endpoint": "203.0.113.12:51820",
                    "allowed_ips": ["10.9.0.0/24"],
                    "tags": ["store"]
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        let filtered: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        assert!(filtered
            .peers
            .iter()
            .any(|peer| peer.id == created.id && peer.kind == "wireguard_only"));
        assert!(!filtered.peers.iter().any(|peer| peer.id == tagged.id));

        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &format!("/v1/orgs/{}/wireguard-only-peers/{}", org.id, created.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let after_revoke: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        assert!(!after_revoke.peers.iter().any(|peer| peer.id == created.id));

        let writer: crate::admin::ApiClientCreated = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/api-clients", org.id),
                serde_json::json!({"name":"wg-writer","scopes":["devices:write"]}),
                Some(&owner),
            )
            .await,
        )
        .await;
        let listed: serde_json::Value = body(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/api/v1/wireguard-only-peers")
                        .header(AUTHORIZATION, format!("Bearer {}", writer.token))
                        .header("x-blaktail-organisation", org.id.to_string())
                        .body(Body::from("null"))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed["data"].as_array().unwrap().len(), 2);
        assert_eq!(listed["data"][0]["kind"], "wireguard_only");
        assert!(listed
            .to_string()
            .to_ascii_uppercase()
            .find("PRIVATE")
            .is_none());
    }

    #[tokio::test]
    async fn wireguard_only_rotation_exports_both_keys_then_drops_the_old_one() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "wg-rotate-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
        let node =
            register_test_node(&router, org.id, &owner, "office-one", "office-key", &[]).await;
        sqlx::query("UPDATE nodes SET tags_json=$1 WHERE id=$2")
            .bind(r#"["office"]"#)
            .bind(node.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let created: crate::wg_only::WireGuardOnlyPeer = body(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/wireguard-only-peers", org.id),
                serde_json::json!({
                    "name": "site-router",
                    "kind": "wireguard_only",
                    "wg_public_key": "oldRouterPublicKeyExample+/=",
                    "endpoint": "203.0.113.10:51820",
                    "allowed_ips": ["10.8.0.0/24"],
                    "tags": ["office"]
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!(
                    "/v1/orgs/{}/wireguard-only-peers/{}/rotate",
                    org.id, created.id
                ),
                serde_json::json!({
                    "wg_public_key": "newRouterPublicKeyExample+/=",
                    "overlap_seconds": 15
                }),
                Some(&member),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let rotated: crate::wg_only::WireGuardOnlyPeer = body(
            call(
                &router,
                Method::POST,
                &format!(
                    "/v1/orgs/{}/wireguard-only-peers/{}/rotate",
                    org.id, created.id
                ),
                serde_json::json!({
                    "wg_public_key": "newRouterPublicKeyExample+/=",
                    "overlap_seconds": 15
                }),
                Some(&owner),
            )
            .await,
        )
        .await;
        assert_eq!(rotated.wg_public_key, "newRouterPublicKeyExample+/=");
        assert_eq!(
            rotated.previous_wg_public_key.as_deref(),
            Some("oldRouterPublicKeyExample+/=")
        );
        assert!(rotated.overlap_until.is_some_and(|until| until > now()));
        let overlapping: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        let keys: Vec<_> = overlapping
            .peers
            .iter()
            .filter(|peer| peer.kind == "wireguard_only")
            .map(|peer| peer.wg_public_key.as_str())
            .collect();
        assert!(keys.contains(&"newRouterPublicKeyExample+/="));
        assert!(keys.contains(&"oldRouterPublicKeyExample+/="));
        let during: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/updates?since=0&wait=0", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        let seen_revision = during["revision"].as_i64().expect("control revision");
        sqlx::query("UPDATE wireguard_only_peers SET overlap_until=$1 WHERE id=$2")
            .bind(now() - 1)
            .bind(created.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let after_wait = call(
            &router,
            Method::GET,
            &format!("/v1/nodes/{}/updates?since={seen_revision}&wait=0", node.id),
            serde_json::Value::Null,
            Some(&node.node_token),
        )
        .await;
        assert_eq!(after_wait.status(), StatusCode::OK);
        let after_update: serde_json::Value = body(after_wait).await;
        assert_eq!(after_update["kind"], "snapshot");
        let update_keys: Vec<&str> = after_update["peers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|peer| peer["kind"] == "wireguard_only")
            .filter_map(|peer| peer["wg_public_key"].as_str())
            .collect();
        assert_eq!(update_keys, vec!["newRouterPublicKeyExample+/="]);
        let after_overlap: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        let remaining: Vec<_> = after_overlap
            .peers
            .iter()
            .filter(|peer| peer.kind == "wireguard_only")
            .map(|peer| peer.wg_public_key.as_str())
            .collect();
        assert_eq!(remaining, vec!["newRouterPublicKeyExample+/="]);
        assert!(!after_overlap
            .peers
            .iter()
            .any(|peer| peer.wg_public_key == "oldRouterPublicKeyExample+/="));
    }

    #[tokio::test]
    async fn control_updates_return_snapshot_or_wait_without_crossing_gateway_cap() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "control-stream-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let node =
            register_test_node(&router, org.id, &owner, "office-one", "office-key", &[]).await;
        let snapshot: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/updates?since=0&wait=0", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(snapshot["kind"], "snapshot");
        assert_eq!(snapshot["control_updates"]["wait_max_seconds"], 25);
        let revision = snapshot["revision"].as_i64().unwrap();
        assert!(revision >= 1);

        let peers: PeersResponse = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/peers", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(peers.control_updates.as_ref().unwrap().wait_max_seconds, 25);

        let started = Instant::now();
        let unchanged = call(
            &router,
            Method::GET,
            &format!("/v1/nodes/{}/updates?since={revision}&wait=1", node.id),
            serde_json::Value::Null,
            Some(&node.node_token),
        )
        .await;
        assert_eq!(unchanged.status(), StatusCode::NO_CONTENT);
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert!(started.elapsed() < Duration::from_secs(3));

        let waiter = {
            let router = router.clone();
            let token = node.node_token.clone();
            let path = format!("/v1/nodes/{}/updates?since={revision}&wait=5", node.id);
            tokio::spawn(async move {
                call(
                    &router,
                    Method::GET,
                    &path,
                    serde_json::Value::Null,
                    Some(&token),
                )
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::json!({"rules":[]}),
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let woken = waiter.await.unwrap();
        assert_eq!(woken.status(), StatusCode::OK);
        let updated: serde_json::Value = body(woken).await;
        assert_eq!(updated["kind"], "snapshot");
        assert!(updated["revision"].as_i64().unwrap() > revision);

        assert_eq!(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/updates?since=0&wait=1&version=3", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn control_view_storm_clears_baselines_so_the_next_poll_is_a_snapshot() {
        let views = Mutex::new(ControlViewMap::new());
        let observer = Uuid::from_u128(1);
        let peers = BTreeSet::from([Uuid::from_u128(9)]);
        assert!(remember_and_baseline(&views, observer, 1, &peers).is_none());
        assert_eq!(
            remember_and_baseline(&views, observer, 2, &peers).map(|(revision, _)| revision),
            Some(1)
        );
        {
            let mut map = views.lock().unwrap();
            map.clear();
            for index in 0..MAX_CONTROL_VIEWS {
                map.insert(Uuid::from_u128(1_000 + index as u128), (1, BTreeSet::new()));
            }
        }
        assert!(remember_and_baseline(&views, observer, 3, &peers).is_none());
        assert_eq!(views.lock().unwrap().len(), 1);
        assert_eq!(
            remember_and_baseline(&views, observer, 4, &peers).map(|(revision, _)| revision),
            Some(3)
        );
    }

    #[tokio::test]
    async fn control_updates_many_waiters_finish_within_the_wait_cap() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "control-storm-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let node =
            register_test_node(&router, org.id, &owner, "office-one", "office-key", &[]).await;
        let snapshot: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/updates?since=0&wait=0", node.id),
                serde_json::Value::Null,
                Some(&node.node_token),
            )
            .await,
        )
        .await;
        let revision = snapshot["revision"].as_i64().unwrap();
        let started = Instant::now();
        let mut waiters = Vec::new();
        for _ in 0..16 {
            let router = router.clone();
            let token = node.node_token.clone();
            let path = format!("/v1/nodes/{}/updates?since={revision}&wait=1", node.id);
            waiters.push(tokio::spawn(async move {
                call(
                    &router,
                    Method::GET,
                    &path,
                    serde_json::Value::Null,
                    Some(&token),
                )
                .await
            }));
        }
        let mut statuses = Vec::new();
        for waiter in waiters {
            statuses.push(waiter.await.unwrap().status());
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "waiters took {:?}",
            started.elapsed()
        );
        assert!(
            statuses
                .iter()
                .all(|status| *status == StatusCode::NO_CONTENT),
            "{statuses:?}"
        );
    }

    #[tokio::test]
    async fn control_updates_coalesce_peer_add_and_revoke_into_one_delta() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "control-delta-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let office =
            register_test_node(&router, org.id, &owner, "office-one", "office-key", &[]).await;
        let snapshot: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/updates?since=0&wait=0&version=2", office.id),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(snapshot["kind"], "snapshot");
        let revision = snapshot["revision"].as_i64().unwrap();

        let store_node =
            register_test_node(&router, org.id, &owner, "store-one", "store-key", &[]).await;
        let extra =
            register_test_node(&router, org.id, &owner, "store-two", "store-two-key", &[]).await;
        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &format!("/v1/orgs/{}/nodes/{}", org.id, extra.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        let v1: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!(
                    "/v1/nodes/{}/updates?since={revision}&wait=0&version=1",
                    office.id
                ),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(v1["kind"], "snapshot");
        assert!(v1["added"].is_null());
        assert!(v1["peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|peer| { peer["id"] == store_node.id.to_string() }));

        let snapshot_again: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/updates?since=0&wait=0&version=2", office.id),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        let baseline = snapshot_again["revision"].as_i64().unwrap();
        let third = register_test_node(
            &router,
            org.id,
            &owner,
            "store-three",
            "store-three-key",
            &[],
        )
        .await;
        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &format!("/v1/orgs/{}/nodes/{}", org.id, store_node.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        let delta: serde_json::Value = body(
            call(
                &router,
                Method::GET,
                &format!(
                    "/v1/nodes/{}/updates?since={baseline}&wait=0&version=2",
                    office.id
                ),
                serde_json::Value::Null,
                Some(&office.node_token),
            )
            .await,
        )
        .await;
        assert_eq!(delta["kind"], "delta");
        assert!(delta["revision"].as_i64().unwrap() > baseline);
        let added = delta["added"].as_array().unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0]["id"], third.id.to_string());
        let removed = delta["removed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(removed.contains(&store_node.id.to_string()));
        assert!(!removed.contains(&extra.id.to_string()));
        assert!(delta["peers"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn expired_tombstones_are_hard_deleted_without_touching_active_nodes() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, "tombstone-purge-org").await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let stale =
            register_test_node(&router, org.id, &owner, "stale-node", "stale-key", &[]).await;
        let fresh =
            register_test_node(&router, org.id, &owner, "fresh-node", "fresh-key", &[]).await;
        let live = register_test_node(&router, org.id, &owner, "live-node", "live-key", &[]).await;
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/nodes/{}/tombstone", org.id, stale.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/nodes/{}/tombstone", org.id, fresh.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        sqlx::query("UPDATE nodes SET deleted_at=$1 WHERE id=$2")
            .bind(now() - DEFAULT_TOMBSTONE_RETENTION_SECS - 60)
            .bind(stale.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        let remaining: Vec<NodeRow> = body(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/nodes?include_deleted=true", org.id),
                serde_json::Value::Null,
                Some(&owner),
            )
            .await,
        )
        .await;
        assert!(remaining.iter().all(|node| node.id != stale.id));
        assert!(remaining
            .iter()
            .any(|node| node.id == fresh.id && node.deleted));
        assert!(remaining
            .iter()
            .any(|node| node.id == live.id && !node.deleted));

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE org_id=$1")
            .bind(org.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
        let audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='node.tombstoned'",
        )
        .bind(org.id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(audit, 2);
    }

    async fn insert_synthetic_peers(store: &Store, org_id: Uuid, count: usize) {
        let created_at = now();
        let expires = created_at + 86_400;
        let mut tx = store.pool.begin().await.unwrap();
        for index in 0..count {
            let octet_hi = 1 + index / 254;
            let octet_lo = 1 + index % 254;
            let name = format!("bench-{index:05}");
            sqlx::query(
                "INSERT INTO nodes(id,org_id,name,display_name,wg_public_key,allowed_ips_json,token_hash,created_at,user_id,user_role,tags_json,dns_name,advertised_routes_json,approved_routes_json,credential_expires_at,capabilities_json,ephemeral) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'[]',$11,'[]','[]',$12,'[]',0)",
            )
            .bind(Uuid::from_u128(index as u128 + 1).to_string())
            .bind(org_id.to_string())
            .bind(&name)
            .bind(&name)
            .bind(format!("bench-key-{index:05}"))
            .bind(format!(r#"["100.64.{octet_hi}.{octet_lo}/32"]"#))
            .bind(format!("bench-hash-{index:05}"))
            .bind(created_at)
            .bind("owner-1")
            .bind("owner")
            .bind(magic_dns_name(&name, &org_id.to_string()))
            .bind(expires)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }

    async fn measure_control_update_baseline(
        label: &str,
        peer_count: usize,
        snapshot_ms_limit: u128,
        delta_ms_limit: u128,
    ) {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
        let org = create_test_org(&router, &format!("control-bench-{label}")).await;
        let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
        let observer =
            register_test_node(&router, org.id, &owner, "observer", "observer-key", &[]).await;
        insert_synthetic_peers(&store, org.id, peer_count).await;

        let started = Instant::now();
        let snapshot_response = call(
            &router,
            Method::GET,
            &format!("/v1/nodes/{}/updates?since=0&wait=0&version=2", observer.id),
            serde_json::Value::Null,
            Some(&observer.node_token),
        )
        .await;
        let snapshot_ms = started.elapsed().as_millis();
        assert_eq!(snapshot_response.status(), StatusCode::OK);
        let snapshot_bytes = to_bytes(snapshot_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&snapshot_bytes).unwrap();
        assert_eq!(snapshot["kind"], "snapshot");
        let peers = snapshot["peers"].as_array().unwrap();
        assert_eq!(peers.len(), peer_count);
        let revision = snapshot["revision"].as_i64().unwrap();
        register_test_node(
            &router,
            org.id,
            &owner,
            &format!("bench-extra-{label}"),
            &format!("bench-extra-key-{label}"),
            &[],
        )
        .await;

        let started = Instant::now();
        let delta_response = call(
            &router,
            Method::GET,
            &format!(
                "/v1/nodes/{}/updates?since={revision}&wait=0&version=2",
                observer.id
            ),
            serde_json::Value::Null,
            Some(&observer.node_token),
        )
        .await;
        let delta_ms = started.elapsed().as_millis();
        assert_eq!(delta_response.status(), StatusCode::OK);
        let delta_bytes = to_bytes(delta_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let delta: serde_json::Value = serde_json::from_slice(&delta_bytes).unwrap();
        assert!(
            delta["kind"] == "delta" || delta["kind"] == "snapshot",
            "unexpected control update {delta}"
        );

        println!(
            "control_update_baseline nodes={} snapshot_ms={} snapshot_bytes={} peers={} delta_ms={} delta_bytes={} connections=1",
            peer_count + 1,
            snapshot_ms,
            snapshot_bytes.len(),
            peers.len(),
            delta_ms,
            delta_bytes.len()
        );
        assert!(
            snapshot_ms < snapshot_ms_limit,
            "snapshot {snapshot_ms}ms exceeded {snapshot_ms_limit}ms"
        );
        assert!(
            delta_ms < delta_ms_limit,
            "delta {delta_ms}ms exceeded {delta_ms_limit}ms"
        );
    }

    #[tokio::test]
    async fn control_update_baseline_one_thousand() {
        measure_control_update_baseline("1k", 1_000, 20_000, 10_000).await;
    }

    #[tokio::test]
    async fn control_update_baseline_ten_thousand() {
        measure_control_update_baseline("10k", 10_000, 60_000, 15_000).await;
    }
}
