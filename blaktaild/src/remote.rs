//! Browser remote access and allowlisted remote jobs (draft 13).
//!
//! Two separate opt-ins. The sshd drop-in plus `BLAKTAIL_SSH_USER_CA` lets
//! the organisation's onshore gateway log in with session certificates (see
//! `sshd`). `--allow-remote-jobs` with `--remote-jobs-user` lets this agent
//! pull owner-approved, coordinator-signed jobs and run exactly their argv
//! (no shell) as that unprivileged user, with a timeout, an output cap and
//! cancellation. The agent never accepts a command string from anywhere.

use crate::{read_state, Coordinator, Error, NodeState};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, sync::watch};
use uuid::Uuid;

pub const CAP_REMOTE_SSH: &str = "remote-ssh-ca";
pub const CAP_REMOTE_JOBS: &str = "remote-jobs";
pub const HOST_KEY_ENV: &str = "BLAKTAIL_SSH_HOST_KEY";
pub const DEFAULT_HOST_KEY: &str = "/etc/ssh/ssh_host_ed25519_key.pub";
const JOB_SIGNATURE_CONTEXT: &str = "blaktail-remote-job-v1\n";
const MAX_TIMEOUT_SECS: i64 = 10 * 60;
const MAX_OUTPUT_BYTES: i64 = 64 * 1024;
const PIN_FILE: &str = "remote-jobs.pub";
const CANCEL_CHECK: Duration = Duration::from_secs(2);

/// What the coordinator publishes with each peer map.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteAccessView {
    #[serde(default)]
    pub user_ca: String,
    #[serde(default)]
    pub gateway_addresses: Vec<String>,
    #[serde(default)]
    pub job_signing_key: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteState {
    #[serde(default)]
    pub view: Option<RemoteAccessView>,
    /// The last sshd apply proved the gateway-only CA block is active.
    #[serde(default)]
    pub ssh_ca_active: bool,
    #[serde(default)]
    pub jobs_enabled: bool,
    /// Host key last accepted by the coordinator, to report only changes.
    #[serde(default)]
    pub host_key_reported: Option<String>,
}

impl RemoteState {
    pub fn capabilities(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.ssh_ca_active {
            out.push(CAP_REMOTE_SSH.to_string());
        }
        if self.jobs_enabled {
            out.push(CAP_REMOTE_JOBS.to_string());
        }
        out
    }
}

/// The local Ed25519 host public key, without its comment.
pub fn local_host_key() -> Option<String> {
    let path = std::env::var_os(HOST_KEY_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_HOST_KEY));
    let text = std::fs::read_to_string(path).ok()?;
    let mut parts = text.split_whitespace();
    let (Some("ssh-ed25519"), Some(data)) = (parts.next(), parts.next()) else {
        return None;
    };
    Some(format!("ssh-ed25519 {data}"))
}

impl Coordinator {
    /// Reports this device's SSH host key so the gateway can pin it.
    pub async fn report_ssh_host_key(&self, state: &NodeState, key: &str) -> Result<(), Error> {
        self.client
            .put(format!(
                "{}/v1/nodes/{}/ssh-host-key",
                self.base, state.node_id
            ))
            .bearer_auth(&state.node_token)
            .json(&serde_json::json!({ "public_key": key }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// Sends the host key when it differs from the last accepted report.
pub async fn report_host_key(coordinator: &Coordinator, state: &mut NodeState) -> bool {
    let Some(key) = local_host_key() else {
        return false;
    };
    if state.remote.host_key_reported.as_deref() == Some(key.as_str()) {
        return false;
    }
    match coordinator.report_ssh_host_key(state, &key).await {
        Ok(()) => {
            state.remote.host_key_reported = Some(key);
            true
        }
        Err(error) => {
            tracing::warn!(%error, "could not report the SSH host key");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Remote jobs

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedJob {
    pub run_id: Uuid,
    pub org_id: Uuid,
    pub node_id: Uuid,
    pub argv: Vec<String>,
    pub timeout_secs: i64,
    pub output_cap_bytes: i64,
    pub expires_at: i64,
}

#[derive(Deserialize)]
struct AgentJob {
    run_id: Uuid,
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
struct AgentJobs {
    jobs: Vec<AgentJob>,
}

#[derive(Deserialize)]
struct JobState {
    cancel: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Outcome {
    pub status: &'static str,
    pub exit_code: Option<i64>,
    pub output: String,
    pub output_truncated: bool,
}

/// Verifies a job against the pinned key and this node, and returns the
/// job only if every bound holds. Nothing unsigned reaches the executor.
pub fn verify_job(
    pinned_key: &str,
    node_id: Uuid,
    payload: &str,
    signature: &str,
    now: i64,
) -> Result<SignedJob, String> {
    let key: [u8; 32] = STANDARD
        .decode(pinned_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("job signing key is malformed")?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| "job signing key is invalid")?;
    let signature = STANDARD
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or("job signature is malformed")?;
    key.verify_strict(
        format!("{JOB_SIGNATURE_CONTEXT}{payload}").as_bytes(),
        &signature,
    )
    .map_err(|_| "job signature does not verify")?;
    let job: SignedJob = serde_json::from_str(payload).map_err(|_| "job payload is malformed")?;
    if job.node_id != node_id {
        return Err("job is for another device".into());
    }
    if job.expires_at <= now {
        return Err("job approval has expired".into());
    }
    if job.argv.is_empty() || !job.argv[0].starts_with('/') {
        return Err("job program must be an absolute path".into());
    }
    if !(1..=MAX_TIMEOUT_SECS).contains(&job.timeout_secs)
        || !(1..=MAX_OUTPUT_BYTES).contains(&job.output_cap_bytes)
    {
        return Err("job limits are out of range".into());
    }
    Ok(job)
}

/// Pins the coordinator's job key on first use; a changed key stops jobs
/// until an operator removes the pin file.
fn pinned_key(state_dir: &Path, published: &str) -> Result<String, String> {
    let path = state_dir.join(PIN_FILE);
    match std::fs::read_to_string(&path) {
        Ok(pinned) if pinned.trim() == published => Ok(published.to_owned()),
        Ok(_) => Err(format!(
            "the coordinator's job signing key changed; remote jobs stay off until {} is removed",
            path.display()
        )),
        Err(_) if !published.is_empty() => {
            crate::write_secret(&path, published.as_bytes()).map_err(|error| error.to_string())?;
            Ok(published.to_owned())
        }
        Err(_) => Err("the coordinator has not published a job signing key".into()),
    }
}

/// Who runs jobs: a named non-root account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
    /// Switch to `uid`/`gid` (the agent runs as root); otherwise the agent
    /// already is that user.
    pub switch: bool,
}

pub fn resolve_user(name: &str) -> Result<RunAs, String> {
    let c_name = std::ffi::CString::new(name).map_err(|_| "invalid user name")?;
    // SAFETY: getpwnam returns a pointer into static storage or null; it is
    // read immediately on this thread.
    let entry = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if entry.is_null() {
        return Err(format!("remote jobs user {name} does not exist"));
    }
    // SAFETY: non-null result of getpwnam.
    let (uid, gid) = unsafe { ((*entry).pw_uid, (*entry).pw_gid) };
    if uid == 0 {
        return Err("remote jobs must not run as root; name an unprivileged user".into());
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 && euid != uid {
        return Err(format!(
            "the agent cannot switch to {name}; run it as root or as that user"
        ));
    }
    Ok(RunAs {
        uid,
        gid,
        switch: euid == 0,
    })
}

fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: signals the process group the child leads; harmless if gone.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

fn finish_output(mut bytes: Vec<u8>, cap: usize) -> (String, bool) {
    let mut truncated = false;
    if bytes.len() > cap {
        bytes.truncate(cap);
        truncated = true;
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    while text.len() > cap {
        text.pop();
        truncated = true;
    }
    (text, truncated)
}

/// Runs exactly `argv` (no shell) with an empty environment, stdin closed,
/// in its own process group. The timeout, output cap and cancel each kill
/// the whole group.
pub async fn execute(
    argv: &[String],
    timeout: Duration,
    output_cap: usize,
    run_as: Option<RunAs>,
    mut cancel: watch::Receiver<bool>,
) -> Outcome {
    let mut command = tokio::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    if let Some(run_as) = run_as.filter(|run_as| run_as.switch) {
        command.uid(run_as.uid).gid(run_as.gid);
        // SAFETY: setgroups is async-signal-safe; it drops the agent's
        // supplementary groups in the child before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Outcome {
                status: "error",
                exit_code: None,
                output: finish_output(format!("could not start: {error}").into_bytes(), output_cap)
                    .0,
                output_truncated: false,
            }
        }
    };
    let pid = child.id();
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut output = Vec::new();
    let mut out_buf = [0u8; 4096];
    let mut err_buf = [0u8; 4096];
    let (mut out_open, mut err_open) = (true, true);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let stopped: Option<&'static str> = loop {
        tokio::select! {
            read = stdout.read(&mut out_buf), if out_open => match read {
                Ok(0) | Err(_) => out_open = false,
                Ok(n) => output.extend_from_slice(&out_buf[..n]),
            },
            read = stderr.read(&mut err_buf), if err_open => match read {
                Ok(0) | Err(_) => err_open = false,
                Ok(n) => output.extend_from_slice(&err_buf[..n]),
            },
            _ = &mut deadline => break Some("timed_out"),
            changed = cancel.changed() => {
                if changed.is_ok() && *cancel.borrow() {
                    break Some("cancelled");
                }
            }
            status = child.wait(), if !out_open && !err_open => {
                let (output, output_truncated) = finish_output(output, output_cap);
                return match status {
                    Ok(status) if status.success() => Outcome {
                        status: "succeeded",
                        exit_code: Some(0),
                        output,
                        output_truncated,
                    },
                    Ok(status) => Outcome {
                        status: "failed",
                        exit_code: status.code().map(i64::from),
                        output,
                        output_truncated,
                    },
                    Err(_) => Outcome {
                        status: "error",
                        exit_code: None,
                        output,
                        output_truncated,
                    },
                };
            }
        }
        if output.len() > output_cap {
            break Some("output_capped");
        }
    };
    kill_group(pid);
    let _ = child.wait().await;
    let (output, _) = finish_output(output, output_cap);
    Outcome {
        status: stopped.unwrap_or("error"),
        exit_code: None,
        output,
        output_truncated: stopped == Some("output_capped"),
    }
}

/// Polls the coordinator for approved jobs until the process exits.
pub async fn job_loop(coordinator: Coordinator, state_dir: PathBuf, run_as: RunAs, poll: Duration) {
    loop {
        if let Err(error) = poll_once(&coordinator, &state_dir, run_as).await {
            tracing::warn!(%error, "remote jobs poll failed");
        }
        tokio::time::sleep(poll).await;
    }
}

async fn poll_once(
    coordinator: &Coordinator,
    state_dir: &Path,
    run_as: RunAs,
) -> Result<(), Error> {
    let state = read_state(state_dir)?;
    let published = state
        .remote
        .view
        .as_ref()
        .map(|view| view.job_signing_key.clone())
        .unwrap_or_default();
    let pinned = pinned_key(state_dir, &published).map_err(Error::Message)?;
    let jobs: AgentJobs = coordinator
        .client
        .get(format!(
            "{}/v1/nodes/{}/remote-jobs",
            coordinator.base, state.node_id
        ))
        .bearer_auth(&state.node_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    for job in jobs.jobs {
        let now = unix_now();
        let verified = match verify_job(&pinned, state.node_id, &job.payload, &job.signature, now) {
            Ok(verified) if verified.run_id == job.run_id => verified,
            Ok(_) | Err(_) => {
                tracing::warn!(run_id = %job.run_id, "refusing a remote job that does not verify");
                continue;
            }
        };
        run_one(coordinator, &state, verified, run_as).await?;
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

async fn run_one(
    coordinator: &Coordinator,
    state: &NodeState,
    job: SignedJob,
    run_as: RunAs,
) -> Result<(), Error> {
    let base = format!(
        "{}/v1/nodes/{}/remote-jobs/{}",
        coordinator.base, state.node_id, job.run_id
    );
    let claim = coordinator
        .client
        .post(format!("{base}/claim"))
        .bearer_auth(&state.node_token)
        .send()
        .await?;
    if !claim.status().is_success() {
        return Ok(());
    }
    tracing::info!(run_id = %job.run_id, program = %job.argv[0], "running approved remote job");
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let watcher = {
        let client = coordinator.client.clone();
        let url = base.clone();
        let token = state.node_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CANCEL_CHECK).await;
                let cancelled = match client.get(&url).bearer_auth(&token).send().await {
                    Ok(response) => response
                        .json::<JobState>()
                        .await
                        .map(|state| state.cancel)
                        .unwrap_or(false),
                    Err(_) => false,
                };
                if cancelled {
                    let _ = cancel_tx.send(true);
                    return;
                }
            }
        })
    };
    let outcome = execute(
        &job.argv,
        Duration::from_secs(job.timeout_secs as u64),
        job.output_cap_bytes as usize,
        Some(run_as),
        cancel_rx,
    )
    .await;
    watcher.abort();
    tracing::info!(run_id = %job.run_id, status = outcome.status, "remote job finished");
    coordinator
        .client
        .post(format!("{base}/result"))
        .bearer_auth(&state.node_token)
        .json(&outcome)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn current_user() -> RunAs {
        // SAFETY: getuid/getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        RunAs {
            uid,
            gid,
            switch: false,
        }
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn never() -> watch::Receiver<bool> {
        let (sender, receiver) = watch::channel(false);
        std::mem::forget(sender);
        receiver
    }

    #[tokio::test]
    async fn runs_exact_argv_without_a_shell() {
        let outcome = execute(
            &argv(&["/bin/echo", "$(id)", ";", "reboot", "|", "`whoami`"]),
            Duration::from_secs(5),
            1024,
            Some(current_user()),
            never(),
        )
        .await;
        assert_eq!(outcome.status, "succeeded");
        // The shell metacharacters arrive as literal arguments.
        assert_eq!(outcome.output, "$(id) ; reboot | `whoami`\n");
        let failed = execute(
            &argv(&["/bin/ls", "/definitely/not/here"]),
            Duration::from_secs(5),
            1024,
            None,
            never(),
        )
        .await;
        assert_eq!(failed.status, "failed");
        assert!(failed.exit_code.unwrap() != 0);
    }

    #[tokio::test]
    async fn timeout_kills_the_job() {
        let started = std::time::Instant::now();
        let outcome = execute(
            &argv(&["/bin/sleep", "30"]),
            Duration::from_millis(300),
            1024,
            None,
            never(),
        )
        .await;
        assert_eq!(outcome.status, "timed_out");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn output_is_capped_and_the_job_stopped() {
        let outcome = execute(
            &argv(&["/usr/bin/yes", "blaktail"]),
            Duration::from_secs(10),
            100,
            None,
            never(),
        )
        .await;
        assert_eq!(outcome.status, "output_capped");
        assert!(outcome.output_truncated);
        assert_eq!(outcome.output.len(), 100);
    }

    #[tokio::test]
    async fn cancel_stops_a_running_job() {
        let (sender, receiver) = watch::channel(false);
        let started = std::time::Instant::now();
        let job = tokio::spawn(async move {
            execute(
                &argv(&["/bin/sleep", "30"]),
                Duration::from_secs(60),
                1024,
                None,
                receiver,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        sender.send(true).unwrap();
        let outcome = job.await.unwrap();
        assert_eq!(outcome.status, "cancelled");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn only_signed_unexpired_jobs_for_this_node_verify() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        let node = Uuid::from_u128(3);
        let payload = serde_json::json!({
            "run_id": Uuid::from_u128(1),
            "org_id": Uuid::from_u128(2),
            "node_id": node,
            "argv": ["/usr/bin/uptime"],
            "timeout_secs": 30,
            "output_cap_bytes": 1024,
            "expires_at": 1_000,
        })
        .to_string();
        let sign = |payload: &str| {
            STANDARD.encode(
                key.sign(format!("{JOB_SIGNATURE_CONTEXT}{payload}").as_bytes())
                    .to_bytes(),
            )
        };
        let signature = sign(&payload);
        let job = verify_job(&public, node, &payload, &signature, 999).unwrap();
        assert_eq!(job.argv, vec!["/usr/bin/uptime".to_string()]);
        // Tampered argv, another node, expiry and another key all fail.
        let tampered = payload.replace("/usr/bin/uptime", "/sbin/reboot");
        assert!(verify_job(&public, node, &tampered, &signature, 999).is_err());
        assert!(verify_job(&public, Uuid::from_u128(4), &payload, &signature, 999).is_err());
        assert!(verify_job(&public, node, &payload, &signature, 1_000).is_err());
        let other = STANDARD.encode(
            SigningKey::from_bytes(&[6u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        assert!(verify_job(&other, node, &payload, &signature, 999).is_err());
        // A signed payload with an extra field is still refused.
        let extra = payload.replace("\"expires_at\"", "\"shell\":true,\"expires_at\"");
        assert!(verify_job(&public, node, &extra, &sign(&extra), 999).is_err());
    }

    #[test]
    fn job_key_is_pinned_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        assert!(pinned_key(dir.path(), "").is_err());
        assert_eq!(pinned_key(dir.path(), "AAA").unwrap(), "AAA");
        assert_eq!(pinned_key(dir.path(), "AAA").unwrap(), "AAA");
        assert!(pinned_key(dir.path(), "BBB").is_err());
    }

    #[test]
    fn root_is_never_a_job_user() {
        assert!(resolve_user("root").is_err());
        assert!(resolve_user("no-such-blaktail-user").is_err());
    }
}
