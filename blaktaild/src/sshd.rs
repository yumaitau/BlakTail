//! Opt-in sshd integration for per-user SSH policy (draft 07).
//!
//! When `BLAKTAIL_SSHD_DROPIN` names a file that sshd includes, the agent
//! writes its `Match Address` blocks there, then:
//! 1. `sshd -t` must accept the whole configuration;
//! 2. `sshd -T -C` must show the expected `allowusers`/`denyusers` for each
//!    limited source address, and none of them for an unrelated address;
//! 3. a running sshd must accept a reload.
//!
//! Any failure restores the previous file and reports the limits as not
//! enforced, so the agent and coordinator keep TCP 22 closed to user-limited
//! sources. The agent never edits `sshd_config` itself.
//!
//! Browser remote access (draft 13) is a second opt-in: when
//! `BLAKTAIL_SSH_USER_CA` also names a file, the agent writes the
//! organisation's SSH user CA there and trusts it only inside a
//! `Match Address` block for the gateway's overlay addresses. The principal
//! mapping is sshd's built-in one, used only when no `AuthorizedPrincipalsFile`
//! or command is configured (verified below): a certificate logs in only as a
//! login name it lists, and the coordinator lists exactly one approved OS
//! user per session certificate.

use crate::{acl_filter, Error, Peer};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

pub const DROPIN_ENV: &str = "BLAKTAIL_SSHD_DROPIN";
pub const USER_CA_ENV: &str = "BLAKTAIL_SSH_USER_CA";
pub const PID_FILE: &str = "/run/sshd.pid";
/// TEST-NET-1: never an overlay peer, so its effective config must not
/// carry BlakTail's per-source limits.
const UNRELATED_ADDRESS: &str = "192.0.2.1";

pub trait Runner {
    /// Runs a program; `None` when it could not be started.
    fn run(&mut self, program: &str, args: &[&str]) -> Option<(bool, String)>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Option<(bool, String)> {
        let output = Command::new(program).args(args).output().ok()?;
        Some((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }
}

/// The configured drop-in path. Only Linux agents manage sshd.
pub fn configured_dropin() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    std::env::var_os(DROPIN_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Where to write the organisation's SSH user CA. Needs the drop-in too.
pub fn configured_user_ca() -> Option<PathBuf> {
    configured_dropin()?;
    std::env::var_os(USER_CA_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The organisation SSH user CA, trusted only from the gateway addresses.
pub struct RemoteCa<'a> {
    pub path: &'a Path,
    pub public_key: &'a str,
    pub gateways: &'a [String],
}

impl RemoteCa<'_> {
    /// Everything here lands in sshd configuration, so anything that could
    /// add a keyword or a line is refused.
    fn validated(&self) -> Result<(String, Vec<String>), String> {
        let path = self.path.to_str().unwrap_or_default();
        if !self.path.is_absolute()
            || path
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '"')
        {
            return Err(format!(
                "{USER_CA_ENV} must be an absolute path without spaces"
            ));
        }
        let mut parts = self.public_key.split(' ');
        let valid_key = parts.next() == Some("ssh-ed25519")
            && parts.next().is_some_and(|data| {
                data.len() >= 68
                    && data
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
            })
            && parts.next().is_none();
        if !valid_key {
            return Err("coordinator SSH user CA is not a bare ssh-ed25519 key".into());
        }
        let gateways = self
            .gateways
            .iter()
            .map(|address| {
                address
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.to_string())
                    .map_err(|_| "gateway address is not an IP address".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if gateways.is_empty() {
            return Err("no gateway address to trust the SSH user CA from".into());
        }
        Ok((path.to_owned(), gateways))
    }
}

fn remote_ca_config(ca: &RemoteCa<'_>) -> Result<String, String> {
    let (path, gateways) = ca.validated()?;
    let mut out = String::from("# browser remote access: organisation CA, gateway only\n");
    out.push_str(&format!("Match Address {}\n", gateways.join(",")));
    for line in [
        format!("TrustedUserCAKeys {path}"),
        "PasswordAuthentication no".into(),
        "KbdInteractiveAuthentication no".into(),
        "AllowAgentForwarding no".into(),
        "AllowTcpForwarding no".into(),
        "X11Forwarding no".into(),
        "PermitTunnel no".into(),
    ] {
        out.push_str("    ");
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("Match all\n");
    Ok(out)
}

/// Writes and proves the drop-in. Returns whether the remote-access CA is
/// active; a CA problem leaves the CA out but keeps the user policy.
pub fn sync(
    path: &Path,
    peers: &[Peer],
    remote: Option<&RemoteCa<'_>>,
    runner: &mut dyn Runner,
    pid_file: impl AsRef<Path>,
) -> Result<bool, Error> {
    let mut config = acl_filter::sshd_policy_config(peers);
    let mut trusted = None;
    if let Some(ca) = remote {
        match remote_ca_config(ca) {
            Ok(block) => {
                write_ca(ca)?;
                config.push_str(&block);
                trusted = Some(ca);
            }
            Err(reason) => tracing::warn!(%reason, "browser remote access CA not installed"),
        }
    }
    let previous = fs::read(path).ok();
    if previous.as_deref() != Some(config.as_bytes()) {
        write_config(path, config.as_bytes())?;
    }
    let verified = verify(peers, runner).and_then(|()| match trusted {
        Some(ca) => verify_ca(ca, runner),
        None => Ok(()),
    });
    if let Err(reason) = verified {
        restore(path, previous.as_deref())?;
        return Err(Error::Message(reason));
    }
    reload(runner, pid_file.as_ref()).map_err(Error::Message)?;
    Ok(trusted.is_some())
}

fn write_ca(ca: &RemoteCa<'_>) -> Result<(), Error> {
    let line = format!("{}\n", ca.public_key);
    if fs::read(ca.path).ok().as_deref() != Some(line.as_bytes()) {
        write_config(ca.path, line.as_bytes())?;
    }
    Ok(())
}

fn verify_ca(ca: &RemoteCa<'_>, runner: &mut dyn Runner) -> Result<(), String> {
    let (path, gateways) = ca.validated()?;
    let trusted = format!("trustedusercakeys {}", path.to_ascii_lowercase());
    for gateway in &gateways {
        let lines = effective(runner, gateway)?;
        if !lines.contains(&trusted) {
            return Err(format!(
                "sshd does not apply the BlakTail SSH user CA for gateway {gateway}; check that sshd_config includes the drop-in"
            ));
        }
        // Another principals source would map certificates to users by its
        // own rules rather than "principal equals login name".
        let builtin_mapping = lines
            .iter()
            .any(|line| line == "authorizedprincipalsfile none")
            && !lines.iter().any(|line| {
                line.starts_with("authorizedprincipalscommand ")
                    && line != "authorizedprincipalscommand none"
            });
        if !builtin_mapping {
            return Err(
                "sshd sets an AuthorizedPrincipalsFile or command; remove it to use BlakTail session certificates".into(),
            );
        }
    }
    if effective(runner, UNRELATED_ADDRESS)?.contains(&trusted) {
        return Err("the BlakTail SSH user CA leaks outside the gateway Match block".into());
    }
    Ok(())
}

fn write_config(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let tmp = path.with_extension("blaktail-tmp");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn restore(path: &Path, previous: Option<&[u8]>) -> Result<(), Error> {
    match previous {
        Some(bytes) => write_config(path, bytes),
        None => match fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        },
    }
}

fn effective(runner: &mut dyn Runner, address: &str) -> Result<Vec<String>, String> {
    let spec = format!("user=blaktail-probe,host=blaktail-probe,addr={address}");
    match runner.run("sshd", &["-T", "-C", &spec]) {
        Some((true, output)) => Ok(output
            .lines()
            .map(|line| line.trim().to_ascii_lowercase())
            .collect()),
        _ => Err("sshd -T could not evaluate the effective configuration".into()),
    }
}

fn verify(peers: &[Peer], runner: &mut dyn Runner) -> Result<(), String> {
    match runner.run("sshd", &["-t"]) {
        Some((true, _)) => {}
        _ => return Err("sshd -t rejected the configuration with the BlakTail drop-in".into()),
    }
    let mut ours = Vec::new();
    for peer in peers {
        let Some(ingress) = &peer.ingress else {
            continue;
        };
        if !acl_filter::ssh_restricted(ingress) {
            continue;
        }
        let Some(address) = acl_filter::overlay_host_addrs(&peer.allowed_ips)
            .into_iter()
            .next()
        else {
            continue;
        };
        let lines = effective(runner, &address)?;
        let expected = ingress
            .ssh_users
            .iter()
            .filter(|user| *user != "*")
            .map(|user| format!("allowusers {}", user.to_ascii_lowercase()))
            .chain(
                ingress
                    .ssh_deny_users
                    .iter()
                    .map(|user| format!("denyusers {}", user.to_ascii_lowercase())),
            );
        for line in expected {
            if !lines.contains(&line) {
                return Err(format!(
                    "sshd does not apply the BlakTail drop-in for {address}; check that sshd_config includes it"
                ));
            }
            ours.push(line);
        }
    }
    if !ours.is_empty() {
        let unrelated = effective(runner, UNRELATED_ADDRESS)?;
        if ours.iter().any(|line| unrelated.contains(line)) {
            return Err(
                "BlakTail SSH limits leak outside their Match blocks; move the Include to the end of sshd_config"
                    .into(),
            );
        }
    }
    Ok(())
}

fn reload(runner: &mut dyn Runner, pid_file: &Path) -> Result<(), String> {
    for unit in ["ssh.service", "sshd.service"] {
        if matches!(runner.run("systemctl", &["reload", unit]), Some((true, _))) {
            return Ok(());
        }
    }
    if let Ok(pid) = fs::read_to_string(pid_file) {
        let pid = pid.trim();
        if !pid.is_empty()
            && pid.chars().all(|ch| ch.is_ascii_digit())
            && matches!(runner.run("kill", &["-HUP", pid]), Some((true, _)))
        {
            return Ok(());
        }
    }
    // Nothing running means the file applies when sshd starts.
    match runner.run("pgrep", &["-x", "sshd"]) {
        Some((true, _)) => Err("sshd is running but could not be reloaded".into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerIngress;
    use uuid::Uuid;

    /// Fakes sshd: `-T` echoes what the written drop-in would apply.
    struct FakeSshd {
        dropin: PathBuf,
        accept: bool,
        include_applies: bool,
        leaks: bool,
        running: bool,
        principals_file: &'static str,
        calls: Vec<String>,
    }

    impl Runner for FakeSshd {
        fn run(&mut self, program: &str, args: &[&str]) -> Option<(bool, String)> {
            self.calls.push(format!("{program} {}", args.join(" ")));
            match (program, args) {
                ("sshd", ["-t"]) => Some((self.accept, String::new())),
                ("sshd", ["-T", "-C", spec]) => {
                    let text = fs::read_to_string(&self.dropin).unwrap_or_default();
                    let addr = spec.rsplit("addr=").next().unwrap_or_default();
                    let mut out = String::from("port 22\n");
                    out.push_str(&format!(
                        "authorizedprincipalsfile {}\n",
                        self.principals_file
                    ));
                    let mut active = false;
                    for line in text.lines() {
                        if let Some(list) = line.strip_prefix("Match Address ") {
                            active = self.leaks || list.split(',').any(|a| a == addr);
                        } else if line == "Match all" {
                            active = false;
                        } else if active && self.include_applies {
                            let mut words = line.split_whitespace();
                            let key = words.next().unwrap_or_default().to_ascii_lowercase();
                            for user in words {
                                out.push_str(&format!("{key} {user}\n"));
                            }
                        }
                    }
                    Some((true, out))
                }
                ("systemctl", _) => Some((false, String::new())),
                ("pgrep", _) => Some((self.running, String::new())),
                ("kill", _) => Some((true, String::new())),
                _ => None,
            }
        }
    }

    fn limited(users: &[&str]) -> Peer {
        Peer {
            id: Uuid::from_u128(3),
            name: "office".into(),
            wg_public_key: "key".into(),
            endpoint: None,
            allowed_ips: vec!["100.64.0.3/32".into()],
            dns_name: "office.blaktail".into(),
            tags: vec![],
            relay_endpoint: None,
            ingress: Some(PeerIngress {
                tcp: vec!["22".into()],
                ssh_users: users.iter().map(|user| user.to_string()).collect(),
                ..PeerIngress::default()
            }),
        }
    }

    fn fake(dir: &Path) -> FakeSshd {
        FakeSshd {
            dropin: dir.join("60-blaktail.conf"),
            accept: true,
            include_applies: true,
            leaks: false,
            running: false,
            principals_file: "none",
            calls: vec![],
        }
    }

    #[test]
    fn verified_dropin_is_written_and_reported_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut sshd = fake(dir.path());
        let path = sshd.dropin.clone();
        sync(
            &path,
            &[limited(&["deploy"])],
            None,
            &mut sshd,
            dir.path().join("none.pid"),
        )
        .unwrap();
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains("AllowUsers deploy"));
        assert!(sshd
            .calls
            .iter()
            .any(|call| call.contains("addr=192.0.2.1")));
    }

    #[test]
    fn rejected_or_ineffective_dropin_is_restored() {
        let dir = tempfile::tempdir().unwrap();
        let mut sshd = fake(dir.path());
        let path = sshd.dropin.clone();
        fs::write(&path, "# previous\n").unwrap();
        sshd.accept = false;
        assert!(sync(
            &path,
            &[limited(&["deploy"])],
            None,
            &mut sshd,
            dir.path().join("none.pid")
        )
        .is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "# previous\n");

        let mut sshd = fake(dir.path());
        sshd.include_applies = false;
        assert!(sync(
            &path,
            &[limited(&["deploy"])],
            None,
            &mut sshd,
            dir.path().join("none.pid")
        )
        .is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "# previous\n");

        let mut sshd = fake(dir.path());
        sshd.leaks = true;
        let error = sync(
            &path,
            &[limited(&["deploy"])],
            None,
            &mut sshd,
            dir.path().join("none.pid"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("leak"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "# previous\n");

        let fresh = dir.path().join("fresh.conf");
        let mut sshd = fake(dir.path());
        sshd.dropin = fresh.clone();
        sshd.accept = false;
        assert!(sync(
            &fresh,
            &[limited(&["deploy"])],
            None,
            &mut sshd,
            dir.path().join("none.pid")
        )
        .is_err());
        assert!(!fresh.exists());
    }

    #[test]
    fn running_sshd_must_reload() {
        let dir = tempfile::tempdir().unwrap();
        let mut sshd = fake(dir.path());
        let path = sshd.dropin.clone();
        sshd.running = true;
        assert!(sync(
            &path,
            &[limited(&["deploy"])],
            None,
            &mut sshd,
            dir.path().join("none.pid")
        )
        .is_err());
        let pid = dir.path().join("sshd.pid");
        fs::write(&pid, "4242\n").unwrap();
        let mut sshd = fake(dir.path());
        sshd.running = true;
        sync(&path, &[limited(&["deploy"])], None, &mut sshd, &pid).unwrap();
        assert!(sshd.calls.iter().any(|call| call == "kill -HUP 4242"));
    }

    const CA: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOT6Bm5wD3HKNzLD7SKSaVM9ADEFMHGm9pScXfB1IxZ";

    #[test]
    fn remote_ca_is_trusted_only_from_the_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let mut sshd = fake(dir.path());
        let path = sshd.dropin.clone();
        let ca_path = dir.path().join("blaktail_user_ca.pub");
        let gateways = vec!["100.64.0.9".to_string()];
        let ca = RemoteCa {
            path: &ca_path,
            public_key: CA,
            gateways: &gateways,
        };
        let active = sync(
            &path,
            &[limited(&["deploy"])],
            Some(&ca),
            &mut sshd,
            dir.path().join("none.pid"),
        )
        .unwrap();
        assert!(active);
        assert_eq!(fs::read_to_string(&ca_path).unwrap(), format!("{CA}\n"));
        let config = fs::read_to_string(&path).unwrap();
        assert!(config.contains("Match Address 100.64.0.9\n"));
        assert!(config.contains(&format!("TrustedUserCAKeys {}", ca_path.display())));
        assert!(!config.contains("AuthorizedPrincipalsFile"));
        assert!(config.contains("PasswordAuthentication no"));
        assert!(sshd
            .calls
            .iter()
            .any(|call| call.contains("addr=100.64.0.9")));

        // Another principals source would change who a certificate logs in as.
        let mut mapped = fake(dir.path());
        mapped.principals_file = "/etc/ssh/principals/%u";
        let before = fs::read_to_string(&path).unwrap();
        assert!(sync(
            &path,
            &[],
            Some(&ca),
            &mut mapped,
            dir.path().join("none.pid")
        )
        .unwrap_err()
        .to_string()
        .contains("AuthorizedPrincipalsFile"));
        assert_eq!(fs::read_to_string(&path).unwrap(), before);

        // A CA that leaks to every address is refused and the file restored.
        let mut leaky = fake(dir.path());
        leaky.leaks = true;
        let before = fs::read_to_string(&path).unwrap();
        assert!(sync(
            &path,
            &[],
            Some(&ca),
            &mut leaky,
            dir.path().join("none.pid")
        )
        .is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn untrusted_ca_input_never_reaches_sshd_config() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pub");
        let good = vec!["100.64.0.9".to_string()];
        let injected = vec!["100.64.0.9\n    PermitRootLogin yes".to_string()];
        let spaced = PathBuf::from("/etc/ssh/ca file.pub");
        for (path, key, gateways) in [
            (
                ca_path.as_path(),
                "ssh-ed25519 AAAA\nPermitRootLogin yes",
                &good,
            ),
            (
                ca_path.as_path(),
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
                &good,
            ),
            (ca_path.as_path(), CA, &injected),
            (ca_path.as_path(), CA, &vec![]),
            (spaced.as_path(), CA, &good),
            (Path::new("relative.pub"), CA, &good),
        ] {
            let mut sshd = fake(dir.path());
            let dropin = sshd.dropin.clone();
            let ca = RemoteCa {
                path,
                public_key: key,
                gateways,
            };
            let active =
                sync(&dropin, &[], Some(&ca), &mut sshd, dir.path().join("x.pid")).unwrap();
            assert!(!active, "{key:?} {gateways:?} {path:?}");
            let config = fs::read_to_string(&dropin).unwrap_or_default();
            assert!(!config.contains("TrustedUserCAKeys"));
            assert!(!config.contains("PermitRootLogin"));
        }
    }
}
