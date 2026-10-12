//! Windows host integration that is not the tunnel itself: state directory
//! ACLs, the NRPT split-DNS rule, and the stop signal shared by the console
//! (Ctrl+C, Ctrl+Break, window close) and the service control manager.

use crate::Error;
use std::ffi::OsStr;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, LazyLock, Mutex};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_FILE_NOT_FOUND, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, TokenElevation,
    TokenUser, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegQueryInfoKeyW, RegSetValueExW,
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, REG_DWORD, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn win32(code: u32, what: &str) -> Result<(), Error> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Message(format!(
            "{what}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        )))
    }
}

// ---------------------------------------------------------------------------
// State directory and secret file ACLs
// ---------------------------------------------------------------------------

/// Restricts `path` to SYSTEM and Administrators with inheritance from the
/// parent removed: the Windows form of the 0700 state directory and 0600
/// secret files on Linux and macOS. Directories pass full control on to the
/// files created inside them.
///
/// An elevated process (or SYSTEM) also makes Administrators the owner, so a
/// standard user who pre-created the directory keeps no owner rights over it.
/// A process that is not elevated (a developer running tests) cannot do that
/// and would lock itself out, so its own account is added instead; such a
/// process holds no secret worth protecting from itself.
pub fn restrict_path(path: &Path, directory: bool) -> Result<(), Error> {
    let inherit = if directory { "OICI" } else { "" };
    let elevated = process_is_elevated();
    let mut sddl = format!("O:BAD:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)");
    if !elevated {
        if let Some(user) = current_user_sid() {
            sddl.push_str(&format!("(A;{inherit};FA;;;{user})"));
        }
    }
    let descriptor = SecurityDescriptor::from_sddl(&sddl)?;
    let (owner, dacl) = descriptor.owner_and_dacl()?;
    let name = wide(path.as_os_str());
    // The DACL first: an owner may always rewrite it, and the new one grants
    // Administrators the WRITE_OWNER right that changing the owner needs.
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if code == 0 && elevated {
        // Best effort: the DACL above already decides who has access.
        unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
    }
    win32(
        code,
        &format!("could not restrict access to {}", path.display()),
    )
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, Error> {
        let text = wide(sddl);
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || descriptor.is_null() {
            return Err(Error::Message(format!(
                "could not build security descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self(descriptor))
    }

    fn owner_and_dacl(&self) -> Result<(PSID, *const ACL), Error> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted = 0;
        let mut present = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let ok = unsafe {
            GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) != 0
                && GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) != 0
        };
        if !ok || present == 0 {
            return Err(Error::Message("security descriptor has no DACL".into()));
        }
        Ok((owner, dacl))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

struct Token(HANDLE);

impl Token {
    fn current() -> Option<Self> {
        let mut token: HANDLE = std::ptr::null_mut();
        (unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0)
            .then_some(Self(token))
    }

    fn information(&self, class: i32) -> Option<Vec<u8>> {
        let mut needed = 0u32;
        unsafe { GetTokenInformation(self.0, class, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return None;
        }
        // u64 storage keeps the buffer aligned for the token structures.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let ok = unsafe {
            GetTokenInformation(
                self.0,
                class,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        (ok != 0).then(|| {
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), buffer.len() * 8) };
            bytes.to_vec()
        })
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// True for an elevated administrator or a service account such as SYSTEM.
pub fn process_is_elevated() -> bool {
    let Some(token) = Token::current() else {
        return false;
    };
    token
        .information(TokenElevation)
        .filter(|raw| raw.len() >= std::mem::size_of::<TOKEN_ELEVATION>())
        .map(|raw| {
            let elevation: TOKEN_ELEVATION =
                unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };
            elevation.TokenIsElevated != 0
        })
        .unwrap_or(false)
}

fn current_user_sid() -> Option<String> {
    let token = Token::current()?;
    let mut raw = token.information(TokenUser)?;
    let user = raw.as_mut_ptr().cast::<TOKEN_USER>();
    let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW((*user).User.Sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    let value = unsafe {
        let length = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    };
    unsafe { LocalFree(text.cast()) };
    Some(value)
}

// ---------------------------------------------------------------------------
// MagicDNS split routing (Name Resolution Policy Table)
// ---------------------------------------------------------------------------

/// Local NRPT rules: the same location `Add-DnsClientNrptRule` writes when no
/// Group Policy object is named. The DNS client applies changes at once.
const NRPT_LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
/// Group Policy NRPT rules. When any exist Windows ignores the local table.
const NRPT_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
/// NRPT `ConfigOptions` bit: the rule names generic DNS servers.
const NRPT_GENERIC_DNS_SERVERS: u32 = 0x8;

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    fn create(path: &str) -> Result<Self, Error> {
        let name = wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        let code = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                name.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        win32(code, &format!("could not open HKLM\\{path}"))?;
        Ok(Self(key))
    }

    fn set(&self, name: &str, kind: u32, data: &[u8]) -> Result<(), Error> {
        let value = wide(name);
        let code = unsafe {
            RegSetValueExW(
                self.0,
                value.as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            )
        };
        win32(code, &format!("could not write NRPT value {name}"))
    }

    fn set_string(&self, name: &str, value: &str) -> Result<(), Error> {
        self.set(name, REG_SZ, &utf16_bytes(&wide(value)))
    }

    fn set_dword(&self, name: &str, value: u32) -> Result<(), Error> {
        self.set(name, REG_DWORD, &value.to_le_bytes())
    }

    fn set_multi(&self, name: &str, values: &[String]) -> Result<(), Error> {
        let mut units: Vec<u16> = Vec::new();
        for value in values {
            units.extend(OsStr::new(value).encode_wide());
            units.push(0);
        }
        units.push(0);
        self.set(name, REG_MULTI_SZ, &utf16_bytes(&units))
    }
}

fn utf16_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// The NRPT rule name for one BlakTail interface.
pub fn nrpt_rule_name(interface: &str) -> String {
    format!("BlakTail-{interface}")
}

/// Sends queries for `suffixes` (and their subdomains) to `server` only, the
/// Windows form of `resolvectl domain <if> ~suffix` and `/etc/resolver`.
pub fn set_nrpt_rule(rule: &str, suffixes: &[String], server: IpAddr) -> Result<(), Error> {
    let namespaces: Vec<String> = suffixes
        .iter()
        .map(|suffix| format!(".{}", suffix.trim_start_matches('.')))
        .collect();
    let key = Key::create(&format!(r"{NRPT_LOCAL}\{rule}"))?;
    key.set_dword("Version", 2)?;
    key.set_multi("Name", &namespaces)?;
    key.set_string("GenericDNSServers", &server.to_string())?;
    key.set_dword("ConfigOptions", NRPT_GENERIC_DNS_SERVERS)?;
    key.set_string("IPSECCARestriction", "")?;
    key.set_string("Comment", "Managed by blaktaild")?;
    if group_policy_nrpt_present() {
        tracing::warn!(
            "Group Policy NRPT rules exist on this machine; Windows ignores local rules, so MagicDNS names may not resolve until the BlakTail rule is added to that policy"
        );
    }
    Ok(())
}

/// Removes the rule `set_nrpt_rule` wrote. A missing rule is not an error.
pub fn remove_nrpt_rule(rule: &str) -> Result<(), Error> {
    let base = Key::create(NRPT_LOCAL)?;
    let name = wide(rule);
    let code = unsafe { RegDeleteTreeW(base.0, name.as_ptr()) };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    win32(code, &format!("could not remove NRPT rule {rule}"))
}

fn group_policy_nrpt_present() -> bool {
    let name = wide(NRPT_POLICY);
    let mut key: HKEY = std::ptr::null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, name.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
        return false;
    }
    let key = Key(key);
    let mut subkeys = 0u32;
    let code = unsafe {
        RegQueryInfoKeyW(
            key.0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut subkeys,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    code == 0 && subkeys > 0
}

// ---------------------------------------------------------------------------
// Stop signal: console control events and the service control manager
// ---------------------------------------------------------------------------

static STOP: LazyLock<tokio::sync::watch::Sender<bool>> =
    LazyLock::new(|| tokio::sync::watch::channel(false).0);
static ARMED: AtomicBool = AtomicBool::new(false);
static TEARDOWN: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
/// Windows ends a console process about five seconds after a close, logoff
/// or shutdown event; teardown must finish inside that.
const CLOSE_GRACE: Duration = Duration::from_millis(4_500);

/// Asks the running agent to tear the tunnel down and exit.
pub fn request_stop() {
    STOP.send_replace(true);
}

/// Completes once `request_stop` has been called (immediately if it was).
pub async fn stop_requested() {
    let mut receiver = STOP.subscribe();
    let _ = receiver.wait_for(|stopping| *stopping).await;
}

/// Routes Ctrl+C, Ctrl+Break and console close/logoff/shutdown to
/// `request_stop` once `arm_console_stop` has been called. Before that (for
/// example while waiting for browser enrolment) they keep their default
/// effect of ending the process, as there is nothing to tear down yet.
pub fn install_console_handler() {
    unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) };
}

/// Called once the tunnel exists and the agent is about to sync peers.
pub fn arm_console_stop() {
    ARMED.store(true, Ordering::SeqCst);
}

/// Called after teardown so a pending close event lets the process end.
pub fn teardown_complete() {
    let (done, signal) = &TEARDOWN;
    if let Ok(mut done) = done.lock() {
        *done = true;
        signal.notify_all();
    }
}

unsafe extern "system" fn console_handler(event: u32) -> windows_sys::core::BOOL {
    if !ARMED.load(Ordering::SeqCst) {
        return 0;
    }
    match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            // A second Ctrl+C while teardown is under way ends the process.
            if *STOP.borrow() {
                return 0;
            }
            request_stop();
            1
        }
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            request_stop();
            // Returning lets Windows end the process, so wait for teardown.
            let (done, signal) = &TEARDOWN;
            if let Ok(guard) = done.lock() {
                let _ = signal.wait_timeout_while(guard, CLOSE_GRACE, |done| !*done);
            }
            1
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
    };

    fn dacl_sddl(path: &Path) -> String {
        let name = wide(path.as_os_str());
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let code = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(code, 0);
        let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        let value = unsafe {
            let length = (0..).take_while(|&i| *text.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
        };
        unsafe {
            LocalFree(text.cast());
            LocalFree(descriptor);
        }
        value
    }

    #[test]
    fn state_directory_and_files_lose_inherited_access() {
        let dir = std::env::temp_dir().join(format!("blaktail-acl-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::prepare_state_dir(&dir).unwrap();
        let (key, _) = crate::ensure_private_key(&dir).unwrap();
        for (path, inherit) in [(dir.as_path(), "OICI"), (key.as_path(), "")] {
            let sddl = dacl_sddl(path);
            // Protected: nothing inherited from the temp directory.
            assert!(sddl.starts_with("D:P"), "{sddl}");
            assert!(sddl.contains(&format!("(A;{inherit};FA;;;SY)")), "{sddl}");
            assert!(sddl.contains(&format!("(A;{inherit};FA;;;BA)")), "{sddl}");
            // Users, Authenticated Users and Everyone have no entry.
            for broad in [";BU)", ";AU)", ";WD)"] {
                assert!(!sddl.contains(broad), "{sddl}");
            }
            if process_is_elevated() {
                assert_eq!(sddl.matches("(A;").count(), 2, "{sddl}");
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
