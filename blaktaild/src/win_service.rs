//! `blaktaild run --service`: the Windows Service Control Manager entry point.
//!
//! The SCM starts the process, which hands its main thread to the service
//! dispatcher. The agent reports StartPending until the tunnel is up, then
//! Running. Stop and Preshutdown request the same clean teardown as Ctrl+C
//! in a console (MagicDNS rule, routes, addresses, adapter), after which the
//! service reports Stopped with exit code 0, or a service-specific code 1
//! when the agent failed. Logs go to `blaktaild.log` in the state directory.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing::{error, info};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
};

/// The agent body run on the service thread; `Err` carries the message to log.
pub type ServiceBody = Box<dyn FnOnce() -> Result<(), String> + Send>;

struct Launch {
    name: String,
    body: ServiceBody,
}

static LAUNCH: Mutex<Option<Launch>> = Mutex::new(None);
static STATUS: OnceLock<service_control_handler::ServiceStatusHandle> = OnceLock::new();

const START_WAIT: Duration = Duration::from_secs(60);
const STOP_WAIT: Duration = Duration::from_secs(30);

define_windows_service!(ffi_service_main, service_main);

/// Runs `body` as the service `name`. Returns once the service has stopped.
/// Fails when the process was not started by the SCM (run it from a console
/// without `--service` instead).
pub fn run(name: &str, body: ServiceBody) -> Result<(), String> {
    *LAUNCH.lock().map_err(|_| "service launch lock poisoned")? = Some(Launch {
        name: name.to_owned(),
        body,
    });
    service_dispatcher::start(name, ffi_service_main).map_err(|error| {
        format!(
            "could not connect to the Service Control Manager ({error}); --service is for the installed service, use `blaktaild run` in a console"
        )
    })
}

fn report(state: ServiceState, exit: ServiceExitCode, wait: Duration) {
    let Some(handle) = STATUS.get() else {
        return;
    };
    let controls_accepted = if state == ServiceState::Running {
        ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN
    } else {
        ServiceControlAccept::empty()
    };
    let pending = matches!(
        state,
        ServiceState::StartPending | ServiceState::StopPending
    );
    let _ = handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted,
        exit_code: exit,
        checkpoint: u32::from(pending),
        wait_hint: if pending { wait } else { Duration::ZERO },
        process_id: None,
    });
}

/// Writes `message` to the Windows Application event log (source BlakTail),
/// for failures that happen before the log file is usable.
pub fn report_to_event_log(message: &str) {
    let source: Vec<u16> = "BlakTail"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let text: Vec<u16> = format!("blaktaild: {message}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let handle = RegisterEventSourceW(std::ptr::null(), source.as_ptr());
        if handle.is_null() {
            return;
        }
        let strings = [text.as_ptr()];
        ReportEventW(
            handle,
            EVENTLOG_ERROR_TYPE,
            0,
            1,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        );
        DeregisterEventSource(handle);
    }
}

/// Tells the SCM the tunnel is up. Does nothing outside service mode.
pub fn report_running() {
    if STATUS.get().is_some() {
        report(
            ServiceState::Running,
            ServiceExitCode::Win32(0),
            Duration::ZERO,
        );
        info!("service running");
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let Some(launch) = LAUNCH.lock().ok().and_then(|mut launch| launch.take()) else {
        return;
    };
    let handler = |control| match control {
        ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
            info!(?control, "service stop requested");
            report(
                ServiceState::StopPending,
                ServiceExitCode::Win32(0),
                STOP_WAIT,
            );
            crate::win_host::request_stop();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = match service_control_handler::register(&launch.name, handler) {
        Ok(handle) => handle,
        Err(error) => {
            error!(%error, "could not register the service control handler");
            return;
        }
    };
    let _ = STATUS.set(handle);
    report(
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
        START_WAIT,
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(launch.body));
    let exit = match outcome {
        Ok(Ok(())) => {
            info!("service stopped");
            ServiceExitCode::Win32(0)
        }
        Ok(Err(message)) => {
            error!(error = %message, "service stopped after an error");
            report_to_event_log(&message);
            ServiceExitCode::ServiceSpecific(1)
        }
        Err(_) => {
            error!("service stopped after a panic");
            ServiceExitCode::ServiceSpecific(2)
        }
    };
    report(ServiceState::Stopped, exit, Duration::ZERO);
}

// ---------------------------------------------------------------------------
// Log file
// ---------------------------------------------------------------------------

/// Largest log before it is moved to `blaktaild.log.1` (the one before that
/// is discarded), so the service never fills the disk.
const LOG_LIMIT: u64 = 16 * 1024 * 1024;

/// `blaktaild.log` in the state directory, which carries the directory's
/// SYSTEM and Administrators only access.
pub fn log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("blaktaild.log")
}

/// A size-capped append-only log file shared by every tracing writer.
#[derive(Clone)]
pub struct LogFile(Arc<Mutex<(File, u64, PathBuf)>>);

impl LogFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        // A log left with other access (copied in, or edited by hand) is
        // brought back to the state directory's SYSTEM and Administrators.
        if path.exists() {
            let _ = crate::win_host::restrict_path(path, false);
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        let mut state = (file, size, path.to_path_buf());
        if size >= LOG_LIMIT {
            rotate(&mut state);
        }
        Ok(Self(Arc::new(Mutex::new(state))))
    }
}

/// Moves the full log aside. Files opened by Rust allow rename while open,
/// so this works without closing the current handle first.
fn rotate(state: &mut (File, u64, PathBuf)) {
    let path = state.2.clone();
    let previous = path.with_extension("log.1");
    let _ = fs::remove_file(&previous);
    if fs::rename(&path, &previous).is_ok() {
        if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
            state.0 = file;
            state.1 = 0;
        }
    }
}

impl Write for LogFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))?;
        guard.0.write_all(bytes)?;
        guard.1 += bytes.len() as u64;
        if guard.1 >= LOG_LIMIT {
            rotate(&mut guard);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))?
            .0
            .flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogFile {
    type Writer = LogFile;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
