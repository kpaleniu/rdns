//! Running under the Windows service control manager (`--service NAME`,
//! `TODO.md` #190).
//!
//! The SCM starts the process and waits up to 30 seconds for it to call
//! `StartServiceCtrlDispatcher`; outside the SCM that call fails. So
//! `--service` is asked for, never detected, and a console run makes no
//! attempt. `windows-service` holds the `unsafe`.
//!
//! - STOP and PRESHUTDOWN start the graceful stop the console events start
//!   ([`rdns::shutdown::service_stop`]), reported as STOP_PENDING with a wait
//!   hint covering the drain.
//! - PARAMCHANGE is the reload SIGHUP is on Unix
//!   ([`rdns::shutdown::service_reload`]).
//! - The daemon's exit code becomes the service's, so a failed start shows
//!   as one in the SCM.

use std::ffi::OsString;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

/// The daemon, run once the dispatcher has called back. Returns its exit code.
type Body = Box<dyn FnOnce() -> u32 + Send>;

static BODY: Mutex<Option<Body>> = Mutex::new(None);
static NAME: OnceLock<String> = OnceLock::new();

/// How long a stop may take before the SCM gives up on it: the drain budget,
/// and slack for the tasks to wind down around it.
const STOP_WAIT_HINT: Duration = Duration::from_secs(15);

define_windows_service!(ffi_service_main, service_main);

/// Run `body` as service `name`. Returns once the SCM has been told the
/// service stopped; an error is a process the SCM did not start.
pub fn run(name: &str, body: impl FnOnce() -> u32 + Send + 'static) -> std::io::Result<()> {
    let _ = NAME.set(name.to_string());
    *BODY.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(body));
    service_dispatcher::start(name, ffi_service_main).map_err(std::io::Error::other)
}

fn status(state: ServiceState, accept: ServiceControlAccept, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: if exit == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(exit)
        },
        checkpoint: 0,
        wait_hint: match state {
            ServiceState::StopPending => STOP_WAIT_HINT,
            _ => Duration::ZERO,
        },
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let name = NAME.get().cloned().unwrap_or_default();
    // The handler runs on the SCM's thread and needs the handle that
    // registering it returns, so it reads it from here.
    let handle: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let in_handler = handle.clone();
    let registered = service_control_handler::register(&name, move |control| match control {
        ServiceControl::Stop | ServiceControl::Preshutdown => {
            if let Some(handle) = in_handler.get() {
                let _ = handle.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    0,
                ));
            }
            rdns::shutdown::service_stop();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::ParamChange => {
            rdns::shutdown::service_reload();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    });
    let Ok(registered) = registered else {
        // Nothing to report to: without a handle the SCM sees a service that
        // never started, which is what it is.
        return;
    };
    let _ = handle.set(registered);
    let _ = registered.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP
            | ServiceControlAccept::PRESHUTDOWN
            | ServiceControlAccept::PARAM_CHANGE,
        0,
    ));
    let body = BODY.lock().unwrap_or_else(PoisonError::into_inner).take();
    let code = body.map_or(1, |body| body());
    let _ = registered.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        code,
    ));
}
