//! A daemon's `main`: the runtime, and the service dispatcher when
//! `--service` names one (`TODO.md` #190). Shared so the two daemons start,
//! fail and exit the same way.

use std::future::Future;
use std::process::ExitCode;

/// Run `serve` on a multi-threaded runtime, as the Windows service `service`
/// when one is named, else as a console process.
///
/// A failure is printed as `main` returning `Err` prints it, and also logged to
/// a log file, since a service's standard error goes nowhere.
pub fn run<F>(service: Option<&str>, serve: impl FnOnce() -> F + Send + 'static) -> ExitCode
where
    F: Future<Output = anyhow::Result<()>>,
{
    #[cfg(windows)]
    if let Some(name) = service {
        return match crate::service::run(name, move || code(block(serve))) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!(
                    "Error: --service {name}: {e}; a service is started by the service \
                     control manager (sc.exe start {name})"
                );
                ExitCode::FAILURE
            }
        };
    }
    let _ = service;
    match code(block(serve)) {
        0 => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn block<F>(serve: impl FnOnce() -> F) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    // What `#[tokio::main]` builds.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

fn code(result: anyhow::Result<()>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            if crate::logging::to_file() {
                tracing::error!("{e:#}");
            }
            // `{e:?}`, as `main` returning `Err` printed it: the whole chain.
            eprintln!("Error: {e:?}");
            1
        }
    }
}
