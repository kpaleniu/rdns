//! The startup sequence, run as a process (`TODO.md` #90).
//!
//! Everything else in this workspace calls into the process it is already
//! running in. That is right for the answer path — it goes over real sockets —
//! and wrong for `main`, whose ordering *is* the behaviour and whose
//! `--check-config` exists to be believed before a restart. `CLAUDE.md` §4:
//! when a change is about what happens to a process, the test has to involve a
//! process.
//!
//! **The refuting check the row asked for was taken first**, and it came back
//! the other way. Lifting the startup sequence out of `main` into a testable
//! function is possible — there is nothing in it that needs a process — but it
//! is not cheaper: `main` holds **28** top-level bindings before the dry-run
//! exit and about twenty are still live after it, so the lifted function hands
//! back a struct built in one place and destructured in another. That is #83's
//! reload cluster exactly, measured there at 18 items and fields and declined
//! on it. `CARGO_BIN_EXE_rdnsd` needs no container, works on both platforms,
//! and tests the artefact an operator runs.
//!
//! What this does *not* cover, said rather than implied (§18): binding sockets,
//! the drain, and signals. CI's `image` job covers those for `rdnsd` and is the
//! one job no local `cargo` invocation stands in for.

use std::path::Path;
use std::process::{Command, Output};

use rdns::testutil::ScratchDir;

/// One zone that loads, so a dry run has something to be valid about.
const ZONE: &str = "\
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@   IN NS  ns1.example.com.
ns1 IN A   192.0.2.1
";

fn rdnsd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdnsd"))
        .args(args)
        .output()
        .expect("rdnsd runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn zone_in(dir: &ScratchDir, text: &str) -> String {
    let path = dir.join("example.com.zone");
    std::fs::write(&path, text).expect("write the zone");
    path.to_string_lossy().into_owned()
}

/// The dry run's whole job: exit 0, and say what it checked.
///
/// The output is asserted because it is the output. A deploy script reads this
/// line, and a `--check-config` that printed nothing and exited 0 would pass a
/// test that only looked at the status.
#[test]
fn check_config_accepts_a_zone_that_loads() {
    let dir = ScratchDir::new("check-config-ok");
    let zone = zone_in(&dir, ZONE);

    let out = rdnsd(&["--check-config", "--zone-file", &zone]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let line = stdout(&out);
    assert!(
        line.starts_with("configuration is valid: 1 zone(s)"),
        "got: {line:?}"
    );
    assert!(line.contains("0 TSIG key(s)"), "got: {line:?}");
    assert!(line.contains("signing disabled"), "got: {line:?}");
    assert!(
        line.contains("encrypted transports disabled"),
        "got: {line:?}"
    );
}

/// And the case it exists for. A zone that does not parse has to fail the dry
/// run, or the dry run is worth nothing — this is the deploy that would
/// otherwise SIGHUP a typo into a live server.
#[test]
fn check_config_refuses_a_zone_that_does_not_parse() {
    let dir = ScratchDir::new("check-config-bad");
    let zone = zone_in(&dir, "$ORIGIN example.com.\n@ IN SOA not enough fields\n");

    let out = rdnsd(&["--check-config", "--zone-file", &zone]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("example.com.zone"),
        "the message names the file: {}",
        stderr(&out)
    );
}

/// A flag whose *value* is malformed has to fail the dry run, not the start.
///
/// `--dnstap` was parsed inside `serve`'s argument list, which is evaluated
/// below the dry-run exit, so `--check-config` accepted a target the real start
/// refused (`TODO.md` #99). Put the parse back in the argument list and this
/// fails with a zero status and "configuration is valid" on stdout.
#[test]
fn check_config_refuses_a_malformed_dnstap_target() {
    let dir = ScratchDir::new("check-config-dnstap");
    let zone = zone_in(&dir, ZONE);

    let out = rdnsd(&[
        "--check-config",
        "--zone-file",
        &zone,
        "--dnstap",
        "garbage-not-a-scheme",
    ]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("a dnstap target is"),
        "the message says what a target looks like: {}",
        stderr(&out)
    );
}

/// `--quiet` must not be able to take the output away: the flag is about log
/// lines and this is an answer on stdout. The comment in `main` says so; this
/// is the assertion behind it.
#[test]
fn quiet_does_not_silence_the_dry_runs_answer() {
    let dir = ScratchDir::new("check-config-quiet");
    let zone = zone_in(&dir, ZONE);

    let out = rdnsd(&["--check-config", "--quiet", "--zone-file", &zone]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).starts_with("configuration is valid:"),
        "got: {:?}",
        stdout(&out)
    );
}

/// §15's "two sources for one setting is an error". `rdnsd/src/config.rs`
/// already asks clap for the *set* of flags this applies to (#63i); this asks
/// whether the refusal reaches the operator as a non-zero exit and a message
/// naming both, which is a property of the process and not of the parser.
#[test]
fn a_flag_beside_config_is_refused_by_the_process() {
    let dir = ScratchDir::new("conflict");
    let config = dir.join("rdnsd.toml");
    std::fs::write(&config, "[server]\nzone-dir = \"z\"\n").expect("write the config");

    let out = rdnsd(&[
        "--config",
        &config.to_string_lossy(),
        "--port",
        "5353",
        "--check-config",
    ]);
    assert!(!out.status.success());
    let message = stderr(&out);
    assert!(message.contains("--port"), "got: {message}");
    assert!(message.contains("--config"), "got: {message}");
}

/// A mode flag whose prerequisite is checked in code rather than by clap,
/// because `--signing-key-dir` is also an ordinary server setting. Reached
/// before anything binds, which is the ordering this file exists to hold.
#[test]
fn generate_keys_without_a_directory_is_refused() {
    let out = rdnsd(&["--generate-keys", "example.com."]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--signing-key-dir"),
        "got: {}",
        stderr(&out)
    );
}

/// A policy that cannot act is one the operator believes is in force
/// (`CLAUDE.md` §15). Refusing every transfer there will ever be is a startup
/// error, and the dry run has to reach it.
#[test]
fn transfer_tls_only_without_an_encrypted_listener_is_refused() {
    let dir = ScratchDir::new("tls-only");
    let zone = zone_in(&dir, ZONE);

    let out = rdnsd(&[
        "--check-config",
        "--zone-file",
        &zone,
        "--transfer-tls-only",
    ]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("--tls-listen"),
        "the message names what is missing: {}",
        stderr(&out)
    );
}

/// `--version` is what the container image asserts on, and the only check here
/// that the binary was built with its git description rather than a bare
/// `0.1.0`. Kept loose on purpose: a source tree with no `.git` is a legitimate
/// build and reports the bare version.
#[test]
fn the_binary_reports_a_version() {
    let out = rdnsd(&["--version"]);
    assert!(out.status.success());
    assert!(
        stdout(&out).starts_with("rdnsd "),
        "got: {:?}",
        stdout(&out)
    );
}

/// A server with no zone source is refused, and says which flag it wants.
#[test]
fn a_server_with_no_zone_source_says_which_flag_it_wants() {
    let out = rdnsd(&[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--zone-file") && stderr(&out).contains("--zone-dir"),
        "got: {}",
        stderr(&out)
    );
}

/// A bare dry run is refused the same way a bare start is, and says the same
/// thing (`TODO.md` #90).
///
/// It used to demand `--config`: `#[arg(long, requires = "config")]` made
/// `rdnsd --check-config` ask for a TOML file while `--check-config
/// --zone-file x` ran happily, because `--zone-file` conflicts with `--config`
/// so the requirement never fired where it would bite. Inert where it mattered
/// and misleading where it fired. `rdnsr`'s `check_config` had the argument
/// against it written on it and no attribute; `rdnsd` had the attribute and no
/// argument (§7).
#[test]
fn a_bare_dry_run_wants_a_zone_source_not_a_config_file() {
    let out = rdnsd(&["--check-config"]);
    assert!(!out.status.success());
    let message = stderr(&out);
    assert!(
        message.contains("--zone-file") && message.contains("--zone-dir"),
        "got: {message}"
    );
    assert!(
        !message.contains("required arguments were not provided"),
        "clap should not be asking for --config: {message}"
    );
}

/// Sanity on the harness itself: the binary under test is this package's, and
/// the scratch directory is somewhere a test may write.
#[test]
fn the_harness_points_at_the_binary_and_a_writable_directory() {
    let exe = Path::new(env!("CARGO_BIN_EXE_rdnsd"));
    assert!(exe.exists(), "{exe:?} was not built");
    let dir = ScratchDir::new("harness");
    std::fs::write(dir.join("probe"), b"x").expect("the scratch dir is writable");
}
