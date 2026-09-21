//! `rdnsr`'s startup sequence, run as a process (`TODO.md` #90).
//!
//! The reasoning is `rdnsd/tests/startup.rs`'s and is not repeated. What is
//! different here is that a resolver needs no zone source, so the bare dry run
//! is the *valid* case rather than a refusal — `rdnsr` with no flags recurses
//! from the built-in root hints — and `--check-config` has never carried
//! `requires = "config"`, which is the argument #90 removed it from `rdnsd`
//! for.

use std::process::{Command, Output};

use rdns::testutil::ScratchDir;

fn rdnsr(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdnsr"))
        .args(args)
        .output()
        .expect("rdnsr runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The default deployment is valid and says what it will do. A resolver with no
/// configuration at all is a working resolver, which is why this is the case
/// that has to pass rather than the one that has to fail.
#[test]
fn a_bare_dry_run_describes_the_default_resolver() {
    let out = rdnsr(&["--check-config"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let line = stdout(&out);
    assert!(line.starts_with("configuration is valid:"), "got: {line:?}");
    assert!(
        line.contains("root hints"),
        "it says where it resolves from: {line:?}"
    );
    assert!(line.contains("0 policy feed(s)"), "got: {line:?}");
}

/// The half an operator gets wrong: a feed at `passthru` blocks nothing and
/// looks exactly like a working server, so the count of feeds not taken at
/// their word is in the line (`CLAUDE.md` §14).
#[test]
fn the_dry_run_names_a_policy_feed_it_will_not_take_at_its_word() {
    let dir = ScratchDir::new("rdnsr-rpz");
    let feed = dir.join("block.zone");
    std::fs::write(
        &feed,
        "\
$ORIGIN rpz.example.
$TTL 300
@       IN SOA ns.rpz.example. admin.rpz.example. ( 1 3600 600 604800 300 )
@       IN NS  ns.rpz.example.
bad.com IN CNAME .
",
    )
    .expect("write the feed");

    let out = rdnsr(&[
        "--check-config",
        "--rpz",
        &feed.to_string_lossy(),
        "--rpz-policy",
        "passthru",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let line = stdout(&out);
    assert!(line.contains("1 policy feed(s)"), "got: {line:?}");
    assert!(
        line.contains("not taken at their word"),
        "a feed at passthru blocks nothing and the line has to say so: {line:?}"
    );
}

/// A feed that does not parse fails the dry run, and names the file.
#[test]
fn the_dry_run_refuses_a_policy_feed_that_does_not_parse() {
    let dir = ScratchDir::new("rdnsr-rpz-bad");
    let feed = dir.join("broken.zone");
    std::fs::write(&feed, "$ORIGIN rpz.example.\n@ IN SOA not enough\n").expect("write the feed");

    let out = rdnsr(&["--check-config", "--rpz", &feed.to_string_lossy()]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("broken.zone"),
        "the message names the file: {}",
        stderr(&out)
    );
}

/// The same defect as `rdnsd`'s dnstap target, one daemon over and worse.
///
/// `TsigKey::parse` sat two hundred lines below the exit, after both sockets
/// were bound and the anomaly watcher spawned, so a secret that is not base64
/// passed the dry run and killed a started process (`TODO.md` #99). Move the
/// parse back down and this fails with a zero status.
#[test]
fn the_dry_run_refuses_a_tsig_secret_that_is_not_base64() {
    let dir = ScratchDir::new("rdnsr-bad-key");
    let config = dir.join("rdnsr.toml");
    std::fs::write(
        &config,
        "[keys.\"partner.key.\"]
algorithm = \"hmac-sha256\"
secret = \"not!base64!\"
",
    )
    .expect("write the config");

    let out = rdnsr(&["--config", &config.to_string_lossy(), "--check-config"]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("not base64"),
        "the message names the secret: {}",
        stderr(&out)
    );
}

/// §15 again, and #63i's row: `--dnstap-max-bytes` was the one flag of 35 not
/// refused beside `--config`, so the file overwrote it in silence. This asks
/// whether the refusal reaches the operator.
#[test]
fn a_flag_beside_config_is_refused_by_the_process() {
    let dir = ScratchDir::new("rdnsr-conflict");
    let config = dir.join("rdnsr.toml");
    std::fs::write(&config, "[server]\n").expect("write the config");

    let out = rdnsr(&[
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

#[test]
fn the_binary_reports_a_version() {
    let out = rdnsr(&["--version"]);
    assert!(out.status.success());
    assert!(
        stdout(&out).starts_with("rdnsr "),
        "got: {:?}",
        stdout(&out)
    );
}
