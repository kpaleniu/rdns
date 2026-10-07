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

/// The dry run names each encrypted listener, a DoH-only one included: the
/// case `rdnsd`'s copy of this line once reported as disabled, and which this
/// daemon reported only as "certificate loads" (`TODO.md` #153).
#[test]
fn the_dry_run_names_a_doh_only_listener() {
    let dir = ScratchDir::new("rdnsr-doh-only");
    let issued =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a certificate");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, issued.cert.pem()).expect("write the certificate");
    std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write the key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }

    let out = rdnsr(&[
        "--check-config",
        "--https-listen",
        "127.0.0.1:8443",
        "--tls-cert",
        &cert.to_string_lossy(),
        "--tls-key",
        &key.to_string_lossy(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let line = stdout(&out);
    assert!(
        line.contains(
            "encrypted transports on 127.0.0.1:8443 (IPv4) /dns-query DoH, certificate loads"
        ),
        "got: {line:?}"
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

/// `--serve-stale-first` answers from the `--serve-stale` window, so without
/// one it is a setting that does nothing, refused before the dry run answers
/// (`CLAUDE.md` §15, `TODO.md` #58). With one it is accepted, and so are the
/// pool's sizes, which clap refused beside anything but `--prefetch` until the
/// pool had a second use.
#[test]
fn serving_stale_first_needs_a_stale_window() {
    for args in [
        &["--check-config", "--serve-stale-first"][..],
        &[
            "--check-config",
            "--serve-stale-first",
            "--serve-stale",
            "3600",
            "--no-cache",
        ],
    ] {
        let out = rdnsr(args);
        assert!(!out.status.success(), "{args:?} passed the dry run");
        assert!(
            stderr(&out).contains("--serve-stale-first"),
            "{args:?}: {}",
            stderr(&out)
        );
    }

    let out = rdnsr(&[
        "--check-config",
        "--serve-stale",
        "3600",
        "--serve-stale-first",
        "--prefetch-workers",
        "2",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let dir = ScratchDir::new("rdnsr-stale-first");
    let config = dir.join("rdnsr.toml");
    std::fs::write(&config, "[resolver]\nserve-stale-first = true\n").expect("write");
    let out = rdnsr(&["--config", &config.to_string_lossy(), "--check-config"]);
    assert!(!out.status.success(), "the file is refused the same way");
    assert!(
        stderr(&out).contains("--serve-stale-first"),
        "{}",
        stderr(&out)
    );
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

/// `rdnsd`'s test of the same name, for the other daemon (`TODO.md` #155).
#[test]
fn a_zero_connection_limit_or_idle_timeout_is_refused_by_name() {
    let dir = ScratchDir::new("zero-connections");
    for (flag, key) in [
        ("--max-connections", "max-connections"),
        ("--connection-idle-timeout", "connection-idle-timeout"),
    ] {
        let out = rdnsr(&["--check-config", flag, "0"]);
        assert!(!out.status.success(), "stdout: {}", stdout(&out));
        assert!(stderr(&out).contains(flag), "got: {}", stderr(&out));

        let config = dir.join("rdnsr.toml");
        std::fs::write(&config, format!("[server]\n{key} = 0\n")).expect("write the config");
        let out = rdnsr(&["--config", &config.to_string_lossy(), "--check-config"]);
        assert!(!out.status.success(), "stdout: {}", stdout(&out));
        assert!(stderr(&out).contains(key), "got: {}", stderr(&out));
    }
}

/// `rdnsd`'s test of the same name, for the other daemon (`TODO.md` #156).
#[test]
fn a_malformed_per_source_exemption_is_refused_by_name() {
    let out = rdnsr(&[
        "--check-config",
        "--max-connections-per-source-exempt",
        "not-an-address",
    ]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("--max-connections-per-source-exempt"),
        "got: {}",
        stderr(&out)
    );

    let dir = ScratchDir::new("per-source-exempt");
    let config = dir.join("rdnsr.toml");
    std::fs::write(
        &config,
        "[server]\nmax-connections-per-source = 0\n\
         max-connections-per-source-exempt = [\"192.0.2.0/24\"]\n",
    )
    .expect("write the config");
    let out = rdnsr(&["--config", &config.to_string_lossy(), "--check-config"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
}

/// Off loopback with no `--allow-query` is an open resolver, refused before
/// the dry run answers and naming the flag that put it there (`TODO.md` #171,
/// `docs/adr/0007`). Every listener counts, the wildcard included.
#[test]
fn an_open_resolver_is_refused_until_the_acl_says_who_may_ask() {
    for args in [
        &["--check-config", "--host", "0.0.0.0"][..],
        &["--check-config", "--host", "::"][..],
        &["--check-config", "--host", "192.0.2.1"][..],
    ] {
        let out = rdnsr(args);
        assert!(!out.status.success(), "{args:?} passed the dry run");
        let message = stderr(&out);
        assert!(message.contains("--host"), "{args:?}: {message}");
        assert!(message.contains("--allow-query"), "{args:?}: {message}");
    }

    let out = rdnsr(&[
        "--check-config",
        "--host",
        "0.0.0.0",
        "--allow-query",
        "192.0.2.0/24",
        "--allow-query",
        "2001:db8::/32",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("query ACL 2 --allow-query rule(s)"),
        "got: {}",
        stdout(&out)
    );
    let out = rdnsr(&["--check-config", "--host", "127.0.0.2"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("query ACL open"),
        "got: {}",
        stdout(&out)
    );
}

/// An encrypted listener off loopback is an open resolver too, though `--host`
/// is the default.
#[test]
fn an_encrypted_listener_off_loopback_needs_the_acl_too() {
    let dir = ScratchDir::new("rdnsr-acl-doh");
    let issued =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a certificate");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, issued.cert.pem()).expect("write the certificate");
    std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write the key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
    let out = rdnsr(&[
        "--check-config",
        "--https-listen",
        "0.0.0.0:8443",
        "--tls-cert",
        &cert.to_string_lossy(),
        "--tls-key",
        &key.to_string_lossy(),
    ]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("--https-listen"), "{}", stderr(&out));
}

/// The ACL runs before a NOTIFY is read, so a primary it does not list would
/// be refused with nothing saying why; that is refused at startup instead,
/// naming the rule.
#[test]
fn a_notify_sender_outside_the_acl_is_refused_at_startup() {
    let dir = ScratchDir::new("rdnsr-acl-notify");
    let feed = dir.join("block.zone");
    std::fs::write(
        &feed,
        "\
$ORIGIN rpz.example.
$TTL 300
@       IN SOA ns.rpz.example. admin.rpz.example. ( 1 3600 600 604800 300 )
@       IN NS  ns.rpz.example.
",
    )
    .expect("write the feed");
    let feed = feed.to_string_lossy();
    let base = [
        "--check-config",
        "--rpz",
        &feed,
        "--allow-query",
        "10.0.0.0/8",
    ];

    let out = rdnsr(&[&base[..], &["--rpz-notify-from", "192.0.2.1"]].concat());
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    let message = stderr(&out);
    assert!(
        message.contains("192.0.2.1/32"),
        "names the rule: {message}"
    );
    assert!(message.contains("--allow-query"), "{message}");

    let out = rdnsr(&[&base[..], &["--rpz-notify-from", "10.1.0.0/16"]].concat());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
}

/// The config file's key reaches the same check as the flag, and the two
/// together are refused as every other pair is (`CLAUDE.md` §15).
#[test]
fn allow_query_in_the_config_file_is_the_flag() {
    let dir = ScratchDir::new("rdnsr-acl-config");
    let config = dir.join("rdnsr.toml");
    std::fs::write(&config, "[server]\nhost = \"0.0.0.0\"\n").expect("write the config");
    let out = rdnsr(&["--config", &config.to_string_lossy(), "--check-config"]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("--allow-query"), "{}", stderr(&out));

    std::fs::write(
        &config,
        "[server]\nhost = \"0.0.0.0\"\nallow-query = [\"10.0.0.0/8\"]\n",
    )
    .expect("write the config");
    let out = rdnsr(&["--config", &config.to_string_lossy(), "--check-config"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let out = rdnsr(&[
        "--config",
        &config.to_string_lossy(),
        "--allow-query",
        "10.0.0.0/8",
        "--check-config",
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--allow-query"), "{}", stderr(&out));
}

/// An entry that would switch nothing off is refused before the dry run
/// answers, naming it and saying why (`TODO.md` #173).
#[test]
fn a_name_that_is_not_an_empty_zone_is_refused_at_startup() {
    for (name, why) in [
        ("localhost.", "special-use"),
        ("127.in-addr.arpa.", "special-use"),
        (
            "1.10.in-addr.arpa.",
            "inside the empty zone 10.in-addr.arpa.",
        ),
        ("example.", "not an empty zone"),
    ] {
        let out = rdnsr(&["--check-config", "--disable-empty-zone", name]);
        assert!(!out.status.success(), "{name} passed the dry run");
        let message = stderr(&out);
        assert!(
            message.contains(name) && message.contains(why),
            "{name}: {message}"
        );
    }
    let out = rdnsr(&[
        "--check-config",
        "--no-empty-zones",
        "--disable-empty-zone",
        "10.in-addr.arpa.",
    ]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("--no-empty-zones"),
        "{}",
        stderr(&out)
    );

    let out = rdnsr(&["--check-config", "--disable-empty-zone", "10.in-addr.arpa."]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("empty zones off: 10.in-addr.arpa."),
        "got: {}",
        stdout(&out)
    );
}

/// The file's two keys reach the same set as the flags, and their pair is
/// refused as the flags' is.
#[test]
fn the_empty_zone_keys_are_the_flags() {
    let dir = ScratchDir::new("rdnsr-empty-zones");
    let config = dir.join("rdnsr.toml");
    for (text, ok, said) in [
        (
            "[resolver]\nempty-zones = false\n",
            true,
            "empty zones all off",
        ),
        (
            "[resolver]\ndisable-empty-zone = [\"168.192.in-addr.arpa.\"]\n",
            true,
            "empty zones off: 168.192.in-addr.arpa.",
        ),
        (
            "[resolver]\nempty-zones = false\ndisable-empty-zone = [\"10.in-addr.arpa.\"]\n",
            false,
            "--no-empty-zones",
        ),
    ] {
        std::fs::write(&config, text).expect("write the config");
        let out = rdnsr(&["--config", &config.to_string_lossy(), "--check-config"]);
        assert_eq!(out.status.success(), ok, "{text}: {}", stderr(&out));
        let shown = if ok { stdout(&out) } else { stderr(&out) };
        assert!(shown.contains(said), "{text}: {shown}");
    }

    let out = rdnsr(&[
        "--config",
        &config.to_string_lossy(),
        "--no-empty-zones",
        "--check-config",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--no-empty-zones"),
        "{}",
        stderr(&out)
    );
}

/// `--nsid` is checked before the dry run answers: empty, bad hex and text
/// that is not ASCII are refused by name, and `0x` hex is the raw octets
/// (`TODO.md` #179).
#[test]
fn a_malformed_nsid_is_refused_and_hex_is_octets() {
    for bad in ["", "0xzz", "0x6", "edge-\u{e9}"] {
        let out = rdnsr(&["--check-config", "--nsid", bad]);
        assert!(!out.status.success(), "{bad:?} passed the dry run");
        assert!(stderr(&out).contains("--nsid"), "{bad:?}: {}", stderr(&out));
    }
    let out = rdnsr(&["--check-config", "--nsid", "0x6564"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("NSID ed"), "got: {}", stdout(&out));
    let out = rdnsr(&["--check-config"]);
    assert!(stdout(&out).contains("NSID off"), "got: {}", stdout(&out));
}
