//! The `[server]` keys both daemons have, written once.
//!
//! `rdnsd`'s `[server]` table holds 34 keys and 22 of them name a setting
//! `rdnsr` has as a flag under the same name (`TODO.md` #63b). Two parsers for
//! one setting is how `[zones."x"].also-notify` came to be parsed into a field
//! nothing read (#46c), so the shared half is written here.
//!
//! **A macro and not a shared struct**, because the struct was built and
//! measured (#63h): flattening one into each daemon's `[server]` costs the
//! error message its line number and its expected-key list — for `rdnsd`'s
//! existing file as much as for the new one — and puts `serde` in this crate,
//! where nothing reads a file. These fields expand in the daemon's own module,
//! so they are ordinary fields of an ordinary struct and serde reports a typo
//! exactly as it does today.
//!
//! The contract is that the calling crate's root defines the `default_*`
//! functions named below, which both daemons already do (#63e). A crate that
//! does not gets a compile error naming the missing one.

/// Declare a `[server]` table: the 22 shared keys, then this daemon's own.
///
/// ```ignore
/// rdns::server_table! {
///     #[derive(Debug, Deserialize)]
///     #[serde(deny_unknown_fields, rename_all = "kebab-case")]
///     struct Server {
///         zone_dir: Option<String>,
///     }
///     defaults {
///         zone_dir: None,
///     }
/// }
/// ```
///
/// The `defaults` block is this daemon's own fields only — the shared ones are
/// filled from the crate root's `default_*` functions, so the file and the flag
/// cannot take different numbers (§15, and #63e is what happens when they can).
// `crate::` here is the *calling* crate's root, which is the contract this
// macro exists to state: each daemon's own `default_*` functions, so a flag and
// a key cannot take different numbers (#63e). `$crate` would name `rdns`, where
// none of them lives. Clippy warns because that is usually the bug rather than
// the intent.
#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! server_table {
    (
        $(#[$meta:meta])*
        struct $name:ident {
            $($own:tt)*
        }
        defaults {
            $($own_default:tt)*
        }
    ) => {
        $(#[$meta])*
        struct $name {
            #[serde(default = "crate::default_host")]
            host: String,
            #[serde(default = "crate::default_port")]
            port: u16,
            /// Response bytes per second, per client address; 0 is off.
            #[serde(default = "crate::default_response_rate")]
            response_rate: u32,
            /// Queries per second, per client address; 0 is off.
            #[serde(default = "crate::default_query_rate")]
            query_rate: u32,
            #[serde(default = "crate::default_query_burst")]
            query_burst: u32,
            #[serde(default)]
            query_rate_exempt: Vec<String>,
            /// Largest request accepted, per transport, in octets. The UDP one
            /// is floored at the advertised payload size.
            #[serde(default = "crate::default_max_udp_request")]
            max_udp_request: u16,
            #[serde(default = "crate::default_max_tcp_request")]
            max_tcp_request: u16,
            /// What every reply's OPT advertises this host can reassemble, and
            /// the largest UDP reply it will send. Both floored at 512 — see
            /// `rdns::UdpSizes`.
            #[serde(default = "crate::default_udp_payload_size")]
            udp_payload_size: u16,
            #[serde(default = "crate::default_max_udp_response")]
            max_udp_response: u16,
            /// How often the anomaly warnings run, in seconds; 0 is off. The
            /// four thresholds below are per interval.
            #[serde(default = "crate::default_anomaly_interval")]
            anomaly_interval: u64,
            #[serde(default = "crate::default_anomaly_query_rate")]
            anomaly_query_rate: f64,
            #[serde(default = "crate::default_anomaly_error_percent")]
            anomaly_error_percent: f64,
            #[serde(default = "crate::default_anomaly_source_queries")]
            anomaly_source_queries: u64,
            #[serde(default = "crate::default_anomaly_source_refusals")]
            anomaly_source_refusals: u64,
            /// Prometheus and the liveness probe.
            metrics_listen: Option<String>,
            /// Where to answer DNS over TLS (RFC 7858), QUIC (RFC 9250) and
            /// HTTPS (RFC 8484), and with what. A listener with no certificate
            /// is refused — in code, because a config file has no equivalent of
            /// clap's `requires` and "either listener needs the pair" is not an
            /// `or` `requires` can express.
            ///
            /// ~~By each daemon's `check`.~~ `rdnsr`'s, yes; `rdnsd` refuses it
            /// in `main`, where the flags and the file have already been merged
            /// into one `Cli` and the certificate is about to be loaded
            /// (`TODO.md` #79f). One check over both sources rather than two,
            /// at the cost of a file error without a line number —
            /// `--check-config` still reaches it.
            tls_listen: Option<String>,
            quic_listen: Option<String>,
            https_listen: Option<String>,
            https_path: Option<String>,
            tls_cert: Option<std::path::PathBuf>,
            tls_key: Option<std::path::PathBuf>,
            $($own)*
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    host: crate::default_host(),
                    port: crate::default_port(),
                    response_rate: crate::default_response_rate(),
                    query_rate: crate::default_query_rate(),
                    query_burst: crate::default_query_burst(),
                    query_rate_exempt: Vec::new(),
                    max_udp_request: crate::default_max_udp_request(),
                    max_tcp_request: crate::default_max_tcp_request(),
                    udp_payload_size: crate::default_udp_payload_size(),
                    max_udp_response: crate::default_max_udp_response(),
                    anomaly_interval: crate::default_anomaly_interval(),
                    anomaly_query_rate: crate::default_anomaly_query_rate(),
                    anomaly_error_percent: crate::default_anomaly_error_percent(),
                    anomaly_source_queries: crate::default_anomaly_source_queries(),
                    anomaly_source_refusals: crate::default_anomaly_source_refusals(),
                    metrics_listen: None,
                    tls_listen: None,
                    quic_listen: None,
                    https_listen: None,
                    https_path: None,
                    tls_cert: None,
                    tls_key: None,
                    $($own_default)*
                }
            }
        }
    };
}
