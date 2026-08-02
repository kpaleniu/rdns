//! Counters an operator can page on, and the Prometheus text to scrape them.
//!
//! **This module used to be dead** — referenced only by `bench.rs` — while both
//! servers used a second `DnsMetrics` in a `telemetry` module built around an
//! OpenTelemetry OTLP exporter that was never initialised. That module is gone;
//! see `TODO.md` #9d for what it cost and why scraping is the right shape here.
//!
//! The counters are plain relaxed atomics. Relaxed is right: each is
//! independent, nothing branches on one, and a scrape is a snapshot of a moving
//! system either way — ordering between two counters would buy nothing and cost
//! a fence on every query.

use crate::utils::record_types as rt;
use crate::Qtype;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::ResponseCode;

/// Upper bounds, in milliseconds, of the latency histogram's buckets.
///
/// Chosen for what a DNS answer actually costs: an in-memory zone lookup is
/// tens of microseconds, so the interesting resolution is *below* a
/// millisecond, and anything past ten means a lock was contended, a signature
/// was computed, or a disk was touched. A histogram whose first bucket is 5 ms
/// would report every healthy server as identical.
const LATENCY_BUCKETS_MS: [f64; 8] = [0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 25.0, 100.0];

/// Escape a label value for the Prometheus text format: backslash, double quote
/// and newline (the exposition format's §"label value" rules).
///
/// A zone name should contain none of these — but it comes from a file an
/// operator wrote, and RFC 1035 §5.1 allows `\` escapes in one, so "should" is
/// not "cannot". An unescaped quote here would not corrupt one metric, it would
/// make the *rest of the scrape* unparseable.
fn escape_label(value: &str) -> String {
    if !value.contains(['\\', '"', '\n']) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

/// One zone's gauges, named and owned, as [`DnsMetrics::zone_facts`] hands them
/// out.
///
/// A separate type from the internal [`ZoneGauge`] because it carries the zone
/// name: inside the map the name is the key, and a caller reading a snapshot
/// needs the pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFacts {
    pub zone: String,
    pub serial: u32,
    /// `None` for a zone we are primary for, and for a secondary that has never
    /// reached its master. Those are different from each other and from zero,
    /// which is 1970 and would fire every staleness alert there is.
    pub last_transfer: Option<u64>,
}

/// What is currently true of one zone.
#[derive(Debug, Clone, Copy, Default)]
struct ZoneGauge {
    /// The SOA serial being served, which is the one number that says *which
    /// version* of a zone a server has — the thing you compare across a primary
    /// and its secondaries to find the one that is behind.
    serial: u32,
    /// Unix seconds of the last successful *contact with a master*, for a zone
    /// we replicate — which is what EXPIRE counts from, and so what decides
    /// whether the zone is still ours to answer for. A refresh that found
    /// nothing new still counts: the zone is confirmed current, which is exactly
    /// what "not stale" means.
    ///
    /// `None` covers two cases that must not render the same as each other or as
    /// zero: a zone we are primary for, which is never transferred, and a
    /// secondary zone we have not managed to fetch yet. Emitting `0` for either
    /// would read as 1970 and fire every staleness alert there is.
    last_transfer: Option<u64>,
}

/// Prometheus-compatible metrics for DNS server
#[derive(Clone)]
pub struct DnsMetrics {
    // Query counters
    pub queries_received: Arc<AtomicU64>,
    pub queries_authoritative: Arc<AtomicU64>,
    pub queries_recursive: Arc<AtomicU64>,

    // Response counters
    pub responses_sent: Arc<AtomicU64>,
    pub responses_nxdomain: Arc<AtomicU64>,
    pub responses_servfail: Arc<AtomicU64>,
    pub responses_refused: Arc<AtomicU64>,
    pub responses_noerror: Arc<AtomicU64>,

    // Cache metrics
    pub cache_hits: Arc<AtomicU64>,
    pub cache_misses: Arc<AtomicU64>,

    // Security metrics
    pub rate_limited: Arc<AtomicU64>,
    pub validation_errors: Arc<AtomicU64>,
    pub queries_dropped: Arc<AtomicU64>,

    // Answer latency, as cumulative histogram buckets plus a count and a sum —
    // the three things Prometheus needs to compute a quantile.
    latency_buckets: Arc<[AtomicU64; 8]>,
    latency_count: Arc<AtomicU64>,
    /// Microseconds, integer, so the sum needs no float atomic.
    latency_sum_us: Arc<AtomicU64>,

    /// Per-zone facts, updated when they change rather than sampled.
    ///
    /// A gauge over live state, unlike everything else here, and it is written
    /// at the moment the fact changes — a zone installed, a transfer that
    /// succeeded — rather than read out of the zone map at scrape time. That is
    /// deliberate: sampling would need the zone-map lock on the scrape path, so
    /// a scrape could be blocked behind a reload and a reload behind a scrape,
    /// and the number would still only be as fresh as the last scrape.
    ///
    /// Not bounded, and it does not need to be (`CLAUDE.md` §5): the key space
    /// is zone names from the configuration, not anything a client can put on
    /// the wire.
    zones: Arc<RwLock<BTreeMap<String, ZoneGauge>>>,

    // Record type counters
    pub queries_type_a: Arc<AtomicU64>,
    pub queries_type_aaaa: Arc<AtomicU64>,
    pub queries_type_mx: Arc<AtomicU64>,
    pub queries_type_ns: Arc<AtomicU64>,
    pub queries_type_cname: Arc<AtomicU64>,
    pub queries_type_txt: Arc<AtomicU64>,
    pub queries_type_soa: Arc<AtomicU64>,
    pub queries_type_ptr: Arc<AtomicU64>,
    pub queries_type_other: Arc<AtomicU64>,
}

impl DnsMetrics {
    pub fn new() -> Self {
        DnsMetrics {
            queries_received: Arc::new(AtomicU64::new(0)),
            queries_authoritative: Arc::new(AtomicU64::new(0)),
            queries_recursive: Arc::new(AtomicU64::new(0)),
            responses_sent: Arc::new(AtomicU64::new(0)),
            responses_nxdomain: Arc::new(AtomicU64::new(0)),
            responses_servfail: Arc::new(AtomicU64::new(0)),
            responses_refused: Arc::new(AtomicU64::new(0)),
            responses_noerror: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            rate_limited: Arc::new(AtomicU64::new(0)),
            validation_errors: Arc::new(AtomicU64::new(0)),
            queries_dropped: Arc::new(AtomicU64::new(0)),
            zones: Arc::new(RwLock::new(BTreeMap::new())),
            latency_buckets: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            latency_count: Arc::new(AtomicU64::new(0)),
            latency_sum_us: Arc::new(AtomicU64::new(0)),
            queries_type_a: Arc::new(AtomicU64::new(0)),
            queries_type_aaaa: Arc::new(AtomicU64::new(0)),
            queries_type_mx: Arc::new(AtomicU64::new(0)),
            queries_type_ns: Arc::new(AtomicU64::new(0)),
            queries_type_cname: Arc::new(AtomicU64::new(0)),
            queries_type_txt: Arc::new(AtomicU64::new(0)),
            queries_type_soa: Arc::new(AtomicU64::new(0)),
            queries_type_ptr: Arc::new(AtomicU64::new(0)),
            queries_type_other: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Add one to a counter, named so a call site reads as what it counts:
    /// `metrics.count(&metrics.rate_limited)`.
    pub fn count(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one answer by the code it carries.
    ///
    /// The rates of these are what an operator pages on, and they say different
    /// things: REFUSED climbing means a zone went *missing*, SERVFAIL climbing
    /// means one went *wrong*, and NXDOMAIN is ordinary and noisy. Anything else
    /// — NOTIMP, FORMERR, BADVERS — is counted as sent and not broken out,
    /// because a per-rcode counter for all twenty-four would be a lot of
    /// cardinality for codes nobody alerts on.
    pub fn count_response(&self, rcode: ResponseCode) {
        self.count(&self.responses_sent);
        match rcode {
            ResponseCode::Ok => self.count(&self.responses_noerror),
            ResponseCode::NoSuchDomain => self.count(&self.responses_nxdomain),
            ResponseCode::ServerFailure => self.count(&self.responses_servfail),
            ResponseCode::Refused => self.count(&self.responses_refused),
            _ => {}
        }
    }

    /// Record one answer's latency into the histogram.
    ///
    /// Cumulative buckets, which is the shape Prometheus wants: each `le` bucket
    /// counts everything at or below it, so a quantile is computed at query time
    /// rather than being fixed here. Bounds are the ones a DNS answer actually
    /// falls between — an in-memory zone lookup is microseconds, and anything
    /// past ten milliseconds means a lock was contended or a disk was touched.
    pub fn observe_latency_ms(&self, ms: f64) {
        for (bound, bucket) in LATENCY_BUCKETS_MS.iter().zip(self.latency_buckets.iter()) {
            if ms <= *bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        // Microseconds, as an integer, so the sum is exact and needs no float
        // atomic. Converted back on the way out.
        self.latency_sum_us
            .fetch_add((ms * 1000.0) as u64, Ordering::Relaxed);
    }

    /// Record the serial currently served for `zone`.
    ///
    /// Call it wherever a zone is installed — that is the only moment the
    /// answer changes, and it is the moment we already hold the version.
    pub fn set_zone_serial(&self, zone: &str, serial: u32) {
        let Ok(mut zones) = self.zones.write() else {
            // A poisoned lock costs a stale gauge. Refusing to serve DNS over it
            // would be absurd (`CLAUDE.md` §6).
            return;
        };
        zones.entry(zone.to_string()).or_default().serial = serial;
    }

    /// Record that `zone` was in contact with its master at `at` (Unix seconds).
    pub fn note_zone_transfer(&self, zone: &str, at: u64) {
        let Ok(mut zones) = self.zones.write() else {
            return;
        };
        zones.entry(zone.to_string()).or_default().last_transfer = Some(at);
    }

    /// Stop reporting `zone` — it was removed from the configuration, or
    /// withdrawn for EXPIRE.
    ///
    /// Forgetting rather than zeroing, because a gauge that stays at its last
    /// value is how a dashboard shows a zone that is no longer served as
    /// perfectly healthy. An absent series is visible; a frozen one is not.
    pub fn forget_zone(&self, zone: &str) {
        let Ok(mut zones) = self.zones.write() else {
            return;
        };
        zones.remove(zone);
    }

    /// What is currently true of each zone, by name: the serial being served
    /// and the last contact with a master, if it has one.
    ///
    /// Exists so the control channel's `status` reads the *same* facts the
    /// scrape does rather than growing a second view of them (`CLAUDE.md` §7).
    /// It is a snapshot: the lock is taken and released here, so a caller
    /// cannot hold the gauges open across an await or a reload.
    ///
    /// A poisoned lock yields an empty list, for the reason the setters return
    /// early on one — `status` reporting nothing is a great deal better than
    /// `status` panicking, and either way something else has already gone wrong.
    pub fn zone_facts(&self) -> Vec<ZoneFacts> {
        let Ok(zones) = self.zones.read() else {
            return Vec::new();
        };
        zones
            .iter()
            .map(|(zone, gauge)| ZoneFacts {
                zone: zone.clone(),
                serial: gauge.serial,
                last_transfer: gauge.last_transfer,
            })
            .collect()
    }

    /// Replace the whole set, for a reload that installs every zone at once.
    pub fn retain_zones(&self, keep: &[String]) {
        let Ok(mut zones) = self.zones.write() else {
            return;
        };
        zones.retain(|name, _| keep.iter().any(|k| k.eq_ignore_ascii_case(name)));
    }

    /// Track query type.
    ///
    /// A [`Qtype`] rather than a `u16`: this counts what clients *ask* for, so
    /// AXFR, IXFR and ANY are legitimate values here and would be nonsense as
    /// record types. They land in `other`, which is right — the named counters
    /// are the eight types a dashboard breaks out.
    pub fn track_query_type(&self, qtype: Qtype) {
        let counter = if qtype.is(rt::A) {
            &self.queries_type_a
        } else if qtype.is(rt::AAAA) {
            &self.queries_type_aaaa
        } else if qtype.is(rt::MX) {
            &self.queries_type_mx
        } else if qtype.is(rt::NS) {
            &self.queries_type_ns
        } else if qtype.is(rt::CNAME) {
            &self.queries_type_cname
        } else if qtype.is(rt::TXT) {
            &self.queries_type_txt
        } else if qtype.is(rt::SOA) {
            &self.queries_type_soa
        } else if qtype.is(rt::PTR) {
            &self.queries_type_ptr
        } else {
            &self.queries_type_other
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Generate Prometheus format metrics output
    pub fn to_prometheus_format(&self) -> String {
        let mut output = String::new();

        output.push_str("# HELP dns_queries_received_total Total DNS queries received\n");
        output.push_str("# TYPE dns_queries_received_total counter\n");
        output.push_str(&format!(
            "dns_queries_received_total {}\n",
            self.queries_received.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_queries_authoritative_total Authoritative queries handled\n");
        output.push_str("# TYPE dns_queries_authoritative_total counter\n");
        output.push_str(&format!(
            "dns_queries_authoritative_total {}\n",
            self.queries_authoritative.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_queries_recursive_total Recursive queries handled\n");
        output.push_str("# TYPE dns_queries_recursive_total counter\n");
        output.push_str(&format!(
            "dns_queries_recursive_total {}\n",
            self.queries_recursive.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_sent_total Total DNS responses sent\n");
        output.push_str("# TYPE dns_responses_sent_total counter\n");
        output.push_str(&format!(
            "dns_responses_sent_total {}\n",
            self.responses_sent.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_nxdomain_total NXDOMAIN responses\n");
        output.push_str("# TYPE dns_responses_nxdomain_total counter\n");
        output.push_str(&format!(
            "dns_responses_nxdomain_total {}\n",
            self.responses_nxdomain.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_servfail_total SERVFAIL responses\n");
        output.push_str("# TYPE dns_responses_servfail_total counter\n");
        output.push_str(&format!(
            "dns_responses_servfail_total {}\n",
            self.responses_servfail.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_refused_total REFUSED responses\n");
        output.push_str("# TYPE dns_responses_refused_total counter\n");
        output.push_str(&format!(
            "dns_responses_refused_total {}\n",
            self.responses_refused.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_noerror_total NOERROR responses\n");
        output.push_str("# TYPE dns_responses_noerror_total counter\n");
        output.push_str(&format!(
            "dns_responses_noerror_total {}\n",
            self.responses_noerror.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_cache_hits_total Cache hits\n");
        output.push_str("# TYPE dns_cache_hits_total counter\n");
        output.push_str(&format!(
            "dns_cache_hits_total {}\n",
            self.cache_hits.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_cache_misses_total Cache misses\n");
        output.push_str("# TYPE dns_cache_misses_total counter\n");
        output.push_str(&format!(
            "dns_cache_misses_total {}\n",
            self.cache_misses.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_rate_limited_total Rate limited queries\n");
        output.push_str("# TYPE dns_rate_limited_total counter\n");
        output.push_str(&format!(
            "dns_rate_limited_total {}\n",
            self.rate_limited.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_validation_errors_total Validation errors\n");
        output.push_str("# TYPE dns_validation_errors_total counter\n");
        output.push_str(&format!(
            "dns_validation_errors_total {}\n",
            self.validation_errors.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_queries_dropped_total Dropped queries\n");
        output.push_str("# TYPE dns_queries_dropped_total counter\n");
        output.push_str(&format!(
            "dns_queries_dropped_total {}\n",
            self.queries_dropped.load(Ordering::Relaxed)
        ));

        // Record type metrics
        output.push_str("# HELP dns_queries_type Total queries by type\n");
        output.push_str("# TYPE dns_queries_type counter\n");
        output.push_str(&format!(
            "dns_queries_type{{type=\"A\"}} {}\n",
            self.queries_type_a.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"AAAA\"}} {}\n",
            self.queries_type_aaaa.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"MX\"}} {}\n",
            self.queries_type_mx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"NS\"}} {}\n",
            self.queries_type_ns.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"CNAME\"}} {}\n",
            self.queries_type_cname.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"TXT\"}} {}\n",
            self.queries_type_txt.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"SOA\"}} {}\n",
            self.queries_type_soa.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"PTR\"}} {}\n",
            self.queries_type_ptr.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"OTHER\"}} {}\n",
            self.queries_type_other.load(Ordering::Relaxed)
        ));

        // The latency histogram, in the exact shape `histogram_quantile()`
        // wants: cumulative `le` buckets, a `+Inf` bucket equal to the count,
        // then `_sum` and `_count`. Seconds, because Prometheus convention is
        // base units and a dashboard that has to know we chose milliseconds is
        // a dashboard that will get it wrong.
        output.push_str("# HELP dns_answer_latency_seconds Time to build one answer\n");
        output.push_str("# TYPE dns_answer_latency_seconds histogram\n");
        for (bound, bucket) in LATENCY_BUCKETS_MS.iter().zip(self.latency_buckets.iter()) {
            output.push_str(&format!(
                "dns_answer_latency_seconds_bucket{{le=\"{}\"}} {}\n",
                bound / 1000.0,
                bucket.load(Ordering::Relaxed)
            ));
        }
        let count = self.latency_count.load(Ordering::Relaxed);
        output.push_str(&format!(
            "dns_answer_latency_seconds_bucket{{le=\"+Inf\"}} {count}\n"
        ));
        output.push_str(&format!(
            "dns_answer_latency_seconds_sum {}\n",
            self.latency_sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0
        ));
        output.push_str(&format!("dns_answer_latency_seconds_count {count}\n"));

        // The two per-zone gauges, which are the ones an operator asks for by
        // name: "which version am I serving" and "when did this replica last
        // hear from its master".
        if let Ok(zones) = self.zones.read() {
            output.push_str("# HELP dns_zone_serial SOA serial currently served\n");
            output.push_str("# TYPE dns_zone_serial gauge\n");
            for (zone, gauge) in zones.iter() {
                output.push_str(&format!(
                    "dns_zone_serial{{zone=\"{}\"}} {}\n",
                    escape_label(zone),
                    gauge.serial
                ));
            }

            // A **timestamp**, not a "seconds since". Prometheus convention is to
            // expose the instant and let the query do `time() - x`, because a
            // duration computed here is already stale by the time it is scraped
            // and goes on ageing in the dashboard's cache. The alert is
            // `time() - dns_zone_last_refresh_timestamp_seconds > <expire>`.
            //
            // Zones with no transfer are **omitted rather than zeroed**: a
            // primary is never transferred and a secondary that has not managed
            // its first fetch has no answer, and `0` for either reads as 1970 and
            // fires every staleness alert there is. An absent series is a
            // question the query language can ask about (`absent()`); a wrong
            // one is not.
            output.push_str(
                "# HELP dns_zone_last_refresh_timestamp_seconds \
                 Unix time of the last successful transfer of a replicated zone\n",
            );
            output.push_str("# TYPE dns_zone_last_refresh_timestamp_seconds gauge\n");
            for (zone, gauge) in zones.iter() {
                if let Some(at) = gauge.last_transfer {
                    output.push_str(&format!(
                        "dns_zone_last_refresh_timestamp_seconds{{zone=\"{}\"}} {at}\n",
                        escape_label(zone)
                    ));
                }
            }
        }

        output
    }

    /// Get current metrics snapshot
    pub fn get_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queries_received: self.queries_received.load(Ordering::Relaxed),
            queries_authoritative: self.queries_authoritative.load(Ordering::Relaxed),
            queries_recursive: self.queries_recursive.load(Ordering::Relaxed),
            responses_sent: self.responses_sent.load(Ordering::Relaxed),
            responses_nxdomain: self.responses_nxdomain.load(Ordering::Relaxed),
            responses_servfail: self.responses_servfail.load(Ordering::Relaxed),
            responses_refused: self.responses_refused.load(Ordering::Relaxed),
            responses_noerror: self.responses_noerror.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            validation_errors: self.validation_errors.load(Ordering::Relaxed),
            queries_dropped: self.queries_dropped.load(Ordering::Relaxed),
        }
    }
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Wall-clock timer for one query, in the units a latency histogram wants.
///
/// `Instant`, not the wall clock: this measures an interval rather than naming
/// a moment, and the wall clock can step backwards (`CLAUDE.md` §6).
pub struct LatencyTimer {
    start: Instant,
}

impl LatencyTimer {
    pub fn new() -> Self {
        LatencyTimer {
            start: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    pub fn elapsed_us(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1_000_000.0
    }
}

impl Default for LatencyTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub queries_received: u64,
    pub queries_authoritative: u64,
    pub queries_recursive: u64,
    pub responses_sent: u64,
    pub responses_nxdomain: u64,
    pub responses_servfail: u64,
    pub responses_refused: u64,
    pub responses_noerror: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rate_limited: u64,
    pub validation_errors: u64,
    pub queries_dropped: u64,
}

#[cfg(test)]
mod zone_gauge_tests {
    use super::*;

    fn lines(metrics: &DnsMetrics, prefix: &str) -> Vec<String> {
        metrics
            .to_prometheus_format()
            .lines()
            .filter(|l| l.starts_with(prefix))
            .map(str::to_string)
            .collect()
    }

    /// The two questions an operator asks of a server holding zones: which
    /// version am I serving, and when did this replica last hear from its
    /// master.
    #[test]
    fn a_zone_reports_its_serial_and_a_replica_its_last_contact() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("example.com.", 42);
        metrics.set_zone_serial("replica.test.", 7);
        metrics.note_zone_transfer("replica.test.", 1_700_000_000);

        assert_eq!(
            lines(&metrics, "dns_zone_serial{"),
            [
                "dns_zone_serial{zone=\"example.com.\"} 42",
                "dns_zone_serial{zone=\"replica.test.\"} 7",
            ]
        );
        // Only the replica has a refresh time. The primary is **omitted**, not
        // zeroed: a zero would read as 1970 and fire every staleness alert.
        assert_eq!(
            lines(&metrics, "dns_zone_last_refresh_timestamp_seconds{"),
            ["dns_zone_last_refresh_timestamp_seconds{zone=\"replica.test.\"} 1700000000"]
        );
    }

    /// A withdrawn or removed zone stops being reported. A gauge frozen at its
    /// last value shows a zone nobody serves as perfectly healthy, which is the
    /// failure mode a staleness alert exists to catch and would miss.
    #[test]
    fn a_withdrawn_zone_disappears_rather_than_freezing() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("gone.test.", 1);
        metrics.note_zone_transfer("gone.test.", 1_700_000_000);
        assert_eq!(lines(&metrics, "dns_zone_serial{").len(), 1);

        metrics.forget_zone("gone.test.");
        assert!(lines(&metrics, "dns_zone_serial{").is_empty());
        assert!(lines(&metrics, "dns_zone_last_refresh_timestamp_seconds{").is_empty());
    }

    /// A reload replaces the set, so zones dropped from the configuration go
    /// with it — and the ones that stay keep what they had.
    #[test]
    fn a_reload_keeps_only_the_zones_it_installed() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("kept.test.", 5);
        metrics.note_zone_transfer("kept.test.", 1_700_000_000);
        metrics.set_zone_serial("dropped.test.", 9);

        metrics.retain_zones(&["KEPT.test.".to_string()]);

        assert_eq!(
            lines(&metrics, "dns_zone_serial{"),
            ["dns_zone_serial{zone=\"kept.test.\"} 5"],
            "the comparison is case-insensitive, as every name comparison here is"
        );
        assert_eq!(
            lines(&metrics, "dns_zone_last_refresh_timestamp_seconds{").len(),
            1,
            "and a kept zone keeps its refresh time"
        );
    }

    /// A quote in a label value would end the label early and make **the rest of
    /// the scrape** unparseable, not just this line. Zone names should not
    /// contain one, but they come from a file an operator wrote.
    #[test]
    fn a_label_value_that_could_break_the_format_is_escaped() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("od\"d\\.test.", 1);
        let rendered = lines(&metrics, "dns_zone_serial{");
        assert_eq!(rendered, ["dns_zone_serial{zone=\"od\\\"d\\\\.test.\"} 1"]);
        assert_eq!(escape_label("plain.test."), "plain.test.");
        assert_eq!(escape_label("a\nb"), "a\\nb");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rtype;

    #[test]
    fn test_metrics_creation() {
        let metrics = DnsMetrics::new();
        assert_eq!(metrics.queries_received.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = DnsMetrics::new();
        metrics.queries_received.fetch_add(1, Ordering::Relaxed);
        metrics.responses_sent.fetch_add(1, Ordering::Relaxed);

        assert_eq!(metrics.queries_received.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.responses_sent.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_track_query_type() {
        let metrics = DnsMetrics::new();

        metrics.track_query_type(Qtype::of(rt::A)); // A
        metrics.track_query_type(Qtype::of(rt::A)); // A
        metrics.track_query_type(Qtype::of(rt::AAAA)); // AAAA
        metrics.track_query_type(Qtype::of(Rtype::new(99))); // Unknown

        assert_eq!(metrics.queries_type_a.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.queries_type_aaaa.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.queries_type_other.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = DnsMetrics::new();
        metrics.queries_received.fetch_add(100, Ordering::Relaxed);
        metrics.responses_sent.fetch_add(90, Ordering::Relaxed);

        let prometheus = metrics.to_prometheus_format();
        assert!(prometheus.contains("dns_queries_received_total 100"));
        assert!(prometheus.contains("dns_responses_sent_total 90"));
        assert!(prometheus.contains("# HELP"));
        assert!(prometheus.contains("# TYPE"));
    }

    #[test]
    fn test_metrics_snapshot() {
        let metrics = DnsMetrics::new();
        metrics.queries_received.fetch_add(50, Ordering::Relaxed);
        metrics.cache_hits.fetch_add(25, Ordering::Relaxed);

        let snapshot = metrics.get_snapshot();
        assert_eq!(snapshot.queries_received, 50);
        assert_eq!(snapshot.cache_hits, 25);
    }
}
