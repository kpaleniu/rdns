//! Counters an operator can page on, and the Prometheus text to scrape them.
//!
//! Relaxed atomics: each counter is independent, nothing branches on one, and a
//! scrape is a snapshot of a moving system either way.

use crate::utils::record_types as rt;
use crate::utils::NameKeyBuf;
use crate::Qtype;
use crate::Serial;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::ResponseCode;

/// Upper bounds, in whole microseconds, of the latency histogram's buckets.
///
/// Integers, because the write path compares against them on every answer and a
/// float comparison buys nothing: the sum is already stored in integer
/// microseconds, and the `le` labels are divided into seconds once, at scrape.
///
/// The bottom of the range is measured, not guessed. One whole answer — parse,
/// look up, build, serialize — is 0.84 µs for a lower-case QNAME and 0.94 µs
/// with the case randomized (`TODO.md` #27), so a healthy server lives between
/// 1 and 10 µs. These bounds ran 50 µs to 100 ms before, which put every
/// answer a healthy server gives into the first bucket — the same defect §14
/// records at one decimal higher, where the floor was 5 ms.
const LATENCY_BUCKETS_US: [u64; 8] = [1, 2, 5, 10, 50, 500, 5_000, 50_000];

/// Escape a label value for the Prometheus text format: backslash, double quote
/// and newline.
///
/// Zone names come from a file an operator wrote and RFC 1035 §5.1 allows `\`
/// escapes, and one stray quote makes the rest of the scrape unparseable.
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

/// One zone's gauges, named, as [`DnsMetrics::zone_facts`] hands them out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFacts {
    pub zone: String,
    pub serial: Serial,
    /// `None` for a primary zone and for a secondary that has never reached its
    /// master. Zero would be 1970 and fire every staleness alert there is.
    pub last_transfer: Option<u64>,
}

/// What is currently true of one zone.
#[derive(Debug, Clone, Copy, Default)]
struct ZoneGauge {
    serial: Serial,
    /// Unix seconds of the last successful contact with a master — what EXPIRE
    /// counts from. A refresh that found nothing new still counts.
    ///
    /// `None`, never zero, for a primary zone and for a secondary that has not
    /// managed its first fetch: zero reads as 1970.
    last_transfer: Option<u64>,
}

/// Prometheus-compatible metrics for DNS server.
///
/// A handle: every task that reports anything holds a clone, so cloning is one
/// refcount operation. It was an `Arc` *per counter* — 26 allocations to build
/// and 26 refcount operations to clone, for something whose fields are only ever
/// read and written together (`TODO.md` #25c-bis).
///
/// `Deref` rather than 24 accessors, so `metrics.count(&metrics.rate_limited)`
/// still reads the same at all 31 call sites.
#[derive(Clone)]
pub struct DnsMetrics(Arc<Counters>);

impl std::ops::Deref for DnsMetrics {
    type Target = Counters;

    fn deref(&self) -> &Counters {
        &self.0
    }
}

/// The counters themselves, reached through [`DnsMetrics`].
pub struct Counters {
    // Query counters
    pub queries_received: AtomicU64,
    pub queries_authoritative: AtomicU64,
    pub queries_recursive: AtomicU64,

    // Response counters
    pub responses_sent: AtomicU64,
    pub responses_nxdomain: AtomicU64,
    pub responses_servfail: AtomicU64,
    pub responses_refused: AtomicU64,
    pub responses_noerror: AtomicU64,

    // Cache metrics
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,

    // Security metrics
    pub rate_limited: AtomicU64,
    pub validation_errors: AtomicU64,
    pub queries_dropped: AtomicU64,

    // Cumulative buckets plus count and sum: what `histogram_quantile()` needs.
    latency_buckets: [AtomicU64; 8],
    latency_count: AtomicU64,
    /// Microseconds, integer, so the sum needs no float atomic.
    latency_sum_us: AtomicU64,

    /// Per-zone facts, written where the fact changes rather than sampled at
    /// scrape time: sampling would put the scrape behind the zone-map lock and
    /// the value would still be only as fresh as the last scrape.
    ///
    /// Unbounded is safe here — the keys are configured zone names, not
    /// anything a client puts on the wire.
    zones: RwLock<BTreeMap<NameKeyBuf, ZoneGauge>>,

    // Record type counters
    pub queries_type_a: AtomicU64,
    pub queries_type_aaaa: AtomicU64,
    pub queries_type_mx: AtomicU64,
    pub queries_type_ns: AtomicU64,
    pub queries_type_cname: AtomicU64,
    pub queries_type_txt: AtomicU64,
    pub queries_type_soa: AtomicU64,
    pub queries_type_ptr: AtomicU64,
    pub queries_type_other: AtomicU64,
}

impl DnsMetrics {
    pub fn new() -> Self {
        DnsMetrics(Arc::new(Counters {
            queries_received: AtomicU64::new(0),
            queries_authoritative: AtomicU64::new(0),
            queries_recursive: AtomicU64::new(0),
            responses_sent: AtomicU64::new(0),
            responses_nxdomain: AtomicU64::new(0),
            responses_servfail: AtomicU64::new(0),
            responses_refused: AtomicU64::new(0),
            responses_noerror: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            validation_errors: AtomicU64::new(0),
            queries_dropped: AtomicU64::new(0),
            zones: RwLock::new(BTreeMap::new()),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            latency_count: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            queries_type_a: AtomicU64::new(0),
            queries_type_aaaa: AtomicU64::new(0),
            queries_type_mx: AtomicU64::new(0),
            queries_type_ns: AtomicU64::new(0),
            queries_type_cname: AtomicU64::new(0),
            queries_type_txt: AtomicU64::new(0),
            queries_type_soa: AtomicU64::new(0),
            queries_type_ptr: AtomicU64::new(0),
            queries_type_other: AtomicU64::new(0),
        }))
    }

    /// Add one to a counter: `metrics.count(&metrics.rate_limited)`.
    pub fn count(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one answer by the code it carries.
    ///
    /// Only the three an operator pages on are broken out: REFUSED climbing
    /// means a zone went missing, SERVFAIL that one went wrong, NXDOMAIN is
    /// ordinary. The rest count as sent.
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
    /// One bucket, not every bucket at or above the sample. Prometheus buckets
    /// are cumulative, and this used to make them cumulative *here* — eight
    /// read-modify-writes on shared cache lines per answer, plus the count and
    /// the sum. [`DnsMetrics::render`] adds them up instead, which is what every
    /// Prometheus client library does and renders byte-for-byte the same.
    pub fn observe_latency_us(&self, us: u64) {
        // The first bound at or above the sample: `le` is inclusive, so a sample
        // exactly on a bound belongs to that bound's bucket. Past the last bound
        // there is no bucket to touch — `+Inf` is `latency_count`.
        let index = LATENCY_BUCKETS_US.partition_point(|&bound| bound < us);
        if let Some(bucket) = self.latency_buckets.get(index) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// Record the serial currently served for `zone`. Call it wherever a zone is
    /// installed; that is the only moment the answer changes.
    pub fn set_zone_serial(&self, zone: &str, serial: Serial) {
        let Ok(mut zones) = self.zones.write() else {
            // A poisoned lock costs a stale gauge; refusing to serve DNS over
            // one would be worse.
            return;
        };
        zones.entry(NameKeyBuf::new(zone)).or_default().serial = serial;
    }

    /// Record that `zone` was in contact with its master at `at` (Unix seconds).
    pub fn note_zone_transfer(&self, zone: &str, at: u64) {
        let Ok(mut zones) = self.zones.write() else {
            return;
        };
        zones
            .entry(NameKeyBuf::new(zone))
            .or_default()
            .last_transfer = Some(at);
    }

    /// Stop reporting `zone` — removed from the configuration, or withdrawn for
    /// EXPIRE.
    ///
    /// Forget rather than zero: a gauge frozen at its last value shows a zone
    /// nobody serves as perfectly healthy.
    pub fn forget_zone(&self, zone: &str) {
        let Ok(mut zones) = self.zones.write() else {
            return;
        };
        zones.remove(zone);
    }

    /// Snapshot of each zone's serial and last contact with a master.
    ///
    /// The control channel's `status` reads these rather than growing a second
    /// view of the same facts. The lock is released before returning, so a
    /// caller cannot hold the gauges open across an await.
    pub fn zone_facts(&self) -> Vec<ZoneFacts> {
        let Ok(zones) = self.zones.read() else {
            return Vec::new();
        };
        zones
            .iter()
            .map(|(zone, gauge)| ZoneFacts {
                zone: zone.to_string(),
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
        zones.retain(|name, _| keep.iter().any(|k| k.eq_ignore_ascii_case(name.as_str())));
    }

    /// Track query type.
    ///
    /// A [`Qtype`], not an `Rtype`: AXFR, IXFR and ANY are legitimate here and
    /// land in `other`.
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

        // Seconds: Prometheus convention is base units.
        output.push_str("# HELP dns_answer_latency_seconds Time to build one answer\n");
        output.push_str("# TYPE dns_answer_latency_seconds histogram\n");
        // Cumulated here rather than on the write path. Buckets are read one at
        // a time, so a scrape racing an answer can see a total an instant old —
        // true of every counter in this file, and what Prometheus expects.
        let mut cumulative = 0u64;
        for (bound, bucket) in LATENCY_BUCKETS_US.iter().zip(self.latency_buckets.iter()) {
            cumulative += bucket.load(Ordering::Relaxed);
            output.push_str(&format!(
                "dns_answer_latency_seconds_bucket{{le=\"{}\"}} {}\n",
                *bound as f64 / 1_000_000.0,
                cumulative
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

        if let Ok(zones) = self.zones.read() {
            output.push_str("# HELP dns_zone_serial SOA serial currently served\n");
            output.push_str("# TYPE dns_zone_serial gauge\n");
            for (zone, gauge) in zones.iter() {
                output.push_str(&format!(
                    "dns_zone_serial{{zone=\"{}\"}} {}\n",
                    escape_label(zone.as_str()),
                    gauge.serial
                ));
            }

            // An instant, not a "seconds since": `time() - x` is the query
            // language's job, and a duration computed here is stale on arrival.
            //
            // Zones with no transfer are omitted, not zeroed — zero reads as
            // 1970. `absent()` is a question the query language can ask.
            output.push_str(
                "# HELP dns_zone_last_refresh_timestamp_seconds \
                 Unix time of the last successful transfer of a replicated zone\n",
            );
            output.push_str("# TYPE dns_zone_last_refresh_timestamp_seconds gauge\n");
            for (zone, gauge) in zones.iter() {
                if let Some(at) = gauge.last_transfer {
                    output.push_str(&format!(
                        "dns_zone_last_refresh_timestamp_seconds{{zone=\"{}\"}} {at}\n",
                        escape_label(zone.as_str())
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

/// Timer for one query, in the units a latency histogram wants.
///
/// `Instant`: this measures an interval, and the wall clock steps backwards.
pub struct LatencyTimer {
    start: Instant,
}

impl LatencyTimer {
    pub fn new() -> Self {
        LatencyTimer {
            start: Instant::now(),
        }
    }

    /// Whole microseconds since the timer started.
    ///
    /// Integer: this feeds [`DnsMetrics::observe_latency_us`], whose bounds and
    /// whose sum are both integer microseconds. `as u64` saturates at zero for
    /// the sub-microsecond case, which is the right floor for a duration.
    pub fn elapsed_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
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

    #[test]
    fn a_zone_reports_its_serial_and_a_replica_its_last_contact() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("example.com.", Serial::new(42));
        metrics.set_zone_serial("replica.test.", Serial::new(7));
        metrics.note_zone_transfer("replica.test.", 1_700_000_000);

        assert_eq!(
            lines(&metrics, "dns_zone_serial{"),
            [
                "dns_zone_serial{zone=\"example.com.\"} 42",
                "dns_zone_serial{zone=\"replica.test.\"} 7",
            ]
        );
        // The primary is omitted, not zeroed: zero reads as 1970.
        assert_eq!(
            lines(&metrics, "dns_zone_last_refresh_timestamp_seconds{"),
            ["dns_zone_last_refresh_timestamp_seconds{zone=\"replica.test.\"} 1700000000"]
        );
    }

    /// A gauge frozen at its last value shows a zone nobody serves as perfectly
    /// healthy — the failure a staleness alert exists to catch.
    #[test]
    fn a_withdrawn_zone_disappears_rather_than_freezing() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("gone.test.", Serial::new(1));
        metrics.note_zone_transfer("gone.test.", 1_700_000_000);
        assert_eq!(lines(&metrics, "dns_zone_serial{").len(), 1);

        metrics.forget_zone("gone.test.");
        assert!(lines(&metrics, "dns_zone_serial{").is_empty());
        assert!(lines(&metrics, "dns_zone_last_refresh_timestamp_seconds{").is_empty());
    }

    #[test]
    fn a_reload_keeps_only_the_zones_it_installed() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("kept.test.", Serial::new(5));
        metrics.note_zone_transfer("kept.test.", 1_700_000_000);
        metrics.set_zone_serial("dropped.test.", Serial::new(9));

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

    /// A quote ends the label early and makes the rest of the scrape
    /// unparseable, not just this line.
    #[test]
    fn a_label_value_that_could_break_the_format_is_escaped() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial("od\"d\\.test.", Serial::new(1));
        let rendered = lines(&metrics, "dns_zone_serial{");
        assert_eq!(rendered, ["dns_zone_serial{zone=\"od\\\"d\\\\.test.\"} 1"]);
        assert_eq!(escape_label("plain.test."), "plain.test.");
        assert_eq!(escape_label("a\nb"), "a\\nb");
    }

    /// Buckets are cumulative in the *output* and one-per-sample on the write
    /// path, so the sum has to be rebuilt at scrape. Get that wrong and the
    /// histogram reads as a distribution nobody observed.
    ///
    /// `le` is inclusive, which is the boundary the write path can get off by
    /// one: a sample of exactly 5 µs belongs to `le="0.000005"`, not the one
    /// above it.
    #[test]
    fn the_latency_histogram_renders_cumulative_buckets() {
        let metrics = DnsMetrics::new();
        // One in the first bucket, one exactly on a bound, one past every bound.
        for us in [1, 5, 1_000_000] {
            metrics.observe_latency_us(us);
        }

        let rendered = lines(&metrics, "dns_answer_latency_seconds");
        assert_eq!(
            rendered,
            [
                "dns_answer_latency_seconds_bucket{le=\"0.000001\"} 1",
                "dns_answer_latency_seconds_bucket{le=\"0.000002\"} 1",
                "dns_answer_latency_seconds_bucket{le=\"0.000005\"} 2",
                "dns_answer_latency_seconds_bucket{le=\"0.00001\"} 2",
                "dns_answer_latency_seconds_bucket{le=\"0.00005\"} 2",
                "dns_answer_latency_seconds_bucket{le=\"0.0005\"} 2",
                "dns_answer_latency_seconds_bucket{le=\"0.005\"} 2",
                "dns_answer_latency_seconds_bucket{le=\"0.05\"} 2",
                "dns_answer_latency_seconds_bucket{le=\"+Inf\"} 3",
                "dns_answer_latency_seconds_sum 1.000006",
                "dns_answer_latency_seconds_count 3",
            ]
        );
    }

    /// A sample past the last bound has no bucket of its own — `+Inf` is the
    /// count — and must still reach the count and the sum. An `unwrap` on the
    /// bucket index would panic here, and a `min` would put it in the last
    /// bucket and claim a 1-second answer took under 50 ms.
    #[test]
    fn a_latency_past_every_bound_lands_only_in_inf() {
        let metrics = DnsMetrics::new();
        metrics.observe_latency_us(60_000);
        let rendered = lines(&metrics, "dns_answer_latency_seconds");
        assert!(
            rendered.iter().all(|line| !line.contains("le=\"0.05\"} 1")),
            "60 ms must not be counted under the 50 ms bound: {rendered:?}"
        );
        assert!(rendered.contains(&"dns_answer_latency_seconds_bucket{le=\"+Inf\"} 1".to_string()));
        assert!(rendered.contains(&"dns_answer_latency_seconds_count 1".to_string()));
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
