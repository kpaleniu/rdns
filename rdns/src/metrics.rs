//! Counters an operator can page on, and the Prometheus text to scrape them.
//!
//! Relaxed atomics: each counter is independent, nothing branches on one, and a
//! scrape is a snapshot of a moving system either way.

use crate::name_keys::NameKeyBuf;
use crate::record_types as rt;
use crate::NameRef;
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
///
/// The top of the range is the same defect from the other end, and one
/// histogram serves both daemons. It stopped at 50 ms, so every answer `rdnsr`
/// gives that cost a recursion — a walk from the root is tens to hundreds of
/// milliseconds before anything goes wrong — was `+Inf` and the tail had no
/// shape at all. The three added bounds are each a number something already
/// decides on: 0.5 s is a slow recursion that still finished, **1.8 s is
/// RFC 8767 §4's recommended client response timer**, so `le="1.8"` against
/// `+Inf` is how often that timer would fire (`TODO.md` #58), and 5 s is
/// [`crate::resolver::ResolverConfig::timeout_ms`]'s default, so past it at
/// least one upstream round trip has already timed out.
const LATENCY_BUCKETS_US: [u64; 11] = [
    1, 2, 5, 10, 50, 500, 5_000, 50_000, 500_000, 1_800_000, 5_000_000,
];

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

    /// DoT connections whose handshake completed, and those that did not.
    ///
    /// The pair is how an expired or mismatched certificate is seen at all
    /// (`TODO.md` #42a). Nothing here parses `notAfter` — that would be an X.509
    /// parser whose whole job is a log line — so the failure is reported as the
    /// symptom it produces: every client hanging up at the handshake. A ratio
    /// that goes to one is the alert, and it does not need the expiry date to
    /// fire.
    pub tls_handshakes: AtomicU64,
    pub tls_handshake_failures: AtomicU64,
    /// The same pair for DoQ, and separate on purpose: the two listen on the
    /// same port number over different protocols, so one series would hide a
    /// client population failing on only one of them.
    pub quic_handshakes: AtomicU64,
    pub quic_handshake_failures: AtomicU64,

    /// Answers a Response Policy Zone replaced (`crate::rpz`), and queries it
    /// dropped outright.
    ///
    /// Two counters, because the second is invisible otherwise: an `rpz-drop`
    /// rule sends nothing at all, so without this the operator sees a query
    /// arrive, no answer leave, and has nothing to attribute it to
    /// (`CLAUDE.md` §14). A match that passes the query through is neither —
    /// nothing was changed.
    pub policy_rewrites: AtomicU64,
    pub policy_drops: AtomicU64,

    /// AAAA answers synthesized from an A record (RFC 6147, `--dns64`).
    ///
    /// Every one is an address that exists in no zone, so this is the number an
    /// operator watches when a NAT64 is retired or its prefix changes: it does
    /// not fall to zero on its own.
    pub synthesized: AtomicU64,

    /// Names re-resolved before they expired (`--prefetch`).
    ///
    /// Every one is an upstream query no client asked for, which is what the
    /// switch buys and what it costs: against `dns_cache_hits_total` it says
    /// whether prefetching is paying for itself.
    pub prefetches: AtomicU64,

    /// Resolutions that ran past RFC 8767 §4's client response timer, by what
    /// they did next (`TODO.md` #58).
    ///
    /// The pair, not the sum, because the two say different things about
    /// whether the second timer is worth building. **`completed`** is a client
    /// that waited over [`crate::cache::CLIENT_RESPONSE_TIMER`] for an answer
    /// this resolver could have had from the stale window immediately; every
    /// one of those is the timer's whole case. **`failed`** is a resolution
    /// that was going to serve stale anyway — the *query resolution* timer
    /// already covers it — so the second timer buys only the seconds between
    /// the two, and summing the pair would credit the feature with work it
    /// does not do (`CLAUDE.md` §19).
    ///
    /// A completed resolution whose answer was refused as bogus counts as
    /// completed: what this measures is whether the walk would have finished
    /// into the cache behind an early reply, which it would.
    ///
    /// Only the answer path counts. A prefetch and DNS64's A query resolve with
    /// no client waiting, and a timer about what a client waits for has nothing
    /// to say about them.
    pub slow_resolutions_completed: AtomicU64,
    pub slow_resolutions_failed: AtomicU64,

    /// Answers served from expired cache because a refresh failed (RFC 8767).
    ///
    /// The number an operator watches during somebody else's outage, and the
    /// one that says whether `--serve-stale` is doing anything at all: a
    /// resolver that never serves stale and one that has it turned off look
    /// identical from outside.
    pub stale_answers: AtomicU64,

    /// dnstap payloads queued for the collector, and those the queue had no
    /// room for.
    ///
    /// The pair, not just the first: the queue is bounded on purpose — a
    /// collector that stops reading must not stop the server — so a bound with
    /// no visible shortfall would make the stream quietly incomplete
    /// (`CLAUDE.md` §5). A ratio that leaves zero is the alert.
    pub dnstap_frames: AtomicU64,
    pub dnstap_dropped: AtomicU64,

    // Cumulative buckets plus count and sum: what `histogram_quantile()` needs.
    //
    // Length from the bounds, not repeated: the two were `8` twice, and a bound
    // added without the counter is a scrape that silently stops at the old top
    // (`CLAUDE.md` §17).
    latency_buckets: [AtomicU64; LATENCY_BUCKETS_US.len()],
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
    /// How many member zones each consumed catalog has this server serving
    /// (RFC 9432). Separate from `zones` because a catalog is not a zone fact:
    /// the catalog zone itself has a serial and a last-transfer time like any
    /// other, and this counts what it provisioned.
    catalogs: RwLock<BTreeMap<NameKeyBuf, usize>>,

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
            tls_handshakes: AtomicU64::new(0),
            tls_handshake_failures: AtomicU64::new(0),
            quic_handshakes: AtomicU64::new(0),
            quic_handshake_failures: AtomicU64::new(0),
            synthesized: AtomicU64::new(0),
            prefetches: AtomicU64::new(0),
            stale_answers: AtomicU64::new(0),
            slow_resolutions_completed: AtomicU64::new(0),
            slow_resolutions_failed: AtomicU64::new(0),
            policy_rewrites: AtomicU64::new(0),
            policy_drops: AtomicU64::new(0),
            dnstap_frames: AtomicU64::new(0),
            dnstap_dropped: AtomicU64::new(0),
            zones: RwLock::new(BTreeMap::new()),
            catalogs: RwLock::new(BTreeMap::new()),
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
    /// the sum. [`DnsMetrics::to_prometheus_format`] adds them up instead, which
    /// is what every Prometheus client library does and renders byte-for-byte the
    /// same.
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
    pub fn set_zone_serial(&self, zone: NameRef<'_>, serial: Serial) {
        let Ok(mut zones) = self.zones.write() else {
            // A poisoned lock costs a stale gauge; refusing to serve DNS over
            // one would be worse.
            return;
        };
        zones.entry(NameKeyBuf::new(zone)).or_default().serial = serial;
    }

    /// Record that `zone` was in contact with its master at `at` (Unix seconds).
    pub fn note_zone_transfer(&self, zone: NameRef<'_>, at: u64) {
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
    pub fn forget_zone(&self, zone: NameRef<'_>) {
        let Ok(mut zones) = self.zones.write() else {
            return;
        };
        zones.remove(zone.folded().as_ref());
    }

    /// Record how many member zones `catalog` currently has this server
    /// serving.
    ///
    /// The number an operator alerts on: RFC 9432 §6 is explicit that a
    /// producer's mistake can take every member zone off a whole fleet at once
    /// ("millions of member zones may get deleted from their secondaries within
    /// seconds"), and a count that falls off a cliff is how that is seen before
    /// the queries stop.
    pub fn set_catalog_members(&self, catalog: NameRef<'_>, members: usize) {
        let Ok(mut catalogs) = self.catalogs.write() else {
            // As above: a poisoned lock costs a stale gauge.
            return;
        };
        catalogs.insert(NameKeyBuf::new(catalog), members);
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
    pub fn retain_zones(&self, keep: &[crate::Name]) {
        let Ok(mut zones) = self.zones.write() else {
            return;
        };
        zones.retain(|name, _| keep.iter().any(|k| k.as_ref() == name.as_name()));
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

        output.push_str("# HELP dns_synthesized_total AAAA records synthesized by DNS64\n");
        output.push_str("# TYPE dns_synthesized_total counter\n");
        output.push_str(&format!(
            "dns_synthesized_total {}\n",
            self.synthesized.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_prefetches_total Names re-resolved before expiry\n");
        output.push_str("# TYPE dns_prefetches_total counter\n");
        output.push_str(&format!(
            "dns_prefetches_total {}\n",
            self.prefetches.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_stale_answers_total Answers served from expired cache\n");
        output.push_str("# TYPE dns_stale_answers_total counter\n");
        output.push_str(&format!(
            "dns_stale_answers_total {}\n",
            self.stale_answers.load(Ordering::Relaxed)
        ));

        output.push_str(
            "# HELP dns_slow_resolutions_total \
Resolutions past RFC 8767's client response timer\n",
        );
        output.push_str("# TYPE dns_slow_resolutions_total counter\n");
        output.push_str(&format!(
            "dns_slow_resolutions_total{{outcome=\"completed\"}} {}\n",
            self.slow_resolutions_completed.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_slow_resolutions_total{{outcome=\"failed\"}} {}\n",
            self.slow_resolutions_failed.load(Ordering::Relaxed)
        ));

        output.push_str(
            "# HELP dns_policy_rewrites_total Answers replaced by a response policy zone\n",
        );
        output.push_str("# TYPE dns_policy_rewrites_total counter\n");
        output.push_str(&format!(
            "dns_policy_rewrites_total {}\n",
            self.policy_rewrites.load(Ordering::Relaxed)
        ));

        output
            .push_str("# HELP dns_policy_drops_total Queries dropped by a response policy zone\n");
        output.push_str("# TYPE dns_policy_drops_total counter\n");
        output.push_str(&format!(
            "dns_policy_drops_total {}\n",
            self.policy_drops.load(Ordering::Relaxed)
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

        // Always emitted, including as a pair of zeroes on a server with no DoT
        // listener. A series that appears only once something has happened
        // cannot be alerted on before it does, and `absent()` is the wrong
        // question here: zero handshakes is a fact, not a missing measurement
        // (contrast the per-zone gauges below, which are omitted on purpose).
        output.push_str("# HELP dns_tls_handshakes_total DoT handshakes completed\n");
        output.push_str("# TYPE dns_tls_handshakes_total counter\n");
        output.push_str(&format!(
            "dns_tls_handshakes_total {}\n",
            self.tls_handshakes.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP dns_tls_handshake_failures_total DoT handshakes that did not complete\n",
        );
        output.push_str("# TYPE dns_tls_handshake_failures_total counter\n");
        output.push_str(&format!(
            "dns_tls_handshake_failures_total {}\n",
            self.tls_handshake_failures.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP dns_quic_handshakes_total DoQ handshakes completed
",
        );
        output.push_str(
            "# TYPE dns_quic_handshakes_total counter
",
        );
        output.push_str(&format!(
            "dns_quic_handshakes_total {}
",
            self.quic_handshakes.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP dns_quic_handshake_failures_total DoQ handshakes that did not complete
",
        );
        output.push_str(
            "# TYPE dns_quic_handshake_failures_total counter
",
        );
        output.push_str(&format!(
            "dns_quic_handshake_failures_total {}
",
            self.quic_handshake_failures.load(Ordering::Relaxed)
        ));

        output.push_str(
            "# HELP dns_dnstap_frames_total dnstap payloads queued for the sink
",
        );
        output.push_str(
            "# TYPE dns_dnstap_frames_total counter
",
        );
        output.push_str(&format!(
            "dns_dnstap_frames_total {}
",
            self.dnstap_frames.load(Ordering::Relaxed)
        ));
        output.push_str(
            "# HELP dns_dnstap_dropped_total dnstap payloads the bounded queue had no room for
",
        );
        output.push_str(
            "# TYPE dns_dnstap_dropped_total counter
",
        );
        output.push_str(&format!(
            "dns_dnstap_dropped_total {}
",
            self.dnstap_dropped.load(Ordering::Relaxed)
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
                    escape_label(&zone.to_string()),
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
                        escape_label(&zone.to_string())
                    ));
                }
            }
        }

        if let Ok(catalogs) = self.catalogs.read() {
            if !catalogs.is_empty() {
                output.push_str(
                    "# HELP dns_catalog_members                      Member zones provisioned from a consumed catalog zone
",
                );
                output.push_str(
                    "# TYPE dns_catalog_members gauge
",
                );
                for (catalog, members) in catalogs.iter() {
                    output.push_str(&format!(
                        "dns_catalog_members{{catalog=\"{}\"}} {members}
",
                        escape_label(&catalog.to_string())
                    ));
                }
            }
        }

        output
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
///
/// `Copy`, because an answer path that offers one reply and then falls through
/// to build another needs the same start instant twice.
#[derive(Clone, Copy)]
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

#[cfg(test)]
mod zone_gauge_tests {
    use super::*;
    use crate::test_records::nm;

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
        metrics.set_zone_serial(nm("example.com.").as_ref(), Serial::new(42));
        metrics.set_zone_serial(nm("replica.test.").as_ref(), Serial::new(7));
        metrics.note_zone_transfer(nm("replica.test.").as_ref(), 1_700_000_000);

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
        metrics.set_zone_serial(nm("gone.test.").as_ref(), Serial::new(1));
        metrics.note_zone_transfer(nm("gone.test.").as_ref(), 1_700_000_000);
        assert_eq!(lines(&metrics, "dns_zone_serial{").len(), 1);

        metrics.forget_zone(nm("gone.test.").as_ref());
        assert!(lines(&metrics, "dns_zone_serial{").is_empty());
        assert!(lines(&metrics, "dns_zone_last_refresh_timestamp_seconds{").is_empty());
    }

    #[test]
    fn a_reload_keeps_only_the_zones_it_installed() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial(nm("kept.test.").as_ref(), Serial::new(5));
        metrics.note_zone_transfer(nm("kept.test.").as_ref(), 1_700_000_000);
        metrics.set_zone_serial(nm("dropped.test.").as_ref(), Serial::new(9));

        metrics.retain_zones(&[nm("KEPT.test.")]);

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
    /// unparseable, not just this line. Escaped twice over: the label value is
    /// the zone's *presentation* form, where RFC 1035 §5.1 already spells a
    /// quote `\"` and a dot inside a label `\.`, and Prometheus then escapes
    /// the backslashes those leave behind.
    #[test]
    fn a_label_value_that_could_break_the_format_is_escaped() {
        let metrics = DnsMetrics::new();
        metrics.set_zone_serial(nm("od\"d\\.test.").as_ref(), Serial::new(1));
        let rendered = lines(&metrics, "dns_zone_serial{");
        assert_eq!(
            rendered,
            ["dns_zone_serial{zone=\"od\\\\\\\"d\\\\.test.\"} 1"]
        );
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
        // One in the first bucket; one exactly on a bound; one exactly on the
        // 1.8 s bound, which is the one `TODO.md` #58 reads; one past every
        // bound.
        for us in [1, 5, 1_800_000, 6_000_000] {
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
                "dns_answer_latency_seconds_bucket{le=\"0.5\"} 2",
                "dns_answer_latency_seconds_bucket{le=\"1.8\"} 3",
                "dns_answer_latency_seconds_bucket{le=\"5\"} 3",
                "dns_answer_latency_seconds_bucket{le=\"+Inf\"} 4",
                "dns_answer_latency_seconds_sum 7.800006",
                "dns_answer_latency_seconds_count 4",
            ]
        );
    }

    /// A sample past the last bound has no bucket of its own — `+Inf` is the
    /// count — and must still reach the count and the sum. An `unwrap` on the
    /// bucket index would panic here, and a `min` would put it in the last
    /// bucket and claim a 10-second answer took under 5 s.
    ///
    /// The sample moved with the bounds: 60 µs past the old 50 ms top is an
    /// ordinary recursion under the new one, so left alone this test would have
    /// gone on passing while testing nothing (`CLAUDE.md` §1).
    #[test]
    fn a_latency_past_every_bound_lands_only_in_inf() {
        let metrics = DnsMetrics::new();
        metrics.observe_latency_us(10_000_000);
        let rendered = lines(&metrics, "dns_answer_latency_seconds");
        assert!(
            rendered.iter().all(|line| !line.contains("le=\"5\"} 1")),
            "10 s must not be counted under the 5 s bound: {rendered:?}"
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

    /// A counter that is declared and incremented and never *rendered* is worse
    /// than one that does not exist: the code reads as if it reports something.
    /// All four encrypted-transport counters were added at once and one pair was
    /// left out of `to_prometheus_format` by an edit that silently did not
    /// apply; the series was simply absent from the scrape.
    ///
    /// Emitted even at zero, on purpose. A series that appears only once
    /// something has happened cannot be alerted on beforehand, and for a
    /// handshake count zero is a fact rather than a missing measurement —
    /// unlike the per-zone gauges, which are omitted so `absent()` can ask.
    #[test]
    fn every_encrypted_transport_counter_reaches_the_scrape() {
        let metrics = DnsMetrics::new();
        let at_zero = metrics.to_prometheus_format();
        for series in [
            "dns_tls_handshakes_total",
            "dns_tls_handshake_failures_total",
            "dns_quic_handshakes_total",
            "dns_quic_handshake_failures_total",
            // Not an encrypted transport, and here for the same reason: a
            // stream nobody configured reads zero, and zero is the fact
            // (`TODO.md` #44g).
            "dns_dnstap_frames_total",
            "dns_dnstap_dropped_total",
        ] {
            assert!(
                at_zero.contains(&format!(
                    "{series} 0
"
                )),
                "{series} is missing from a scrape with no DoT or DoQ listener"
            );
            assert!(
                at_zero.contains(&format!("# TYPE {series} counter")),
                "{series} has no TYPE line"
            );
        }

        metrics.quic_handshakes.fetch_add(3, Ordering::Relaxed);
        metrics
            .tls_handshake_failures
            .fetch_add(7, Ordering::Relaxed);
        let counted = metrics.to_prometheus_format();
        assert!(counted.contains("dns_quic_handshakes_total 3"));
        assert!(counted.contains("dns_tls_handshake_failures_total 7"));
    }

    /// One family, two label values, one HELP and one TYPE between them — a
    /// second TYPE line for the same family makes a scrape unparseable.
    ///
    /// Both series at zero on a server that has never been slow: the absence of
    /// `completed` is the answer `TODO.md` #58 is asking for, and an absent
    /// series cannot say it (`CLAUDE.md` §14).
    #[test]
    fn both_halves_of_the_slow_resolution_split_reach_the_scrape() {
        let metrics = DnsMetrics::new();
        metrics
            .slow_resolutions_completed
            .fetch_add(2, Ordering::Relaxed);
        let rendered = metrics.to_prometheus_format();
        assert!(rendered.contains("dns_slow_resolutions_total{outcome=\"completed\"} 2"));
        assert!(rendered.contains("dns_slow_resolutions_total{outcome=\"failed\"} 0"));
        assert_eq!(
            rendered
                .lines()
                .filter(|l| l.starts_with("# TYPE dns_slow_resolutions_total"))
                .count(),
            1
        );
        assert_eq!(
            rendered
                .lines()
                .filter(|l| l.starts_with("# HELP dns_slow_resolutions_total"))
                .count(),
            1
        );
    }
}
