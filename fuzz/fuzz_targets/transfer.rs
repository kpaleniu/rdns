//! Input: a flags byte (bit 0: IXFR rather than AXFR, bit 1: a TSIG key is
//! configured), then the TCP stream. The request id is the first frame's, so a
//! mutation that keeps it gets past the id check.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rdns::tsig::TsigKey;

#[path = "../../rdns/tests/support/wire_input.rs"]
mod wire_input;

static FIXTURE: OnceLock<(wire_input::Fixture, TsigKey, tokio::runtime::Runtime)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Some((&flags, stream)) = data.split_first() else {
        return;
    };
    let (fx, key, runtime) = FIXTURE.get_or_init(|| {
        let key =
            TsigKey::parse("hmac-sha256:probe.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
                .expect("the key spec parses");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime");
        (wire_input::Fixture::new(), key, runtime)
    });
    let id = stream
        .get(2..4)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let key = (flags & 2 != 0).then_some(key);
    let _ = runtime.block_on(rdns::xfr::fuzz_transfer(
        stream,
        id,
        key,
        &fx.zone,
        flags & 1 != 0,
    ));
});
