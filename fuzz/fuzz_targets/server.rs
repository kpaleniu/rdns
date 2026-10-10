#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

#[path = "../../rdns/tests/support/wire_input.rs"]
mod wire_input;

static FIXTURE: OnceLock<wire_input::Fixture> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let fx = FIXTURE.get_or_init(wire_input::Fixture::new);
    wire_input::exercise(data, &fx.zone, &fx.signed, &fx.keyring, fx.now);
});
