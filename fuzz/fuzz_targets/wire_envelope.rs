#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise the decode path with arbitrary input.
    // Must never panic; returning Err is fine.
    let _ = tecdsa_wire::decode::<Vec<u8>>(data);
});
