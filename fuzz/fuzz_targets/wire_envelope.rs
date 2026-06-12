#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tecdsa_wire::decode::<Vec<u8>>(data);
});
