#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 4 * 2 {
        return;
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&data[..32]);
    let header = tecdsa_wire::Header {
        session_id,
        protocol_id: u16::from_be_bytes([data[32], data[33]]),
        round: u16::from_be_bytes([data[34], data[35]]),
        from: u16::from_be_bytes([data[36], data[37]]),
        to: u16::from_be_bytes([data[38], data[39]]),
    };
    // Exercise equality, debug, clone
    let _ = header.clone();
    let _ = format!("{:?}", header);
    let _ = header == header;
});
