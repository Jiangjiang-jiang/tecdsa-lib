#![no_main]
use libfuzzer_sys::fuzz_target;
use tecdsa_wire::{decode, encode};

fuzz_target!(|data: &[u8]| {
    if data.len() < 42 {
        return;
    }
    // Extract header fields from fuzz input
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&data[..32]);
    let protocol_id = u16::from_be_bytes([data[32], data[33]]);
    let round = u16::from_be_bytes([data[34], data[35]]);
    let from = u16::from_be_bytes([data[36], data[37]]);
    let to = u16::from_be_bytes([data[38], data[39]]);
    let payload_len = u16::from_be_bytes([data[40], data[41]]) as usize;

    let header = tecdsa_wire::Header {
        session_id,
        protocol_id,
        round,
        from,
        to,
    };
    let payload: Vec<u8> = data.get(42..42 + payload_len).unwrap_or(&[]).to_vec();

    if let Ok(encoded) = encode(&header, &payload) {
        let decoded: Result<(tecdsa_wire::Header, Vec<u8>), _> = decode(&encoded);
        if let Ok((dec_header, dec_payload)) = decoded {
            assert_eq!(header, dec_header);
            assert_eq!(payload, dec_payload);
        }
    }
});
