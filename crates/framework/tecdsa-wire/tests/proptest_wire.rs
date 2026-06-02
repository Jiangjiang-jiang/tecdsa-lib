// SPDX-License-Identifier: MIT OR Apache-2.0
use proptest::prelude::*;
use tecdsa_wire::{decode, encode, Header};

fn arb_header() -> impl Strategy<Value = Header> {
    (
        proptest::array::uniform32(any::<u8>()),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
    )
        .prop_map(|(session_id, protocol_id, round, from, to)| Header {
            session_id,
            protocol_id,
            round,
            from,
            to,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn wire_roundtrip(header in arb_header(), payload: Vec<u8>) {
        let encoded = encode(&header, &payload).unwrap();

        // Preamble check
        prop_assert_eq!(&encoded[..4], b"MPCE");

        let (dec_hdr, dec_payload) = decode::<Vec<u8>>(&encoded).unwrap();
        prop_assert_eq!(dec_hdr, header);
        prop_assert_eq!(dec_payload, payload);
    }

    #[test]
    fn decode_never_panics(data: Vec<u8>) {
        // Decoding arbitrary bytes must not panic; errors are fine.
        let _ = decode::<Vec<u8>>(&data);
    }
}
