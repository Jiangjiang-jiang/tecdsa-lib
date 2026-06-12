use tecdsa_wire::{decode, encode, Header};

#[test]
fn envelope_roundtrip() {
    let header = Header {
        session_id: [0xAA; 32],
        protocol_id: 1,
        round: 2,
        from: 0,
        to: 1,
    };
    let payload: Vec<u8> = vec![1, 2, 3, 4, 5];
    let encoded = encode(&header, &payload).unwrap();
    assert_eq!(&encoded[..4], b"MPCE");
    assert_eq!(encoded[4..8], [1, 0, 0, 0]);

    let (decoded_header, decoded_payload) = decode::<Vec<u8>>(&encoded).unwrap();
    assert_eq!(decoded_header.session_id, header.session_id);
    assert_eq!(decoded_header.round, 2);
    assert_eq!(decoded_payload, payload);
}

#[test]
fn wrong_preamble_rejected() {
    let bad = b"BAAD\x01\x00\x00\x00rest";
    assert!(decode::<Vec<u8>>(bad).is_err());
}

#[test]
fn wrong_version_rejected() {
    let mut data = encode(
        &Header {
            session_id: [0; 32],
            protocol_id: 0,
            round: 0,
            from: 0,
            to: 0,
        },
        &vec![1u8],
    )
    .unwrap();
    data[4] = 99;
    assert!(decode::<Vec<u8>>(&data).is_err());
}
