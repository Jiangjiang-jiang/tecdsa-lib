use tecdsa_wire::{decode, encode, Header};

#[derive(serde::Deserialize)]
struct KatFile {
    vectors: Vec<KatVector>,
}

#[derive(serde::Deserialize)]
struct KatVector {
    name: String,
    header: KatHeader,
    payload_hex: String,
    encoded_hex: String,
}

#[derive(serde::Deserialize)]
struct KatHeader {
    session_id: String,
    protocol_id: u16,
    round: u16,
    from: u16,
    to: u16,
}

#[test]
fn kat_wire_v1_vectors_encode_and_decode() {
    let file: KatFile =
        serde_json::from_str(include_str!("../../../../tests/vectors/wire_v1.json"))
            .expect("valid wire_v1 KAT JSON");

    assert!(
        !file.vectors.is_empty(),
        "KAT file must contain at least one vector"
    );

    for vector in &file.vectors {
        let session_bytes = hex::decode(&vector.header.session_id).expect("valid session_id hex");
        let session_id: [u8; 32] = session_bytes
            .try_into()
            .expect("session_id must be 32 bytes");

        let header = Header {
            session_id,
            protocol_id: vector.header.protocol_id,
            round: vector.header.round,
            from: vector.header.from,
            to: vector.header.to,
        };

        let payload = hex::decode(&vector.payload_hex).expect("valid payload hex");
        let expected_encoded = hex::decode(&vector.encoded_hex).expect("valid encoded hex");

        let encoded = encode(&header, &payload)
            .unwrap_or_else(|e| panic!("{}: encode failed: {e}", vector.name));
        assert_eq!(
            encoded, expected_encoded,
            "{}: encoding changed",
            vector.name
        );

        let (decoded_header, decoded_payload) = decode::<Vec<u8>>(&expected_encoded)
            .unwrap_or_else(|e| panic!("{}: decode failed: {e}", vector.name));
        assert_eq!(
            decoded_header, header,
            "{}: header decode mismatch",
            vector.name
        );
        assert_eq!(
            decoded_payload, payload,
            "{}: payload decode mismatch",
            vector.name
        );
    }
}
