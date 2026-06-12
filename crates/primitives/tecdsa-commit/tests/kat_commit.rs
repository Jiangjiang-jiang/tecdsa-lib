use sha2::{Digest, Sha256};

#[test]
fn kat_hash_commitment_sha256() {
    let nonce = [0u8; 32];
    let message = b"tecdsa-kat";

    let hash: [u8; 32] = Sha256::new()
        .chain_update(nonce)
        .chain_update(message)
        .finalize()
        .into();

    let actual_hex = hex::encode(hash);

    let expected = "260d31dc13e577cfbbbeebd66ba09aa11d7bfd13157a2ffe76973aeca8f8e7da";
    assert_eq!(
        actual_hex, expected,
        "SHA-256(nonce || message) has changed"
    );
}
