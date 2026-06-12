#[test]
fn paillier_zk_reexports_compile() {
    let _ = std::mem::size_of::<
        tecdsa_paillier::zk::paillier_zk::paillier_encryption_in_range::NiProof,
    >();
    let _ = std::mem::size_of::<
        tecdsa_paillier::zk::paillier_zk::paillier_encryption_in_range::Proof,
    >();

    let _ = std::mem::size_of::<
        tecdsa_paillier::zk::paillier_zk::paillier_affine_operation_in_range::Proof,
    >();

    let _ =
        std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::paillier_blum_modulus::NiProof<33>>();
    let _ =
        std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::paillier_blum_modulus::Commitment>();

    let _ = std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::no_small_factor::NiProof>();
    let _ = std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::no_small_factor::Proof>();

    let _ = std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::no_small_factor::Aux>();

    let zero = tecdsa_paillier::zk::paillier_zk::backend::Integer::from(0);
    assert_eq!(
        zero,
        tecdsa_paillier::zk::paillier_zk::backend::Integer::from(0)
    );

    let _ = std::any::type_name::<tecdsa_paillier::zk::paillier_zk::InvalidProof>();
    let _ = std::any::type_name::<tecdsa_paillier::zk::paillier_zk::BadExponent>();
    let _ = std::any::type_name::<tecdsa_paillier::zk::paillier_zk::PaillierError>();
}
