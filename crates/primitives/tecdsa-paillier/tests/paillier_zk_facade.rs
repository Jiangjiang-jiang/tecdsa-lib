// SPDX-License-Identifier: MIT OR Apache-2.0
/// Compile-surface test: verify that upstream paillier-zk proof types are
/// available through the `tecdsa_paillier::zk::paillier_zk` facade.
/// This does NOT exercise prove/verify logic.
#[test]
fn paillier_zk_reexports_compile() {
    // Pi_enc (paillier encryption in range)
    let _ = std::mem::size_of::<
        tecdsa_paillier::zk::paillier_zk::paillier_encryption_in_range::NiProof,
    >();
    let _ = std::mem::size_of::<
        tecdsa_paillier::zk::paillier_zk::paillier_encryption_in_range::Proof,
    >();

    // Pi_aff_g (affine operation in range)
    let _ = std::mem::size_of::<
        tecdsa_paillier::zk::paillier_zk::paillier_affine_operation_in_range::Proof,
    >();

    // Pi_mod (Blum modulus)
    let _ =
        std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::paillier_blum_modulus::NiProof<33>>();
    let _ =
        std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::paillier_blum_modulus::Commitment>();

    // Pi_fac (no small factor)
    let _ = std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::no_small_factor::NiProof>();
    let _ = std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::no_small_factor::Proof>();

    // Aux (ring-Pedersen parameters)
    let _ = std::mem::size_of::<tecdsa_paillier::zk::paillier_zk::no_small_factor::Aux>();

    // backend::Integer
    let zero = tecdsa_paillier::zk::paillier_zk::backend::Integer::from(0);
    assert_eq!(
        zero,
        tecdsa_paillier::zk::paillier_zk::backend::Integer::from(0)
    );

    // Error types
    let _ = std::any::type_name::<tecdsa_paillier::zk::paillier_zk::InvalidProof>();
    let _ = std::any::type_name::<tecdsa_paillier::zk::paillier_zk::BadExponent>();
    let _ = std::any::type_name::<tecdsa_paillier::zk::paillier_zk::PaillierError>();
}
