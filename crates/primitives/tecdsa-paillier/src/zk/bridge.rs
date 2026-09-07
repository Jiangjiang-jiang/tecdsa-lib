// SPDX-License-Identifier: MIT OR Apache-2.0

/// Converts Ring-Pedersen parameters into the `Aux` type used by this
/// crate's ZK proofs. Both types wrap `rug::Integer`, so this is a
/// straightforward field-by-field clone.
#[must_use]
pub fn pedersen_to_aux(params: &tecdsa_pedersen_mod::PedersenModParams) -> crate::zk::pi_enc::Aux {
    crate::zk::pi_enc::Aux {
        s: params.s.clone(),
        t: params.t.clone(),
        rsa_modulo: params.n.clone(),
    }
}
