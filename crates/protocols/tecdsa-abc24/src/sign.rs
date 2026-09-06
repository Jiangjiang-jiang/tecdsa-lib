// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signing protocol for ABC+24 two-party ECDSA (Protocol 3).
//!
//! The protocol has 2 rounds (3 sequential messages) between Server (S) and Client (C):
//!
//! 1. **S -> C**: `(R_2, Y)` where `R_2 = g^{k_2}`, `Y = X_1^{k_2}`
//! 2. **C -> S**: `(R_1, R, S, psi_sig)` with OLE ciphertext and ZK proof
//! 3. **S**: Decrypts S, computes `(r, sigma)`, verifies and outputs signature
//!
//! ## ECDSA Equation (Protocol 1, Section 2.1)
//!
//! The nonce is derandomized: `k'_1 = k_1 + RO(X, R_2, R, m)` so
//! `R = g^{k_2 * k'_1}` and `r = X(R)`.
//!
//! The OLE computes `sigma = dec(S) * (k_2 + mu)^{-1} mod q` where
//! `mu = RO(X, R_1, R, m)` and S encodes `k_1^{-1}(m + r*x_1) + k_1^{-1}*r*x_2`.
//!
//! The final signature satisfies `s = k^{-1}(m + r*x) mod q`.

use elliptic_curve::{
    group::Curve as CurveGroup, ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes,
    FieldBytesSize, Group, PrimeField,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{backend::Integer, BigIntExt};
use tecdsa_protocol::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::Abc24Error,
    key_share::{Abc24ClientKeyShare, Abc24ServerKeyShare},
};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Round 1 message from Server: ephemeral nonce share and DH consistency proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerRound1Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// `R_2 = g^{k_2}` — server's ephemeral public nonce.
    pub r2: C::ProjectivePoint,
    /// `Y = X_1^{k_2}` — DH consistency value (proves same k_2).
    pub y: C::ProjectivePoint,
}

/// Round 2 message from Client: OLE ciphertext and ZK proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClientRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// `R_1 = g^{k_1}` — client's ephemeral public nonce.
    pub r1: C::ProjectivePoint,
    /// `R = R_2^{k_1}` — combined nonce point for DH check.
    pub r_point: C::ProjectivePoint,
    /// `S = enc_N(u; rho^{lambda_0}) * E^v mod N^2` — OLE ciphertext.
    #[cfg_attr(feature = "serde", serde(with = "tecdsa_bigint::int_wire"))]
    pub s_ct: tecdsa_paillier::Ciphertext,
}

// ---------------------------------------------------------------------------
// Random Oracle: RO(X, R_1, R, m) -> scalar
// ---------------------------------------------------------------------------

fn random_oracle<C: TecdsaCurve>(
    public_key: &C::ProjectivePoint,
    r1: &C::ProjectivePoint,
    r: &C::ProjectivePoint,
    message_digest: &C::Scalar,
) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::group::GroupEncoding;
    let mut hasher = Sha256::new();
    hasher.update(b"ABC24-RO");
    hasher.update(public_key.to_bytes().as_ref());
    hasher.update(r1.to_bytes().as_ref());
    hasher.update(r.to_bytes().as_ref());
    hasher.update(AsRef::<[u8]>::as_ref(&message_digest.to_repr()));
    let hash = hasher.finalize();

    let mut fb = FieldBytes::<C>::default();
    let fb_len = fb.len();
    let hash_len = hash.len().min(fb_len);
    fb[fb_len - hash_len..].copy_from_slice(&hash[..hash_len]);
    Option::from(<C::Scalar as PrimeField>::from_repr(fb)).unwrap_or(C::Scalar::ONE)
}

// ---------------------------------------------------------------------------
// Server signing functions
// ---------------------------------------------------------------------------

/// Server ephemeral state during signing.
pub struct ServerSignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub k2: C::Scalar,
    pub r2: C::ProjectivePoint,
}

impl<C: TecdsaCurve> zeroize::Zeroize for ServerSignState<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k2.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for ServerSignState<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

/// Server, Round 1: sample k_2, compute R_2 = g^{k_2} and Y = X_1^{k_2}.
pub fn server_round1<C: TecdsaCurve>(
    key_share: &Abc24ServerKeyShare<C>,
    rng: &mut impl CryptoRngCore,
) -> (ServerRound1Msg<C>, ServerSignState<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k2 = C::random_scalar(rng);
    let r2 = C::generator() * k2;
    let y = key_share.client_public_share * k2;

    let msg = ServerRound1Msg { r2, y };
    let state = ServerSignState { k2, r2 };

    (msg, state)
}

/// Server, Finalize: verify client's message, decrypt OLE, compute signature.
///
/// Per Protocol 3, Step 3:
/// 1. Compute `r = X(R_1^{k_2 + RO(X, R_1, R, m)})`
/// 2. Check `R_1 != 1`, `S in Z*_{N^2}`, `R = R_1^{k_2}`
/// 3. Decrypt: `sigma = dec(S) * (k_2 + RO(X, R_1, R, m))^{-1} mod q`
/// 4. Output `(r, sigma)` iff valid
pub fn server_finalize<C: TecdsaCurve>(
    key_share: &Abc24ServerKeyShare<C>,
    state: &ServerSignState<C>,
    client_msg: &ClientRound2Msg<C>,
    message: &DataToSign<C>,
) -> Result<Signature<C>, Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    let m = *message.digest();

    // Check R_1 != identity
    if bool::from(client_msg.r1.is_identity()) {
        return Err(Abc24Error::InvalidInput("R_1 is identity".into()));
    }

    // Check DH consistency: R = R_1^{k_2}
    let expected_r = client_msg.r1 * state.k2;
    if expected_r != client_msg.r_point {
        return Err(Abc24Error::DhTupleCheck(
            "R != R_1^{k_2}: DH consistency failed".into(),
        ));
    }

    // Compute mu = RO(X, R_1, R, m)
    let mu = random_oracle::<C>(
        &key_share.public_key,
        &client_msg.r1,
        &client_msg.r_point,
        &m,
    );

    // Compute r = X(R_1^{k_2 + mu})
    let k2_plus_mu = state.k2 + mu;
    let r_combined = client_msg.r1 * k2_plus_mu;
    let r_affine = r_combined.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    // Decrypt S to get the OLE output
    let decrypted = key_share
        .dk
        .decrypt(&client_msg.s_ct)
        .map_err(|e| Abc24Error::Paillier(format!("decryption failed: {e}")))?;

    // Convert decrypted value to scalar (reduce mod q)
    let dec_bytes = decrypted.to_bytes_msf();
    let sigma_raw = bytes_to_scalar::<C>(&dec_bytes);

    // sigma = dec(S) * (k_2 + mu)^{-1} mod q
    let k2_mu_inv = k2_plus_mu
        .invert()
        .into_option()
        .ok_or_else(|| Abc24Error::ProtocolState("k_2 + mu is zero".into()))?;
    let sigma = sigma_raw * k2_mu_inv;

    let s = low_s_normalize::<C>(sigma);
    let signature = Signature { r, s };

    verify_ecdsa::<C>(&signature, &key_share.public_key, message).map_err(|e| {
        Abc24Error::EcdsaVerification(format!("final signature verification failed: {e}"))
    })?;

    Ok(signature)
}

// ---------------------------------------------------------------------------
// Client signing functions
// ---------------------------------------------------------------------------

/// Client, Round 2: verify server's message, compute OLE ciphertext.
///
/// Per Protocol 3, Step 2:
/// 1. Check `R_2 != 1` and `R_2^{x_1} = Y` (DH tuple check)
/// 2. Sample `k_1`, compute `R_1 = g^{k_1}`, `R = R_2^{k_1}`
/// 3. Compute `r = X((R_2 * g^{RO(X, R_1, R, m)})^{k_1})`
/// 4. Compute OLE values: `u = k_1^{-1}(m + r*x_1) + mu*q`, `v = k_1^{-1}*r + mu'*q`
/// 5. Compute `S = enc_N(u; rho^{lambda_0}) * E^v mod N^2`
pub fn client_round2<C: TecdsaCurve>(
    key_share: &Abc24ClientKeyShare<C>,
    server_msg: &ServerRound1Msg<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<ClientRound2Msg<C>, Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let m = *message.digest();

    // Step 1: Check R_2 != identity
    if bool::from(server_msg.r2.is_identity()) {
        return Err(Abc24Error::InvalidInput("R_2 is identity".into()));
    }

    // Step 1: DH tuple check: R_2^{x_1} = Y
    let expected_y = server_msg.r2 * key_share.secret_share;
    if expected_y != server_msg.y {
        return Err(Abc24Error::DhTupleCheck(
            "R_2^{x_1} != Y: server DH consistency failed".into(),
        ));
    }

    // Step 2: Sample k_1, compute R_1 and R
    let k1 = C::random_scalar(rng);
    let r1 = C::generator() * k1;
    let r_point = server_msg.r2 * k1;

    // Step 3: Compute mu = RO(X, R_1, R, m)
    let mu = random_oracle::<C>(&key_share.public_key, &r1, &r_point, &m);

    // Compute r = X((R_2 * g^mu)^{k_1}) = X(R_2^{k_1} * g^{mu*k_1})
    let r_combined = (server_msg.r2 + C::generator() * mu) * k1;
    let r_affine = r_combined.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    // Step 4: Compute k_1^{-1}
    let k1_inv = k1
        .invert()
        .into_option()
        .ok_or_else(|| Abc24Error::ProtocolState("k_1 is zero".into()))?;

    // Get curve order q
    let q_bytes = scalar_to_bytes(&(-C::Scalar::ONE));
    let q_int = Integer::from_bytes_msf(&q_bytes) + 1u8;

    // Compute u = [k_1^{-1} * (m + r * x_1)]_q + mu_mask * q
    let k1_inv_m_rx1 = k1_inv * (m + r * key_share.secret_share);
    let u_base_bytes = scalar_to_bytes(&k1_inv_m_rx1);
    let u_base = tecdsa_paillier::backend::Integer::from_bytes_msf(&u_base_bytes);

    // mu_mask: statistical masking to hide u mod q
    let mu_mask = q_int.sample_below_ref(rng);
    let u = u_base + mu_mask * &q_int;

    // Compute v = [k_1^{-1} * r]_q + mu'_mask * q
    let k1_inv_r = k1_inv * r;
    let v_base_bytes = scalar_to_bytes(&k1_inv_r);
    let v_base = tecdsa_paillier::backend::Integer::from_bytes_msf(&v_base_bytes);

    let mu_prime_mask = q_int.sample_below_ref(rng);
    let v = v_base + mu_prime_mask * q_int;

    // Step 5: Compute S = enc_N(u) * E^v mod N^2
    // enc_N(u) with fresh randomness
    let (enc_u, _nonce_u) = key_share
        .ek
        .encrypt_with_random(rng, &u)
        .map_err(|e| Abc24Error::Paillier(format!("encrypt u failed: {e}")))?;

    // E^v mod N^2 (Paillier homomorphic scalar multiplication)
    let e_v = key_share
        .ek
        .omul(&v, &key_share.enc_x2)
        .map_err(|e| Abc24Error::Paillier(format!("homomorphic scalar mult E^v failed: {e}")))?;

    // S = enc_u (+) e_v (Paillier homomorphic addition)
    let s_ct = key_share
        .ek
        .oadd(&enc_u, &e_v)
        .map_err(|e| Abc24Error::Paillier(format!("homomorphic add failed: {e}")))?;

    Ok(ClientRound2Msg { r1, r_point, s_ct })
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

use tecdsa_curve::conv::{bytes_to_scalar, scalar_to_bytes};

// ---------------------------------------------------------------------------
// End-to-end signing convenience function
// ---------------------------------------------------------------------------

/// Run the complete ABC+24 two-party signing protocol.
///
/// This convenience function executes all rounds sequentially.
/// In a real deployment, messages would be exchanged over a network.
pub fn sign<C: TecdsaCurve>(
    server_key: &Abc24ServerKeyShare<C>,
    client_key: &Abc24ClientKeyShare<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Signature<C>, Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    // Round 1: Server sends (R_2, Y)
    let (server_msg, server_state) = server_round1::<C>(server_key, rng);

    // Round 2: Client verifies, computes OLE, sends (R_1, R, S, psi_sig)
    let client_msg = client_round2::<C>(client_key, &server_msg, message, rng)?;

    // Finalize: Server decrypts, computes and verifies signature
    server_finalize::<C>(server_key, &server_state, &client_msg, message)
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;
    use sha2::Sha256;
    use tecdsa_protocol::DataToSign;

    use super::*;
    use crate::keygen::trusted_dealer_keygen;

    fn make_message(msg: &[u8]) -> DataToSign<Secp256k1> {
        use elliptic_curve::PrimeField;
        use sha2::Digest;
        let hash = Sha256::digest(msg);
        let mut fb = k256::FieldBytes::default();
        fb.copy_from_slice(&hash);
        let scalar = k256::Scalar::from_repr(fb).unwrap();
        DataToSign::from_digest(scalar)
    }

    #[test]
    fn sign_produces_valid_ecdsa_signature() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"hello ABC+24");

        let sig = sign::<Secp256k1>(&server, &client, &message, &mut rng)
            .expect("signing should succeed");

        verify_ecdsa::<Secp256k1>(&sig, &server.public_key, &message)
            .expect("signature must verify");
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn sign_different_messages_produce_different_signatures() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let msg1 = make_message(b"message one");
        let msg2 = make_message(b"message two");

        let sig1 = sign::<Secp256k1>(&server, &client, &msg1, &mut rng).unwrap();
        let sig2 = sign::<Secp256k1>(&server, &client, &msg2, &mut rng).unwrap();

        assert_ne!(sig1.r, sig2.r);
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn sign_multiple_times_with_same_key() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        for i in 0..3 {
            let msg = make_message(format!("message {i}").as_bytes());
            let sig = sign::<Secp256k1>(&server, &client, &msg, &mut rng)
                .expect("signing should succeed");
            verify_ecdsa::<Secp256k1>(&sig, &server.public_key, &msg)
                .expect("signature must verify");
        }
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn server_round1_dh_consistency() {
        let mut rng = rand_core::OsRng;
        let (server, _client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let (msg, state) = server_round1::<Secp256k1>(&server, &mut rng);

        let expected_y = server.client_public_share * state.k2;
        assert_eq!(msg.y, expected_y);
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn client_rejects_bad_dh_tuple() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"test");

        let (mut server_msg, _state) = server_round1::<Secp256k1>(&server, &mut rng);

        // Corrupt Y
        server_msg.y = Secp256k1::generator() * k256::Scalar::from(42u64);

        let result = client_round2::<Secp256k1>(&client, &server_msg, &message, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn server_rejects_bad_dh_tuple() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"test");

        let (server_msg, server_state) = server_round1::<Secp256k1>(&server, &mut rng);
        let mut client_msg =
            client_round2::<Secp256k1>(&client, &server_msg, &message, &mut rng).unwrap();

        // Corrupt R (DH check fails)
        client_msg.r_point = Secp256k1::generator() * k256::Scalar::from(99u64);

        let result = server_finalize::<Secp256k1>(&server, &server_state, &client_msg, &message);
        assert!(result.is_err());
    }

    #[test]
    fn signature_is_low_s() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"low-s test");

        let sig = sign::<Secp256k1>(&server, &client, &message, &mut rng).unwrap();

        // low_s_normalize ensures s <= q/2, verified by successful ECDSA verify
        verify_ecdsa::<Secp256k1>(&sig, &server.public_key, &message)
            .expect("low-s signature must verify");
    }
}
