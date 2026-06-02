// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state struct and logic for DKLs23 online signing (Round 4, 1 round).
//!
//! Each party computes:
//!   u_i = r_i * (phi_i + sum_j psi_{j,i}) + sum_j (c^u_{i,j} + d^u_{j,i})
//!   v_i = sk_i * (phi_i + sum_j psi_{j,i}) + sum_j (c^v_{i,j} + d^v_{j,i})
//!   w_i = H(m) * phi_i + r_x * v_i
//!
//! After collecting all (u_j, w_j), the signature is:
//!   s = sum(w_j) * sum(u_j)^{-1} mod q

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    low_s_normalize, verify_ecdsa, DataToSign, Outgoing, PartyId, Recipient, Signature,
};

use zeroize::Zeroize;

use crate::presign::Dkls23Presignature;
use crate::sign::msg::{Dkls23SignMsg, SignR4Broadcast};
use crate::utils::validate_sender;

// ---------------------------------------------------------------------------
// Round enum
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) enum OnlineSignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round4(Round4State<C>),
    Done(Signature<C>),
    #[default]
    Gone,
}

// ---------------------------------------------------------------------------
// Online signing configuration
// ---------------------------------------------------------------------------

/// Configuration for a DKLs23 online signing session.
pub struct OnlineSignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The presignature from the presigning phase.
    pub presignature: Dkls23Presignature<C>,
    /// The message digest to sign (as a scalar).
    pub message: DataToSign<C>,
}

// ---------------------------------------------------------------------------
// Round 4: compute (u_i, w_i), broadcast, assemble signature
// ---------------------------------------------------------------------------

pub(crate) struct Round4State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    signer_parties: Vec<PartyId>,
    message: DataToSign<C>,
    public_key: C::ProjectivePoint,
    r_x: C::Scalar,
    u_i: C::Scalar,
    w_i: C::Scalar,
    pub outgoing: Vec<Outgoing<Dkls23SignMsg<C>>>,
    round4_msgs: BTreeMap<PartyId, SignR4Broadcast<C>>,
}

impl<C: TecdsaCurve> Round4State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create the Round 4 state from a presignature and message.
    pub fn new(config: OnlineSignConfig<C>) -> Self {
        let presig = config.presignature;
        let message = config.message;
        let m = *message.digest();

        // Compute phi_i + sum_j(psi_{j,i})
        let mut mask_sum = presig.phi_i;
        for &psi_ji in presig.received_psi.values() {
            mask_sum += psi_ji;
        }

        // Compute sum_j(c^u_{i,j} + d^u_{j,i}) and sum_j(c^v_{i,j} + d^v_{j,i})
        //
        // For each counterparty j:
        //   rvole_data[j].c_u is c^u_{i,j} (our sender-side nonce share)
        //   rvole_data[j].d_u is d^u_{j,i} (our receiver-side nonce share)
        let mut cu_du_sum = C::Scalar::ZERO;
        let mut cv_dv_sum = C::Scalar::ZERO;
        for data in presig.rvole_data.values() {
            cu_du_sum = cu_du_sum + data.c_u + data.d_u;
            cv_dv_sum = cv_dv_sum + data.c_v + data.d_v;
        }

        // u_i = r_i * mask_sum + cu_du_sum
        let u_i = presig.r_i * mask_sum + cu_du_sum;

        // v_i = sk_i * mask_sum + cv_dv_sum
        let v_i = presig.sk_i * mask_sum + cv_dv_sum;

        // w_i = m * phi_i + r_x * v_i
        //
        // Correctness: sum(w_i) = m * phi + r_x * (phi * sk) = phi * (m + r_x * sk)
        // and sum(u_i) = k * phi, so s = sum(w_i)/sum(u_i) = k^{-1}(m + r_x * sk).
        // Note: w_i uses phi_i (NOT mask_sum) because the m-term reconstructs
        // via sum(phi_i) and the RVOLE cross-terms cancel in v_i.
        let w_i = m * presig.phi_i + presig.r_x * v_i;

        // Clone heap-allocated fields before presig is dropped (ZeroizeOnDrop).
        // Scalar/point fields are Copy so they are extracted directly.
        let my_id = presig.my_id;
        let signer_parties = presig.signer_parties.clone();
        let public_key = presig.key_share.public_key;
        let r_x = presig.r_x;

        // Broadcast (u_i, w_i)
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Dkls23SignMsg::Round4Broadcast(SignR4Broadcast { u_i, w_i }),
        }];

        Self {
            my_id,
            signer_parties,
            message,
            public_key,
            r_x,
            u_i,
            w_i,
            outgoing,
            round4_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignR4Broadcast<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.signer_parties)?;
        if self.round4_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round4_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round4_msgs.len() == self.expected_count()
    }

    /// Assemble and verify the final ECDSA signature.
    pub fn finish(mut self) -> tecdsa_core::Result<Signature<C>>
    where
        C::ProjectivePoint:
            elliptic_curve::ops::LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        // Collect all u_i and w_i
        let mut u_sum = self.u_i;
        let mut w_sum = self.w_i;
        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }
            let msg = &self.round4_msgs[&pid];
            u_sum += msg.u_i;
            w_sum += msg.w_i;
        }

        // s = sum(w_j) * sum(u_j)^{-1} mod q
        let u_inv = u_sum
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::InvalidShare("u_sum is zero, cannot invert".into()))?;
        let s = w_sum * u_inv;

        // Low-S normalization (BIP-146)
        let s = low_s_normalize::<C>(s);

        let sig = Signature { r: self.r_x, s };

        // Final ECDSA verification
        verify_ecdsa::<C>(&sig, &self.public_key, &self.message)?;

        // Zeroize partial signature shares
        self.u_i.zeroize();
        self.w_i.zeroize();

        Ok(sig)
    }
}
