// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-time, key-independent PRSS setup -- the `Init` interface of `F_rss`.
//!
//! This is the dealer-free key distribution of Section 5: for every subset
//! `A subset [n]` with `|A| = n - t`, the member of `A` with the smallest index
//! is the designated dealer `P*_A`; it samples `k_A` uniformly and sends it to
//! the other members of `A` over their private point-to-point channels.
//!
//! Prior work assumed a trusted dealer or ran a heavyweight key-agreement
//! protocol.  The paper's observation is that neither is needed:
//!
//! * `k_H`, the key of the honest set `H`, is dealt by an honest party, so it is
//!   uniform, unknown to the adversary and consistent -- and that single key is
//!   what makes all PRSS outputs pseudorandom.
//! * For any `A` that contains a corrupted party the adversary learns `k_A`
//!   anyway, even with a trusted dealer.
//! * A corrupted dealer can equivocate, but the honest parties' shares still lie
//!   on a polynomial of the right degree, so `F_rss` is still realised.
//!
//! Consequently the phase is a **single round of point-to-point messages** with
//! no commitments, no complaint resolution and no broadcast channel.
//!
//! The resulting [`crate::prss::PrssKeys`] is key-independent and long-lived: it
//! is reused for every ECDSA key and every presignature batch.

pub mod machine;
pub mod msg;

pub use machine::Ku25SetupMachine;
pub use msg::{KeyEntry, Ku25SetupMsg};

#[cfg(test)]
mod tests {
    use k256::{Scalar, Secp256k1};
    use tecdsa_protocol::PartyId;

    use super::*;
    use crate::{interp::Interp, prss::PrssKeys};

    fn run(n: u16, threshold: u16) -> Vec<PrssKeys<Secp256k1>> {
        let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let machines: Vec<(PartyId, Ku25SetupMachine<Secp256k1>)> = parties
            .iter()
            .map(|&pid| {
                (
                    pid,
                    Ku25SetupMachine::new(pid, parties.clone(), threshold).expect("setup machine"),
                )
            })
            .collect();
        tecdsa_testkit::Orchestrator::new(machines, 4)
            .run()
            .expect("setup must succeed")
            .into_iter()
            .map(|r| r.expect("setup output"))
            .collect()
    }

    #[test]
    fn setup_gives_every_party_the_right_number_of_keys() {
        let keys = run(5, 3);
        // binomial(n - 1, t) = binomial(4, 2) = 6.
        for k in &keys {
            assert_eq!(k.key_count(), 6);
        }
    }

    #[test]
    fn setup_keys_are_replicated_consistently() {
        let (n, threshold) = (5u16, 3u16);
        let keys = run(n, threshold);
        let session = [42u8; 32];
        let indices: Vec<u16> = (1..=n).collect();

        let rand_interp = Interp::<Secp256k1>::new(&indices, usize::from(threshold - 1));
        let shares: Vec<Scalar> = keys.iter().map(|k| k.rand(&session, 0, 1)[0]).collect();
        assert!(
            rand_interp.scalar(&shares).is_some(),
            "PRSS shares must be degree-t consistent"
        );

        let zero_interp = Interp::<Secp256k1>::new(&indices, 2 * usize::from(threshold - 1));
        let zeros: Vec<Scalar> = keys.iter().map(|k| k.zero(&session, 0, 1)[0]).collect();
        assert_eq!(zero_interp.scalar(&zeros), Some(Scalar::ZERO));
    }

    #[test]
    fn setup_works_for_seven_parties() {
        let keys = run(7, 4);
        // binomial(6, 3) = 20.
        for k in &keys {
            assert_eq!(k.key_count(), 20);
        }
    }

    #[test]
    fn setup_rejects_dishonest_majority() {
        let parties: Vec<PartyId> = (1..=5).map(PartyId).collect();
        assert!(Ku25SetupMachine::<Secp256k1>::new(PartyId(1), parties, 4).is_err());
    }
}
