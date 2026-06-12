use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

#[derive(Debug)]
pub struct NimStateA {
    pub r_bytes: Vec<u8>,
    pub x_bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct NimStateB {
    pub s_bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct NimEncodeAOutput {
    pub pe_a: Qfi,
    pub state: NimStateA,
}

pub struct NimEncodeBOutput {
    pub pe_b: ClHsmqkCiphertext,
    pub state: NimStateB,
}

impl std::fmt::Debug for NimEncodeBOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NimEncodeBOutput").finish_non_exhaustive()
    }
}

pub struct Nim<'a> {
    setup: &'a mut ClSetup,
}

impl<'a> Nim<'a> {
    pub fn new(setup: &'a mut ClSetup) -> Self {
        Self { setup }
    }

    pub fn encode_a(
        &mut self,
        x_bytes: &[u8],
        pk: &ClHsmqkPublicKey,
    ) -> ClResult<NimEncodeAOutput> {
        let r_bytes = sample_randomness(self.setup)?;

        let h_r = self.setup.power_of_h_bytes(&r_bytes)?;
        let pk_x = self.setup.pk_pow_bytes(&pk, x_bytes)?;
        let pe_a = self.setup.compose(&h_r, &pk_x)?;

        Ok(NimEncodeAOutput {
            pe_a,
            state: NimStateA {
                r_bytes,
                x_bytes: x_bytes.to_vec(),
            },
        })
    }

    pub fn encode_b(
        &mut self,
        y_bytes: &[u8],
        pk: &ClHsmqkPublicKey,
    ) -> ClResult<NimEncodeBOutput> {
        let s_bytes = sample_randomness(self.setup)?;

        let pe_b = self.setup.encrypt_with_r_bytes(pk, y_bytes, &s_bytes)?;

        Ok(NimEncodeBOutput {
            pe_b,
            state: NimStateB { s_bytes },
        })
    }

    pub fn decode_a(&self, pe_b: &ClHsmqkCiphertext, state: &NimStateA) -> ClResult<Vec<u8>> {
        let (c1, c2) = self.setup.ct_components(pe_b)?;

        let z_a_raw = self
            .setup
            .multiexp_bytes(&[&c1, &c2], &[state.r_bytes.clone(), state.x_bytes.clone()])?;

        extract_f_component(self.setup, &z_a_raw, false)
    }

    pub fn decode_b(&self, pe_a: &Qfi, state: &NimStateB) -> ClResult<Vec<u8>> {
        let z_b_raw = self.setup.exp_bytes(pe_a, &state.s_bytes)?;

        extract_f_component(self.setup, &z_b_raw, true)
    }
}

#[allow(non_snake_case)]
fn extract_f_component(setup: &ClSetup, z: &Qfi, negate: bool) -> ClResult<Vec<u8>> {
    let mut h_label = setup.cl().to_cl_delta_k(z);
    setup.cl().from_cl_delta_k_to_cl_delta(&mut h_label);

    let f_component = if negate {
        let mut z_inv = z.clone();
        z_inv.neg();
        setup.compose(&h_label, &z_inv)?
    } else {
        h_label.neg();
        setup.compose(z, &h_label)?
    };

    #[allow(non_snake_case)]
    setup.dlog_in_F_bytes(&f_component)
}

fn sample_randomness(setup: &mut ClSetup) -> ClResult<Vec<u8>> {
    let (sk, _pk) = setup.keygen()?;
    setup.sk_to_bytes(&sk)
}

#[cfg(test)]
mod tests {
    use rug::{integer::Order, Integer};
    use tecdsa_bigint::mul_mod;

    use super::*;

    #[test]
    #[allow(clippy::similar_names)]
    fn nim_smoke() {
        let mut setup = ClSetup::new_secp256k1("42").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = &7u32.to_be_bytes();
        let y = &11u32.to_be_bytes();

        let mut nim = Nim::new(&mut setup);

        let encode_a = nim.encode_a(x, &pk).expect("encode_a");

        let encode_b = nim.encode_b(y, &pk).expect("encode_b");

        let share_a_bytes = nim
            .decode_a(&encode_b.pe_b, &encode_a.state)
            .expect("decode_a");

        let share_b_bytes = nim
            .decode_b(&encode_a.pe_a, &encode_b.state)
            .expect("decode_b");

        let q = Integer::from_digits(&setup.q_bytes().unwrap(), Order::Msf);
        let z_a = Integer::from_digits(&share_a_bytes, Order::Msf);
        let z_b = Integer::from_digits(&share_b_bytes, Order::Msf);
        let x_val = Integer::from(7u32);
        let y_val = Integer::from(11u32);
        let xy = mul_mod(&x_val, &y_val, &q);
        let sum = Integer::from(&z_a + &z_b) % &q;

        assert_eq!(sum, xy, "NIM correctness: z_A + z_B != x*y mod q");
    }
}
