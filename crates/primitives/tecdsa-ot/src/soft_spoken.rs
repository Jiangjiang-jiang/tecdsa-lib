use elliptic_curve::{ops::Reduce, CurveArithmetic, FieldBytes, PrimeField};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::base_ot::OtError;

pub const KAPPA: u16 = 256;

const BASE_SECURITY: u16 = 128;

pub const STAT_SECURITY: u16 = 80;

pub const OT_SECURITY: u16 = BASE_SECURITY + STAT_SECURITY;

pub const BATCH_SIZE: u16 = KAPPA + 2 * STAT_SECURITY;

pub const EXTENDED_BATCH_SIZE: u16 = BATCH_SIZE + OT_SECURITY;

const HASH_LEN: usize = 32;

pub type PrgOutput = [u8; (EXTENDED_BATCH_SIZE / 8) as usize];

pub type FieldElement = [u8; (OT_SECURITY / 8) as usize];

pub type HashOutput = [u8; HASH_LEN];

const PRG_DATA_SIZE: usize = (EXTENDED_BATCH_SIZE / 8) as usize;

pub(crate) mod serde_prg_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::PRG_DATA_SIZE;

    pub fn serialize<S>(data: &Vec<[u8; PRG_DATA_SIZE]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let flat: Vec<u8> = data.iter().flat_map(|a| a.iter().copied()).collect();
        flat.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; PRG_DATA_SIZE]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let flat: Vec<u8> = Vec::deserialize(deserializer)?;
        flat.chunks(PRG_DATA_SIZE)
            .map(|chunk| {
                let arr: [u8; PRG_DATA_SIZE] =
                    chunk.try_into().map_err(serde::de::Error::custom)?;
                Ok(arr)
            })
            .collect()
    }
}

const TAG_OTE_PRG: &[u8] = b"tecdsa/ot/extension/prg/v1";
const TAG_OTE_CHI: &[u8] = b"tecdsa/ot/extension/chi/v1";
const TAG_OTE_RANDOMIZE: &[u8] = b"tecdsa/ot/extension/randomize/v1";
const TAG_OTE_INIT: &[u8] = b"tecdsa/ot/extension/init/v1";

pub(crate) fn tagged_hash(tag: &[u8], components: &[&[u8]]) -> HashOutput {
    let mut encoded =
        Vec::with_capacity(8 + tag.len() + components.iter().map(|c| 8 + c.len()).sum::<usize>());
    append_len_prefixed(&mut encoded, tag);
    for component in components {
        append_len_prefixed(&mut encoded, component);
    }
    let digest = Sha256::digest(&encoded);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

fn append_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_be_bytes());
    buf.extend_from_slice(data);
}

pub(crate) fn tagged_hash_as_scalar<C: CurveArithmetic>(
    tag: &[u8],
    components: &[&[u8]],
) -> C::Scalar
where
    C::Scalar: Reduce<FieldBytes<C>>,
{
    let hash = tagged_hash(tag, components);
    let fb_len = FieldBytes::<C>::default().len();
    let field_bytes =
        FieldBytes::<C>::try_from(&hash[..fb_len]).expect("hash length matches field byte length");
    <C::Scalar as Reduce<FieldBytes<C>>>::reduce(&field_bytes)
}

pub(crate) fn scalar_to_bytes<C: CurveArithmetic>(scalar: &C::Scalar) -> Vec<u8>
where
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let fb: FieldBytes<C> = (*scalar).into();
    AsRef::<[u8]>::as_ref(&fb).to_vec()
}

pub(crate) fn random_scalar<C: CurveArithmetic>(rng: &mut impl CryptoRngCore) -> C::Scalar
where
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    loop {
        let mut bytes = FieldBytes::<C>::default();
        rng.fill_bytes(&mut bytes);
        if let Some(s) = Option::from(<C::Scalar as PrimeField>::from_repr(bytes)) {
            if !bool::from(elliptic_curve::Field::is_zero(&s)) {
                return s;
            }
        }
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct OtExtensionSender {
    pub correlation: Vec<bool>,
    pub seeds: Vec<HashOutput>,
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct OtExtensionReceiver {
    pub seeds0: Vec<HashOutput>,
    pub seeds1: Vec<HashOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OteDataToSender {
    #[serde(with = "serde_prg_vec")]
    pub u: Vec<PrgOutput>,
    pub verify_x: FieldElement,
    pub verify_t: Vec<FieldElement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OteInitSenderMsg {
    pub blinded_keys: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OteInitReceiverMsg {
    pub encrypted_seeds: Vec<([u8; 32], [u8; 32])>,
}

impl OtExtensionSender {
    pub fn init(session_id: &[u8], rng: &mut impl CryptoRngCore) -> (Self, OteInitSenderMsg) {
        let mut correlation = Vec::with_capacity(KAPPA as usize);
        for _ in 0..KAPPA {
            correlation.push(rng.next_u32() & 1 == 1);
        }

        let mut seeds = Vec::with_capacity(KAPPA as usize);
        let mut blinded_keys = Vec::with_capacity(KAPPA as usize);

        for i in 0..KAPPA {
            let mut nonce = [0u8; 32];
            rng.fill_bytes(&mut nonce);

            let i_bytes = i.to_be_bytes();
            let choice_byte = u8::from(correlation[i as usize]);

            let seed = tagged_hash(
                TAG_OTE_INIT,
                &[session_id, &i_bytes, &[choice_byte], &nonce],
            );
            seeds.push(seed);

            let mut key_data = Vec::with_capacity(35);
            key_data.extend_from_slice(&i_bytes);
            key_data.push(choice_byte);
            key_data.extend_from_slice(&nonce);
            blinded_keys.push(key_data);
        }

        let sender = OtExtensionSender { correlation, seeds };
        let msg = OteInitSenderMsg { blinded_keys };
        (sender, msg)
    }

    pub fn from_seeds(correlation: Vec<bool>, seeds: Vec<HashOutput>) -> Self {
        OtExtensionSender { correlation, seeds }
    }

    #[allow(clippy::type_complexity)]
    pub fn run<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        ot_width: u8,
        input_correlations: &[Vec<C::Scalar>],
        data: &OteDataToSender,
    ) -> Result<(Vec<Vec<C::Scalar>>, Vec<Vec<C::Scalar>>), OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        if input_correlations.len() != ot_width as usize {
            return Err(OtError(
                "input_correlations length does not match ot_width".into(),
            ));
        }
        for corr in input_correlations {
            if corr.len() != BATCH_SIZE as usize {
                return Err(OtError(
                    "correlation vector has incorrect inner length".into(),
                ));
            }
        }
        if self.correlation.len() != KAPPA as usize || self.seeds.len() != KAPPA as usize {
            return Err(OtError("OTE sender state has incorrect dimensions".into()));
        }
        if data.u.len() != KAPPA as usize || data.verify_t.len() != KAPPA as usize {
            return Err(OtError("OTE data has incorrect dimensions".into()));
        }

        let extended_seeds = self.extend_seeds(session_id);

        let q = compute_q(&self.correlation, &extended_seeds, &data.u);

        let (chi1, chi2) = derive_chi(session_id, &data.u);

        let verify_q = compute_verify_vector(&q, &chi1, &chi2)?;

        let verify_sender: Vec<FieldElement> = (0..KAPPA as usize)
            .map(|i| {
                let mut v = [0u8; (OT_SECURITY / 8) as usize];
                for k in 0..(OT_SECURITY / 8) as usize {
                    v[k] = data.verify_t[i][k] ^ (u8::from(self.correlation[i]) * data.verify_x[k]);
                }
                v
            })
            .collect();

        let consistent = verify_q
            .iter()
            .zip(verify_sender.iter())
            .fold(subtle::Choice::from(1u8), |acc, (a, b)| acc & a.ct_eq(b));
        if !bool::from(consistent) {
            return Err(OtError(
                "Receiver cheated in OTE: Consistency check failed!".into(),
            ));
        }

        let transposed_q = cut_and_transpose(&q)?;

        let compressed_correlation = compress_bits(&self.correlation, KAPPA as usize);

        let mut vector_of_v0: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        let mut vector_of_v1: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let mut v0: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            let mut v1: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                let mut tq_plus_corr = [0u8; (KAPPA / 8) as usize];
                for k in 0..(KAPPA / 8) as usize {
                    tq_plus_corr[k] = transposed_q[j as usize][k] ^ compressed_correlation[k];
                }

                let j_bytes = j.to_be_bytes();
                let iter_bytes = iteration.to_be_bytes();

                v0.push(tagged_hash_as_scalar::<C>(
                    TAG_OTE_RANDOMIZE,
                    &[session_id, &j_bytes, &iter_bytes, &transposed_q[j as usize]],
                ));
                v1.push(tagged_hash_as_scalar::<C>(
                    TAG_OTE_RANDOMIZE,
                    &[session_id, &j_bytes, &iter_bytes, &tq_plus_corr],
                ));
            }
            vector_of_v0.push(v0);
            vector_of_v1.push(v1);
        }

        let mut vector_of_tau: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let v0 = &vector_of_v0[iteration as usize];
            let v1 = &vector_of_v1[iteration as usize];
            let corr = &input_correlations[iteration as usize];

            let tau: Vec<C::Scalar> = (0..BATCH_SIZE as usize)
                .map(|j| v1[j] - v0[j] + corr[j])
                .collect();
            vector_of_tau.push(tau);
        }

        Ok((vector_of_v0, vector_of_tau))
    }

    fn extend_seeds(&self, session_id: &[u8]) -> Vec<PrgOutput> {
        let mut extended = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            extended.push(prg_expand(session_id, i, &self.seeds[i as usize]));
        }
        extended
    }
}

impl OtExtensionReceiver {
    pub fn init(session_id: &[u8], sender_msg: &OteInitSenderMsg) -> Result<Self, OtError> {
        if sender_msg.blinded_keys.len() != KAPPA as usize {
            return Err(OtError("init message has wrong number of keys".into()));
        }

        let mut seeds0 = Vec::with_capacity(KAPPA as usize);
        let mut seeds1 = Vec::with_capacity(KAPPA as usize);

        for key_data in &sender_msg.blinded_keys {
            if key_data.len() < 35 {
                return Err(OtError("malformed blinded key data".into()));
            }
            let i_bytes = &key_data[0..2];
            let nonce = &key_data[3..35];

            let s0 = tagged_hash(TAG_OTE_INIT, &[session_id, i_bytes, &[0u8], nonce]);
            let s1 = tagged_hash(TAG_OTE_INIT, &[session_id, i_bytes, &[1u8], nonce]);
            seeds0.push(s0);
            seeds1.push(s1);
        }

        Ok(OtExtensionReceiver { seeds0, seeds1 })
    }

    pub fn from_seeds(seeds0: Vec<HashOutput>, seeds1: Vec<HashOutput>) -> Self {
        OtExtensionReceiver { seeds0, seeds1 }
    }

    pub fn run_phase1(
        &self,
        session_id: &[u8],
        choice_bits: &[bool],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<PrgOutput>, OteDataToSender), OtError> {
        if choice_bits.len() != BATCH_SIZE as usize {
            return Err(OtError("choice_bits has incorrect length".into()));
        }
        if self.seeds0.len() != KAPPA as usize || self.seeds1.len() != KAPPA as usize {
            return Err(OtError(
                "OTE receiver seed vectors have incorrect dimensions".into(),
            ));
        }

        let mut random_bits = Vec::with_capacity(OT_SECURITY as usize);
        for _ in 0..OT_SECURITY {
            random_bits.push(rng.next_u32() & 1 == 1);
        }
        let extended_choice_bits: Vec<bool> =
            choice_bits.iter().copied().chain(random_bits).collect();

        let compressed_extended =
            compress_bits(&extended_choice_bits, EXTENDED_BATCH_SIZE as usize);

        let mut extended_seeds0 = Vec::with_capacity(KAPPA as usize);
        let mut extended_seeds1 = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            extended_seeds0.push(prg_expand(session_id, i, &self.seeds0[i as usize]));
            extended_seeds1.push(prg_expand(session_id, i, &self.seeds1[i as usize]));
        }

        let mut u: Vec<PrgOutput> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA as usize {
            let mut u_i = [0u8; (EXTENDED_BATCH_SIZE / 8) as usize];
            for j in 0..(EXTENDED_BATCH_SIZE / 8) as usize {
                u_i[j] = extended_seeds0[i][j] ^ extended_seeds1[i][j] ^ compressed_extended[j];
            }
            u.push(u_i);
        }

        let (chi1, chi2) = derive_chi(session_id, &u);

        let prod_x_1 = field_mul(&compressed_extended[0..(OT_SECURITY / 8) as usize], &chi1)?;
        let prod_x_2 = field_mul(
            &compressed_extended[(OT_SECURITY / 8) as usize..(2 * OT_SECURITY / 8) as usize],
            &chi2,
        )?;

        let mut verify_x = [0u8; (OT_SECURITY / 8) as usize];
        for k in 0..(OT_SECURITY / 8) as usize {
            verify_x[k] =
                prod_x_1[k] ^ prod_x_2[k] ^ compressed_extended[(2 * OT_SECURITY / 8) as usize + k];
        }

        let mut verify_t: Vec<FieldElement> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA as usize {
            let prod_ti_1 = field_mul(&extended_seeds0[i][0..(OT_SECURITY / 8) as usize], &chi1)?;
            let prod_ti_2 = field_mul(
                &extended_seeds0[i][(OT_SECURITY / 8) as usize..(2 * OT_SECURITY / 8) as usize],
                &chi2,
            )?;

            let mut verify_ti = [0u8; (OT_SECURITY / 8) as usize];
            for k in 0..(OT_SECURITY / 8) as usize {
                verify_ti[k] = prod_ti_1[k]
                    ^ prod_ti_2[k]
                    ^ extended_seeds0[i][(2 * OT_SECURITY / 8) as usize + k];
            }
            verify_t.push(verify_ti);
        }

        let data_to_sender = OteDataToSender {
            u,
            verify_x,
            verify_t,
        };

        Ok((extended_seeds0, data_to_sender))
    }

    pub fn run_phase2<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        ot_width: u8,
        choice_bits: &[bool],
        extended_seeds: &[PrgOutput],
        vector_of_tau: &[Vec<C::Scalar>],
    ) -> Result<Vec<Vec<C::Scalar>>, OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        if choice_bits.len() != BATCH_SIZE as usize {
            return Err(OtError("choice_bits has incorrect length".into()));
        }
        if extended_seeds.len() != KAPPA as usize {
            return Err(OtError(
                "extended seed matrix has incorrect dimensions".into(),
            ));
        }
        if vector_of_tau.len() != ot_width as usize {
            return Err(OtError("tau vector count does not match ot_width".into()));
        }
        for tau in vector_of_tau {
            if tau.len() != BATCH_SIZE as usize {
                return Err(OtError("tau vector has incorrect inner length".into()));
            }
        }

        let transposed_t = cut_and_transpose(extended_seeds)?;

        let mut vector_of_v: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let mut v: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                let j_bytes = j.to_be_bytes();
                let iter_bytes = iteration.to_be_bytes();
                v.push(tagged_hash_as_scalar::<C>(
                    TAG_OTE_RANDOMIZE,
                    &[session_id, &j_bytes, &iter_bytes, &transposed_t[j as usize]],
                ));
            }
            vector_of_v.push(v);
        }

        let mut vector_of_t_b: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let v = &vector_of_v[iteration as usize];
            let tau = &vector_of_tau[iteration as usize];

            let t_b: Vec<C::Scalar> = (0..BATCH_SIZE as usize)
                .map(|j| {
                    let mut t_b_j = -v[j];
                    if choice_bits[j] {
                        t_b_j = tau[j] + t_b_j;
                    }
                    t_b_j
                })
                .collect();
            vector_of_t_b.push(t_b);
        }

        Ok(vector_of_t_b)
    }
}

fn prg_expand(session_id: &[u8], index: u16, seed: &HashOutput) -> PrgOutput {
    let mut prg_bytes: Vec<u8> = Vec::with_capacity((EXTENDED_BATCH_SIZE / 8) as usize + HASH_LEN);
    let i_bytes = index.to_be_bytes();
    let mut count = 0u16;
    while prg_bytes.len() < (EXTENDED_BATCH_SIZE / 8) as usize {
        let count_bytes = count.to_be_bytes();
        count += 1;
        let chunk = tagged_hash(TAG_OTE_PRG, &[session_id, &i_bytes, &count_bytes, seed]);
        prg_bytes.extend_from_slice(&chunk);
    }
    let mut output = [0u8; (EXTENDED_BATCH_SIZE / 8) as usize];
    output.copy_from_slice(&prg_bytes[..(EXTENDED_BATCH_SIZE / 8) as usize]);
    output
}

fn compute_q(
    correlation: &[bool],
    extended_seeds: &[PrgOutput],
    u: &[PrgOutput],
) -> Vec<PrgOutput> {
    let mut q = Vec::with_capacity(KAPPA as usize);
    for i in 0..KAPPA as usize {
        let mut q_i = [0u8; (EXTENDED_BATCH_SIZE / 8) as usize];
        for j in 0..(EXTENDED_BATCH_SIZE / 8) as usize {
            q_i[j] = (u8::from(correlation[i]) * u[i][j]) ^ extended_seeds[i][j];
        }
        q.push(q_i);
    }
    q
}

fn derive_chi(session_id: &[u8], u: &[PrgOutput]) -> (FieldElement, FieldElement) {
    let msg: Vec<u8> = u.iter().flat_map(|row| row.iter().copied()).collect();

    let mut chi1 = [0u8; (OT_SECURITY / 8) as usize];
    let mut chi2 = [0u8; (OT_SECURITY / 8) as usize];

    let hash1 = tagged_hash(TAG_OTE_CHI, &[session_id, b"chi1", &msg]);
    chi1.copy_from_slice(&hash1[..(OT_SECURITY / 8) as usize]);

    let hash2 = tagged_hash(TAG_OTE_CHI, &[session_id, b"chi2", &msg]);
    chi2.copy_from_slice(&hash2[..(OT_SECURITY / 8) as usize]);

    (chi1, chi2)
}

fn compute_verify_vector(
    q: &[PrgOutput],
    chi1: &FieldElement,
    chi2: &FieldElement,
) -> Result<Vec<FieldElement>, OtError> {
    let mut verify_q = Vec::with_capacity(KAPPA as usize);
    for i in 0..KAPPA as usize {
        let prod1 = field_mul(&q[i][0..(OT_SECURITY / 8) as usize], chi1)?;
        let prod2 = field_mul(
            &q[i][(OT_SECURITY / 8) as usize..(2 * OT_SECURITY / 8) as usize],
            chi2,
        )?;

        let mut v = [0u8; (OT_SECURITY / 8) as usize];
        for k in 0..(OT_SECURITY / 8) as usize {
            v[k] = prod1[k] ^ prod2[k] ^ q[i][(2 * OT_SECURITY / 8) as usize + k];
        }
        verify_q.push(v);
    }
    Ok(verify_q)
}

fn compress_bits(bits: &[bool], expected_len: usize) -> Vec<u8> {
    assert!(bits.len() >= expected_len);
    let byte_len = expected_len / 8;
    let mut compressed = Vec::with_capacity(byte_len);
    for i in 0..byte_len {
        let mut byte = 0u8;
        for bit_idx in 0..8 {
            byte |= u8::from(bits[i * 8 + bit_idx]) << bit_idx;
        }
        compressed.push(byte);
    }
    compressed
}

pub fn cut_and_transpose(input: &[PrgOutput]) -> Result<Vec<HashOutput>, OtError> {
    if input.len() != KAPPA as usize {
        return Err(OtError(
            "transpose: input matrix has incorrect dimensions".into(),
        ));
    }

    let mut output: Vec<HashOutput> = vec![[0u8; (KAPPA / 8) as usize]; BATCH_SIZE as usize];

    for row_byte in 0..(KAPPA / 8) as usize {
        for row_bit_within_byte in 0..8u16 {
            for column_byte in 0..(BATCH_SIZE / 8) as usize {
                for column_bit_within_byte in 0..8u16 {
                    let row_bit = (row_byte as u16) * 8 + row_bit_within_byte;
                    let column_bit = (column_byte as u16) * 8 + column_bit_within_byte;

                    let entry =
                        (input[row_bit as usize][column_byte] >> column_bit_within_byte) & 0x01;

                    let shifted_entry = entry << row_bit_within_byte;
                    output[column_bit as usize][row_byte] |= shifted_entry;
                }
            }
        }
    }

    Ok(output)
}

pub fn field_mul(left: &[u8], right: &[u8]) -> Result<FieldElement, OtError> {
    const W: u8 = 64;
    const T: u8 = 4;

    if left.len() != (OT_SECURITY / 8) as usize || right.len() != (OT_SECURITY / 8) as usize {
        return Err(OtError(
            "binary field multiplication: entries have incorrect length".into(),
        ));
    }

    let mut a = [0u64; T as usize];
    let mut b = [0u64; (T + 1) as usize];
    let mut c = [0u64; (2 * T) as usize];

    for i in 0..(OT_SECURITY / 8) as usize {
        a[i >> 3] |= u64::from(left[i]) << ((i & 0x07) << 3);
        b[i >> 3] |= u64::from(right[i]) << ((i & 0x07) << 3);
    }

    for k in 0..W {
        for j in 0..T {
            if (a[j as usize] >> k) % 2 == 1 {
                for i in 0..=T {
                    c[(j + i) as usize] ^= b[i as usize];
                }
            }
        }
        if k != W - 1 {
            for i in (1..=T).rev() {
                b[i as usize] = b[i as usize] << 1 | b[(i - 1) as usize] >> 63;
            }
        }
        b[0] <<= 1;
    }

    for i in (T..(2 * T)).rev() {
        let t = c[i as usize];
        c[(i - 4) as usize] ^= (t << 57) ^ (t << 51) ^ (t << 49) ^ (t << 48);
        c[(i - 3) as usize] ^= (t >> 7) ^ (t >> 13) ^ (t >> 15) ^ (t >> 16);
        c[i as usize] = 0;
    }
    let t = c[(T - 1) as usize] >> 16;
    c[0] ^= (t << 9) ^ (t << 3) ^ (t << 1) ^ t;
    c[(T - 1) as usize] &= 0xFFFF;

    let mut result = [0u8; (OT_SECURITY / 8) as usize];
    for i in 0..(OT_SECURITY / 8) as usize {
        result[i] =
            u8::try_from((c[i >> 3] >> ((i & 0x07) << 3)) & 0xFF).expect("value fits in u8");
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use elliptic_curve::{CurveArithmetic, Field};
    use k256::Secp256k1;
    use rand_core::{OsRng, RngCore};

    use super::*;

    type Scalar = <Secp256k1 as CurveArithmetic>::Scalar;

    #[test]
    fn field_mul_frobenius() {
        let mut rng = OsRng;
        for _ in 0..50 {
            let mut elem = [0u8; (OT_SECURITY / 8) as usize];
            rng.fill_bytes(&mut elem);

            let mut result = elem;
            for _ in 0..OT_SECURITY {
                result = field_mul(&result, &result).expect("field_mul should succeed");
            }
            assert_eq!(elem, result, "x^(2^208) must equal x in GF(2^208)");
        }
    }

    #[test]
    fn field_mul_rejects_wrong_length() {
        let short = [0u8; (OT_SECURITY / 8 - 1) as usize];
        let exact = [0u8; (OT_SECURITY / 8) as usize];
        assert!(field_mul(&short, &exact).is_err());
    }

    #[test]
    fn transpose_rejects_wrong_dimensions() {
        let bad = vec![[0u8; (EXTENDED_BATCH_SIZE / 8) as usize]; KAPPA as usize - 1];
        assert!(cut_and_transpose(&bad).is_err());
    }

    #[test]
    fn ote_roundtrip() {
        let mut rng = OsRng;
        let session_id = b"test-ote-roundtrip";

        let (ote_sender, init_msg) = OtExtensionSender::init(session_id, &mut rng);
        let ote_receiver =
            OtExtensionReceiver::init(session_id, &init_msg).expect("init should succeed");

        let ot_width: u8 = 4;

        let mut sender_correlations: Vec<Vec<Scalar>> = Vec::with_capacity(ot_width as usize);
        for _ in 0..ot_width {
            let mut corr = Vec::with_capacity(BATCH_SIZE as usize);
            for _ in 0..BATCH_SIZE {
                corr.push(random_scalar::<Secp256k1>(&mut rng));
            }
            sender_correlations.push(corr);
        }

        let mut choice_bits = Vec::with_capacity(BATCH_SIZE as usize);
        for _ in 0..BATCH_SIZE {
            choice_bits.push(rng.next_u32() & 1 == 1);
        }

        let (extended_seeds, data_to_sender) = ote_receiver
            .run_phase1(session_id, &choice_bits, &mut rng)
            .expect("receiver phase1 should succeed");

        let (sender_outputs, tau) = ote_sender
            .run::<Secp256k1>(session_id, ot_width, &sender_correlations, &data_to_sender)
            .expect("sender run should succeed");

        let receiver_outputs = ote_receiver
            .run_phase2::<Secp256k1>(session_id, ot_width, &choice_bits, &extended_seeds, &tau)
            .expect("receiver phase2 should succeed");

        for iteration in 0..ot_width as usize {
            for j in 0..BATCH_SIZE as usize {
                let sum = sender_outputs[iteration][j] + receiver_outputs[iteration][j];
                if choice_bits[j] {
                    assert_eq!(
                        sum, sender_correlations[iteration][j],
                        "choice=1: sum should equal correlation at iter={iteration}, j={j}"
                    );
                } else {
                    assert_eq!(
                        sum,
                        <Scalar as Field>::ZERO,
                        "choice=0: sum should be zero at iter={iteration}, j={j}"
                    );
                }
            }
        }
    }

    #[test]
    fn ote_sender_rejects_tampered_u() {
        let mut rng = OsRng;
        let session_id = b"test-tamper-u";

        let (ote_sender, init_msg) = OtExtensionSender::init(session_id, &mut rng);
        let ote_receiver =
            OtExtensionReceiver::init(session_id, &init_msg).expect("init should succeed");

        let mut choice_bits = Vec::with_capacity(BATCH_SIZE as usize);
        for _ in 0..BATCH_SIZE {
            choice_bits.push(rng.next_u32() & 1 == 1);
        }

        let (_, mut data_to_sender) = ote_receiver
            .run_phase1(session_id, &choice_bits, &mut rng)
            .expect("receiver phase1 should succeed");

        data_to_sender.u[0][0] ^= 1;

        let mut correlations = Vec::with_capacity(1);
        let mut corr = Vec::with_capacity(BATCH_SIZE as usize);
        for _ in 0..BATCH_SIZE {
            corr.push(random_scalar::<Secp256k1>(&mut rng));
        }
        correlations.push(corr);

        let result = ote_sender.run::<Secp256k1>(session_id, 1, &correlations, &data_to_sender);
        assert!(
            result.is_err(),
            "tampered U should cause verification failure"
        );
        let err = result.unwrap_err();
        assert!(
            err.0.contains("Consistency check failed"),
            "error should mention consistency check, got: {}",
            err.0
        );
    }

    #[test]
    fn ote_receiver_rejects_wrong_choice_bits_len() {
        let mut rng = OsRng;
        let session_id = b"test-wrong-len";

        let (_, init_msg) = OtExtensionSender::init(session_id, &mut rng);
        let ote_receiver =
            OtExtensionReceiver::init(session_id, &init_msg).expect("init should succeed");

        let wrong_bits = vec![false; BATCH_SIZE as usize - 1];
        let result = ote_receiver.run_phase1(session_id, &wrong_bits, &mut rng);
        assert!(result.is_err());
    }
}
