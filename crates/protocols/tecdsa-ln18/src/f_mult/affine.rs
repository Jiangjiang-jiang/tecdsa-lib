use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::{elgamal_exp::EgexpCiphertext, TecdsaCurve};
use tecdsa_protocol::PartyId;

pub struct AffineInput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub ciphertext: EgexpCiphertext<C>,
    pub a_i: C::Scalar,
    pub s_i: C::Scalar,
    pub per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
}

pub struct AffineOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub ciphertext: EgexpCiphertext<C>,
    pub a_i: C::Scalar,
    pub s_i: C::Scalar,
    pub per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
}

pub fn affine<C: TecdsaCurve>(
    input: AffineInput<C>,
    x: &C::Scalar,
    y: &C::Scalar,
    n: u16,
) -> AffineOutput<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let g = C::generator();

    let n_scalar = scalar_from_u16::<C>(n);
    let n_inv: C::Scalar = {
        let ct_opt = n_scalar.invert();
        let opt: Option<C::Scalar> = ct_opt.into();
        opt.expect("n must be invertible in the scalar field")
    };
    let y_over_n = *y * n_inv;

    let ciphertext = EgexpCiphertext::<C> {
        a: input.ciphertext.a * x,
        b: input.ciphertext.b * x + g * y,
    };

    let per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)> = input
        .per_party_cts
        .iter()
        .map(|(pid, ct)| {
            let new_ct = EgexpCiphertext::<C> {
                a: ct.a * x,
                b: ct.b * x + g * y_over_n,
            };
            (*pid, new_ct)
        })
        .collect();

    let a_i = input.a_i * x + y_over_n;

    let s_i = *x * input.s_i;

    AffineOutput {
        ciphertext,
        a_i,
        s_i,
        per_party_cts,
    }
}

fn scalar_from_u16<C: TecdsaCurve>(val: u16) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut bytes = FieldBytes::<C>::default();
    let len = bytes.len();
    bytes[len - 2] = (val >> 8) as u8;
    bytes[len - 1] = val as u8;
    Option::from(<C::Scalar as PrimeField>::from_repr(bytes))
        .expect("small u16 value must be representable as a scalar")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[test]
    #[cfg(feature = "secp256k1")]
    fn affine_basic() {
        use crate::f_mult::{init::InitState, input::InputState};

        let mut rng = rand::thread_rng();
        let n: usize = 3;
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        let mut init_states: Vec<InitState<C>> = Vec::with_capacity(n);
        let mut r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = InitState::<C>::new(parties[i], parties.clone(), &mut rng);
            init_states.push(state);
            r1_msgs.push(msg);
        }

        let mut r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = init_states[i]
                .handle_round1(&others)
                .expect("init Round-1 should succeed");
            r2_msgs.push(r2);
        }

        let mut init_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = init_states[i]
                .finish_round2(&others)
                .expect("init Round-2 should succeed");
            init_outputs.push(output);
        }

        let elgamal_pk = init_outputs[0].elgamal_pk;

        let shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
        let mut input_r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.clone(), elgamal_pk, shares[i], &mut rng);
            input_states.push(state);
            input_r1_msgs.push(msg);
        }

        let mut input_r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = input_states[i]
                .handle_round1(&others)
                .expect("input Round-1 should succeed");
            input_r2_msgs.push(r2);
        }

        let mut input_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = input_states[i]
                .finish_round2(&others)
                .expect("input Round-2 should succeed");
            input_outputs.push(output);
        }

        let x = scalar_from_u16::<C>(2);
        let y = scalar_from_u16::<C>(3);

        let mut affine_outputs: Vec<AffineOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let aff_input = AffineInput::<C> {
                ciphertext: input_outputs[i].ciphertext.clone(),
                a_i: input_outputs[i].a_i,
                s_i: input_outputs[i].s_i,
                per_party_cts: input_outputs[i].per_party_cts.clone(),
            };
            let output = affine::<C>(aff_input, &x, &y, n as u16);
            affine_outputs.push(output);
        }

        let ct0 = &affine_outputs[0].ciphertext;
        for output in &affine_outputs[1..] {
            assert_eq!(
                output.ciphertext, *ct0,
                "all parties must agree on the affine-transformed ciphertext"
            );
        }

        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, d| acc + d)
            .unwrap();

        let decrypted = ct0.decrypt_to_point(&d);
        let a_sum: <C as elliptic_curve::CurveArithmetic>::Scalar =
            shares.iter().copied().reduce(|acc, s| acc + s).unwrap();
        let expected_val = a_sum * x + y;
        let expected_point = C::generator() * expected_val;
        assert_eq!(
            decrypted, expected_point,
            "affine-transformed ciphertext must decrypt to (a*x + y) * G"
        );

        let share_sum: <C as elliptic_curve::CurveArithmetic>::Scalar = affine_outputs
            .iter()
            .map(|o| o.a_i)
            .reduce(|acc, s| acc + s)
            .unwrap();
        assert_eq!(
            share_sum, expected_val,
            "sum of updated shares must equal a*x + y"
        );

        for i in 0..n {
            let expected_s = x * input_outputs[i].s_i;
            assert_eq!(
                affine_outputs[i].s_i, expected_s,
                "updated randomness must equal x * s_i"
            );
        }

        for output in &affine_outputs {
            assert_eq!(
                output.per_party_cts.len(),
                n,
                "should have n per-party ciphertexts"
            );
        }
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn affine_identity() {
        use elliptic_curve::Field;

        use crate::f_mult::{init::InitState, input::InputState};

        let mut rng = rand::thread_rng();
        let n: usize = 2;
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        let mut init_states: Vec<InitState<C>> = Vec::with_capacity(n);
        let mut r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = InitState::<C>::new(parties[i], parties.clone(), &mut rng);
            init_states.push(state);
            r1_msgs.push(msg);
        }

        let mut r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = init_states[i].handle_round1(&others).unwrap();
            r2_msgs.push(r2);
        }

        let mut init_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = init_states[i].finish_round2(&others).unwrap();
            init_outputs.push(output);
        }

        let elgamal_pk = init_outputs[0].elgamal_pk;

        let shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
        let mut input_r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.clone(), elgamal_pk, shares[i], &mut rng);
            input_states.push(state);
            input_r1_msgs.push(msg);
        }

        let mut input_r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = input_states[i].handle_round1(&others).unwrap();
            input_r2_msgs.push(r2);
        }

        let mut input_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = input_states[i].finish_round2(&others).unwrap();
            input_outputs.push(output);
        }

        let x = <<C as elliptic_curve::CurveArithmetic>::Scalar as Field>::ONE;
        let y = <<C as elliptic_curve::CurveArithmetic>::Scalar as Field>::ZERO;

        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, d| acc + d)
            .unwrap();

        let original_decrypted = input_outputs[0].ciphertext.decrypt_to_point(&d);

        let aff_input = AffineInput::<C> {
            ciphertext: input_outputs[0].ciphertext.clone(),
            a_i: input_outputs[0].a_i,
            s_i: input_outputs[0].s_i,
            per_party_cts: input_outputs[0].per_party_cts.clone(),
        };
        let output = affine::<C>(aff_input, &x, &y, n as u16);
        let new_decrypted = output.ciphertext.decrypt_to_point(&d);

        assert_eq!(
            original_decrypted, new_decrypted,
            "identity affine transformation should not change the plaintext"
        );
    }
}
