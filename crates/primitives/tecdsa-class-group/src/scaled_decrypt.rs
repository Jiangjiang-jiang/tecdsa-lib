use crate::{
    cl::{ClCiphertext, ClPublicKey, ClResult, ClSetup, Qfi},
    zk::r_aff_com::RAffComProof,
};

pub struct ScaledDecryptPartyInput {
    pub alpha_i: Vec<u8>,
    pub beta_i: Vec<u8>,
    pub b_i: Vec<u8>,
}

pub struct ScaledDecryptPublic {
    pub a1: Qfi,
    pub a2: Qfi,
    pub b_agg: Qfi,
}

pub struct ScaledDecryptShare {
    pub f_i: Qfi,
    pub pi_aff_com: Option<RAffComProof>,
}

pub fn compute_f_share(
    setup: &ClSetup,
    input: &ScaledDecryptPartyInput,
    public: &ScaledDecryptPublic,
) -> ClResult<Qfi> {
    let f_i = setup.multiexp_signed_bytes(
        &[&public.a2, &public.a1, &public.b_agg],
        &[
            (false, input.b_i.clone()),
            (false, input.beta_i.clone()),
            (true, input.alpha_i.clone()),
        ],
    )?;
    Ok(f_i)
}

pub fn compute_f_share_with_proof(
    setup: &mut ClSetup,
    cl_pk: &ClPublicKey,
    input: &ScaledDecryptPartyInput,
    public: &ScaledDecryptPublic,
    ct_in: &ClCiphertext,
    u_com_i: &Qfi,
) -> ClResult<ScaledDecryptShare> {
    let f_i = compute_f_share(setup, input, public)?;

    let identity = setup.identity()?;
    let ct_out = setup.ct_from_components(&identity, &f_i)?;

    let pi_aff_com = RAffComProof::prove(
        setup,
        cl_pk,
        ct_in,
        &ct_out,
        u_com_i,
        &input.b_i,
        &[0u8],
        &input.alpha_i,
        &input.beta_i,
    )?;

    Ok(ScaledDecryptShare {
        f_i,
        pi_aff_com: Some(pi_aff_com),
    })
}

pub fn aggregate_and_solve(setup: &ClSetup, f_shares: &[Qfi]) -> ClResult<Vec<u8>> {
    let id = setup.identity()?;
    let mut f_agg = id;
    for fi in f_shares {
        f_agg = setup.compose(&f_agg, fi)?;
    }
    setup.dlog_in_F_bytes(&f_agg)
}

pub fn aggregate_ciphertext_components(
    setup: &ClSetup,
    components: &[(Qfi, Qfi)],
) -> ClResult<(Qfi, Qfi)> {
    let mut a1 = setup.identity()?;
    let mut a2 = setup.identity()?;
    for (c1, c2) in components {
        a1 = setup.compose(&a1, c1)?;
        a2 = setup.compose(&a2, c2)?;
    }
    Ok((a1, a2))
}

pub fn aggregate_commitments(setup: &ClSetup, commitments: &[Qfi]) -> ClResult<Qfi> {
    let id = setup.identity()?;
    let mut b = id;
    for bj in commitments {
        b = setup.compose(&b, bj)?;
    }
    Ok(b)
}

pub fn scaled_decrypt_local(
    setup: &ClSetup,
    inputs: &[ScaledDecryptPartyInput],
    public: &ScaledDecryptPublic,
) -> ClResult<Vec<u8>> {
    let f_shares: Vec<Qfi> = inputs
        .iter()
        .map(|input| compute_f_share(setup, input, public))
        .collect::<ClResult<Vec<_>>>()?;
    aggregate_and_solve(setup, &f_shares)
}
