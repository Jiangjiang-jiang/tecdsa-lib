use bicycl_rs::Context;

fn main() -> Result<(), bicycl_rs::Error> {
    let ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("1337")?;

    let session = ctx.two_party_ecdsa_session(&mut rng, 112)?;
    let session = session.keygen_round1(&ctx, &mut rng)?;
    let session = session.keygen_round2(&ctx, &mut rng)?;
    let session = session.keygen_round3(&ctx, &mut rng)?;
    let session = session.keygen_round4(&ctx)?;

    let session = session.sign_round1(&ctx, &mut rng, b"abc")?;
    let session = session.sign_round2(&ctx, &mut rng)?;
    let session = session.sign_round3(&ctx)?;
    let session = session.sign_round4(&ctx, &mut rng)?;

    let (_session, valid) = session.sign_finalize(&ctx)?;
    println!("signature_valid={valid}");
    Ok(())
}
