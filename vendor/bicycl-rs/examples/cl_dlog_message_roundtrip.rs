use bicycl_rs::{ClDlogMessage, Context};

fn main() -> Result<(), bicycl_rs::Error> {
    let ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("1337")?;

    let prover = ctx.cl_dlog_session(&mut rng, 112)?;
    let prover = prover.prepare_statement(&ctx, &mut rng)?;
    let prover = prover.prove_round(&ctx, &mut rng)?;

    let mut stmt = ClDlogMessage::new()?;
    let mut proof = ClDlogMessage::new()?;
    prover.export_statement(&ctx, &mut stmt)?;
    prover.export_proof(&ctx, &mut proof)?;

    let stmt_bytes = stmt.to_bytes(&ctx)?;
    let proof_bytes = proof.to_bytes(&ctx)?;

    let mut stmt_rx = ClDlogMessage::new()?;
    let mut proof_rx = ClDlogMessage::new()?;
    stmt_rx.load_bytes(&ctx, &stmt_bytes)?;
    proof_rx.load_bytes(&ctx, &proof_bytes)?;

    let verifier = ctx.cl_dlog_session(&mut rng, 112)?;
    let verifier = verifier.import_statement(&ctx, &stmt_rx)?;
    let verifier = verifier.import_proof(&ctx, &proof_rx)?;

    let valid = verifier.verify_round(&ctx)?;
    println!("proof_valid={valid}");
    Ok(())
}
