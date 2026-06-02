//! Demonstrates the threshold (t-of-n) ECDSA signing protocol.
//!
//! Threshold ECDSA allows a group of `n` players to jointly hold an ECDSA
//! signing key such that any `t + 1` players can produce a valid signature,
//! but no group of `t` or fewer players can.
//!
//! The protocol proceeds in two phases:
//!
//! **Key generation** (3 rounds):
//! 1. `keygen_round1` — each player commits to their share
//! 2. `keygen_round2` — players exchange commitments
//! 3. `keygen_finalize` — compute the shared public key
//!
//! **Signing** (8 rounds + finalize):
//! 1–8. Interactive signing protocol across all participating players
//! 9. `sign_finalize` — assemble and verify the final signature
//!
//! The typestate API ensures each round is called in the correct order at
//! compile time — calling a round out-of-order is a type error.
//!
//! Parameters used here are intentionally small for a quick demonstration.
//! Production deployments should use a higher security level.
//!
//! Run with:
//! ```bash
//! cargo run -p bicycl-rs --example threshold_ecdsa
//! ```
use bicycl_rs::Context;

fn main() -> Result<(), bicycl_rs::Error> {
    let ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("42")?;

    // Parameters:
    //   seclevel    = 112  (security level in bits; use 128+ for production)
    //   n_players   = 3    (total number of key-share holders)
    //   threshold_t = 2    (must satisfy threshold_t < n_players; the protocol
    //                       is secure against up to threshold_t corruptions)
    let seclevel: u32 = 112;
    let n_players: u32 = 3;
    let threshold_t: u32 = 2;

    let message = b"Hello, threshold ECDSA!";

    println!("Threshold ECDSA  seclevel={seclevel}  n={n_players}  t={threshold_t}");
    println!("Message: {:?}", std::str::from_utf8(message).unwrap());

    // ── Key generation ────────────────────────────────────────────────────────
    println!("\n-- Key generation --");

    let session = ctx
        .threshold_ecdsa_session(&mut rng, seclevel, n_players, threshold_t)?
        .keygen_round1(&ctx, &mut rng)?;
    println!("  keygen_round1 done");

    let session = session.keygen_round2(&ctx, &mut rng)?;
    println!("  keygen_round2 done");

    let session = session.keygen_finalize(&ctx)?;
    println!("  keygen_finalize done — shared public key established");

    // ── Signing ───────────────────────────────────────────────────────────────
    println!("\n-- Signing --");

    let session = session.sign_round1(&ctx, &mut rng, message)?;
    println!("  sign_round1 done");

    let session = session.sign_round2(&ctx, &mut rng)?;
    println!("  sign_round2 done");

    let session = session.sign_round3(&ctx)?;
    println!("  sign_round3 done");

    let session = session.sign_round4(&ctx)?;
    println!("  sign_round4 done");

    let session = session.sign_round5(&ctx, &mut rng)?;
    println!("  sign_round5 done");

    let session = session.sign_round6(&ctx, &mut rng)?;
    println!("  sign_round6 done");

    let session = session.sign_round7(&ctx, &mut rng)?;
    println!("  sign_round7 done");

    let session = session.sign_round8(&ctx)?;
    println!("  sign_round8 done");

    let session = session.sign_finalize(&ctx)?;
    println!("  sign_finalize done");

    // ── Verification ──────────────────────────────────────────────────────────
    let valid = session.signature_valid(&ctx)?;
    println!("\nSignature valid: {valid}");
    assert!(valid, "threshold ECDSA signature should be valid");

    println!("Threshold ECDSA protocol completed successfully.");
    Ok(())
}
