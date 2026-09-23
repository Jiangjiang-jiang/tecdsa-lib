# tecdsa-ku24

KU24: Honest-Majority Threshold ECDSA with Batch Generation of Key-Independent
Presignatures (Jonathan Katz, Antoine Urban).

Part of the [tecdsa](../../) threshold ECDSA workspace.

## What is different about this protocol

Most threshold ECDSA protocols assume a dishonest majority and generate
*key-dependent* presignatures one at a time. KU24 targets **key-management
networks** -- a fixed set of `n` servers holding shares of a large number of
keys -- and exploits the honest-majority assumption (`n >= 2t + 1`) to offer two
properties that matter in that deployment:

- **Key-independent presignatures.** A presignature is not bound to a key, so a
  network hosting `N` keys does not have to keep `N` presignatures warm. Any
  presignature can be spent under any key.
- **Batch presigning.** `m` presignatures are produced in a fixed number of
  rounds, so the amortized cost collapses as `m` grows (the paper reports
  ~1.3 ms/presignature at `m = 10 000`, against 680 ms at `m = 1` over a 50 ms
  link).

There is no MtA, no Paillier or class group, and no range proof anywhere in the
protocol -- only Shamir sharing, a PRF and elliptic-curve arithmetic.

## Phases

| Phase | Module | Rounds | Key-dependent? | Paper |
|---|---|---|---|---|
| PRSS setup (`F_rss.Init`) | `setup` | 1, point-to-point | no | Section 5 |
| Key generation | `keygen` | 1, broadcast | yes | out of scope (see below) |
| Batch presigning | `presign` | 4, broadcast | **no** | Sections 3, 4, Appendix A |
| Online signing | `sign` | 1, broadcast | yes | Section 3 |

The PRSS setup is run once, ever; it is reused for every key and every batch.

### Presigning round breakdown

1. `F_wmult` over the `2m` pairs `(k_i, a_i)` and `(r, a_i)` (`Pi_triple` step 3,
   batched into a single call).
2. `F_wmult` over the `m` pairs `(mu_i, k_i)` (`Pi_triple` step 4).
3. Open the verification values `r` and `beta` (`Pi_triple` step 5).
4. Open the batch check `T = sum_i (tau_i - r w_i) beta^i` -- abort unless
   `T = 0` -- together with `w_i = a_i k_i` and `R_i = g^{k_i}`; then set
   `k'_{i,j} = w_i^{-1} a_{i,j}` and `r_i = F(R_i)` (`Pi_triple` step 6 merged
   with `Pi_ECDSA` presigning step 4).

Following Section 4 this uses `2m + 2` random values and `3m` weak
multiplications, rather than the `3m + 1` and `4m` a generic application of
Chida et al. would need.

**The ordering of rounds 2 and 3 matters.** `r` and `beta` are available from
`F_rss` immediately, so it is tempting to broadcast them in round 1 and collapse
the phase to three rounds. That breaks Lemma 1, which requires the adversary's
additive shifts to be independent of the challenge: a rushing adversary that
learned `r` before the second `F_wmult` could choose `delta'_i = r * d_i` and
force `T = 0` with a tampered triple. Merging step 6 with `Pi_ECDSA` step 4 is
sound, however -- see the note in `presign`'s module documentation -- so the
phase still costs four rounds rather than five.

## Security model

UC-secure **with abort** against a static, rushing, malicious adversary
corrupting up to `t < n/2` parties, over private point-to-point channels. **No
broadcast channel is assumed.**

`F_wmult` is only secure up to additive attacks; Lemma 1 shows the round-3 batch
check catches any non-zero shift except with probability `(m + 1)/q`. Degree-`t`
openings (`r`, `beta`, `T`, `w_i`, `R_i`) additionally carry a Lagrange
consistency check across all `n` points, which is what detects a party sending
values off the sharing polynomial.

## Deviations from the paper

- **Key generation.** The paper leaves DKG out of scope and assumes the shares
  already exist. Since PRSS is already set up, `keygen` supplies the natural
  one-round DKG for the same model: derive `x_j <- F_rss.Rand`, broadcast
  `g^{x_j}`, and interpolate in the exponent with the degree-`t` consistency
  check.
- **No coordinator.** The paper routes signing shares to a semi-honest
  coordinator. The workspace's `StateMachine` abstraction has none, so every
  party broadcasts `(r, s_j)` and performs the coordinator's reconstruction and
  verification itself. This is equivalent -- the computation uses only public
  data and is checked against the public key.
- **Committee size cap.** PRSS needs `binomial(n, t)` replicated keys. The paper
  targets `n < 20`; this implementation rejects `n > prss::MAX_PARTIES` (16)
  rather than silently exhausting memory.

## Threshold convention

Following the rest of the workspace, `threshold` is the **reconstruction**
threshold, i.e. `t + 1` in the paper's notation. An honest majority requires
`n >= 2 * (threshold - 1) + 1`.

## Usage

See the crate-level documentation for a complete worked example, and
`tests/integration.rs` for the key-independence and batching tests.

## License

MIT OR Apache-2.0
