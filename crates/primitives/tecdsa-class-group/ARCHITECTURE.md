# tecdsa-class-group Architecture

This crate is a monolithic class-group primitive providing CL encryption,
threshold CL, NIM, PVSS, MtA, and ~20 ZK proofs. Short-term this is
acceptable; the API surface is internal to the workspace.

## Module Responsibilities

| Module | Role | Used by |
|--------|------|---------|
| `bicycl_glue.rs` | FFI wrapper: `ClSetup`, type re-exports from bicycl-rs | All |
| `cl_enc.rs` | CL encryption/decryption helpers (encrypt_decimal, hscmul, etc.) | TX25, JTX25, WMC24, WMY23 |
| `t_cl.rs` | Threshold CL: partial decryption, key sharing | JTX25, WMC24 |
| `nim.rs` | Non-Interactive Multiplication over class groups | LLZ25 |
| `pvss.rs` | Publicly Verifiable Secret Sharing over CL | TX25, JTX25 |
| `mta.rs` | CL-based MtA (ClMtA trait impl) | TX25, WMY23 |
| `mta_broadcast.rs` | Broadcast MtA (NimMtA, ScaledDecryptMtA) | LLZ25, Trout |
| `batch.rs` | Batch proof verification utilities | Internal |
| `matrix.rs` | Matrix ZK proof (multi-party consistency) | LLZ25 |
| `ddlog.rs` | Double discrete-log proof helpers | Trout |
| `zk/` | ~20 ZK proof modules (R_enc, R_cl_dl, R_ped_ec, ...) | All CL protocols |

## ZK Proof Inventory (zk/)

Each proof is named after its paper relation: `R_<name>`.

| Proof | Relation | Primary users |
|-------|----------|---------------|
| `r_enc` | Correct CL encryption | TX25, JTX25, WMC24 |
| `r_cl_dl` | CL discrete-log knowledge | TX25, JTX25 |
| `r_cl_dl_ec` | CL DL with EC point binding | LLZ25, Trout |
| `r_dec_dl` | Decryption with DL | JTX25 |
| `r_part_dec` | Partial decryption | JTX25 |
| `r_enc_pc` | Encryption with Pedersen commitment | WMC24 |
| `r_ped_ec` | Pedersen-EC consistency | LLZ25, Trout |
| `r_com_kwlg` | Commitment knowledge | LLZ25, Trout |
| `r_m_aff_dl` | Affine MtA with DL | TX25 |
| `r_m_aff_dl_ec` | Affine MtA with EC binding | TX25 |
| `r_el_cl` | ElGamal-CL consistency | WMC24 |
| `r_gdec_cl` | Grouped decryption | WMC24 |
| `r_aff_com` | Affine with commitment | Internal |
| `r_key` | Key validity | Internal |
| `r_bint` | Big-integer range | Internal |
| `r_ddh_cl` | DDH in CL group | Internal |
| `r_pc_dl` | Pedersen-commitment DL | Internal |
| `r_dl_cl` | DL in CL (Schnorr-style) | JTX25 |
| `r_cl_kwlg` | CL knowledge | Internal |
| `r_sh` | Share consistency | Internal |

## Dependency Direction

```
tecdsa-class-group
  depends on: tecdsa-core, tecdsa-bigint, tecdsa-curve, tecdsa-protocol, bicycl-rs
  depended on by: TX25, JTX25, WMC24, WMY23, LLZ25, Trout
```

## License

MIT OR Apache-2.0

## Future Consideration

If APIs stabilize, consider splitting into:
- `tecdsa-cl-core` (bicycl_glue + cl_enc + t_cl)
- `tecdsa-cl-zk` (all ZK proofs)
- `tecdsa-nim` (NIM + mta_broadcast + matrix)

Not recommended until external consumers need stable sub-APIs.
