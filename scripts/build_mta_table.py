#!/usr/bin/env python3
"""Generate the rows of tab:mta (per-instance MtA conversion cost).

Combines two measured sources, mirroring build_twoparty_table.py:

  * MtA (ms)   -- the TOTAL sender + receiver time of one MtA conversion,
                  i.e. the SUM of every per-phase criterion benchmark in the
                  backend's `mta/<variant>` group (point estimate: slope when
                  criterion sampled linearly, otherwise mean), ns -> ms. Read
                  from target/criterion/**/{new,base}/{benchmark.json,
                  estimates.json}; the most recent run (new/) wins. When a
                  backend's ZK proof is NOT embedded in the cycle (CL's
                  R_{CL-Enc}), that proof's `<id>/prove` + `<id>/verify` time
                  -- benched in the `zk/<...>` group, the same source as
                  build_zk_table.py -- is added on top.

  * Comm.\\ (KB) -- the per-instance communication, measured SEPARATELY for the
                  sender and the receiver by the `protocol_once` binary
                  (mta_once) and reported here as their SUM. Serializable
                  messages (Paillier/CGGMP20, JL, RVOLE) are sized via the
                  orchestrator's bincode config; CL/NIM class-group elements via
                  their native to_bytes. Read from target/comm_online/*.tsv
                  (every file merged, newest wins per key). A separately-measured
                  accompanying proof (CL's R_{CL-Enc}) additionally contributes
                  its serialized size from target/zk_sizes/*.tsv (the
                  build_zk_table.py source); a declared-but-unmeasured proof
                  leaves the cell "--".

Each backend's MtA cycle embeds exactly the security mechanism named in the
table's ZK-proof column:
  PL (GG18)    : Alice/Bob range proofs (R_MtA-A, R_MtA-B)  -- in the cycle
  PL (CGGMP20) : pi_enc + pi_aff-g       (R_enc, R_aff-g)   -- in the cycle
  CL           : WMY23 MtAwc check (g^alpha) + R_{CL-Enc}   -- proof added on top
  JL           : ZkJlEnc + ZkJlAff       (R_JL-enc, R_JL-aff) -- in the cycle
  NIM          : R_Ped (RPedEcProof, LLZ25)                 -- prove + verify
  OT (VOLE)    : none (RVOLE soft-spoken OT consistency)    -- /

Formatting matches build_twoparty_table.py: ms values > 1 are rounded to 5
significant figures, <= 1 keep 4 decimals; KB to 5 sig figs (>1) / 4 decimals.

Output: the complete LaTeX rows for tab:mta. Cells are "--" until measured.
"""

import json
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

CRITERION_DIR = Path("target/criterion")
COMM_DIR = Path("target/comm_online")
ZK_SIZES_DIR = Path("target/zk_sizes")
SCAFFOLD = "--"

# (slug, Backend label, ZK-proof column, [criterion phase function ids],
#  [accompanying ZK proof-ids measured OUTSIDE the mta cycle]).
# MtA (ms) sums every phase (the measured sender + receiver work of one
# conversion); for any accompanying proof-id it ALSO adds that proof's
# `<id>/prove` + `<id>/verify` time. Comm. (KB) likewise adds each accompanying
# proof's serialized size (from target/zk_sizes). Each proof-id is both the
# criterion group base (`<id>/{prove,verify}`) and the zk_once size key
# (`<id>`), exactly as in build_zk_table.py. Backends whose proof is already
# embedded in the cycle (PL, JL) or measured as an mta phase (NIM's r_ped) keep
# an empty list -- those costs are already in the per-phase sums.
ROWS = [
    ("paillier", "PL (GG18)", r"$\mathcal{R}_\text{MtA-A},\mathcal{R}_\text{MtA-B}$",
     ["sender_encrypt", "receiver_compute", "sender_decrypt"], []),
    ("cggmp20", "PL (CGGMP20)", r"$\mathcal{R}_\text{enc},\mathcal{R}_\text{aff-g}$",
     ["sender_encrypt", "receiver_compute", "sender_decrypt"], []),
    # CL: the conversion runs the WMY23-style MtAwc check (g^alpha gen + verify);
    # malicious security additionally needs R_{CL-Enc} (correct CL encryption,
    # `zk/class_group/r_enc`), which is NOT part of the mta cycle, so its
    # prove+verify time and serialized size are added on top here.
    ("cl", "CL", r"$\mathcal{R}_\text{CL-Enc}$",
     ["sender_encrypt", "receiver_compute_with_check", "sender_decrypt", "verify_check"],
     ["zk/class_group/r_enc"]),
    ("jl", "JL", r"$\mathcal{R}_\text{JL-enc},\mathcal{R}_\text{JL-aff}$",
     ["sender_encrypt", "receiver_compute", "sender_decrypt"], []),
    ("nim", "NIM", r"$\mathcal{R}_\text{Ped}$",
     ["encode_a", "encode_b", "r_ped/prove", "r_ped/verify", "decode_a", "decode_b"], []),
    # RVOLE's interactive phases consume their state (sender_compute cannot be
    # isolated -- its bench re-runs init+respond), so the complete conversion is
    # measured by the single `full_cycle` bench (init+respond+compute+finish).
    # This equals sum-of-phases for the others: e.g. paillier sum 180.44 ms vs
    # its full_cycle 180.55 ms.
    ("rvole", "OT (VOLE)", r"/", ["full_cycle"], []),
]


def pick_estimate_ns(estimates: dict) -> float:
    slope = estimates.get("slope")
    est = slope if slope else estimates["mean"]
    return est["point_estimate"]


def load_all(root: Path) -> dict:
    """full_id -> point estimate in ns (prefer the most recent run, new/)."""
    found = {}  # full_id -> (is_new, ns)
    for bench_json in root.rglob("benchmark.json"):
        run_dir = bench_json.parent.name
        if run_dir not in ("new", "base"):
            continue
        est_path = bench_json.parent / "estimates.json"
        if not est_path.exists():
            continue
        full_id = json.loads(bench_json.read_text())["full_id"]
        ns = pick_estimate_ns(json.loads(est_path.read_text()))
        is_new = run_dir == "new"
        if full_id not in found or (is_new and not found[full_id][0]):
            found[full_id] = (is_new, ns)
    return {fid: ns for fid, (_, ns) in found.items()}


def load_comm(comm_dir: Path) -> dict:
    """Merge protocol_once's per-process comm TSVs ('<key>\\t<bytes>')."""
    out = {}
    if comm_dir.is_dir():
        for f in sorted(comm_dir.glob("*.tsv"), key=lambda p: p.stat().st_mtime):
            for line in f.read_text().splitlines():
                if "\t" not in line:
                    continue
                key, val = line.rsplit("\t", 1)
                try:
                    out[key] = int(val)
                except ValueError:
                    pass
    return out


def load_sizes(size_dir: Path) -> dict:
    """Merge zk_once's per-process proof-size TSVs ('<proof-id>\\t<bytes>').

    Same format/merge as load_comm and as build_zk_table.py: every *.tsv is
    read oldest-first so the newest run wins per key.
    """
    out = {}
    if size_dir.is_dir():
        for f in sorted(size_dir.glob("*.tsv"), key=lambda p: p.stat().st_mtime):
            for line in f.read_text().splitlines():
                if "\t" not in line:
                    continue
                key, val = line.rsplit("\t", 1)
                try:
                    out[key] = int(val)
                except ValueError:
                    pass
    return out


def fmt(v) -> str:
    """5 significant figures for v > 1; 4 decimals for v <= 1."""
    if v is None:
        return SCAFFOLD
    if abs(v) > 1:
        d = Decimal(repr(v))
        quant = Decimal(1).scaleb(d.adjusted() - 4)  # 5 sig figs
        return str(d.quantize(quant, rounding=ROUND_HALF_UP))
    return f"{v:.4f}"


def main():
    data = load_all(CRITERION_DIR)
    comm = load_comm(COMM_DIR)
    sizes = load_sizes(ZK_SIZES_DIR)

    def mta_ms(slug, phases, zk_proofs):
        total = 0.0
        for ph in phases:
            fid = f"mta/{slug}/{ph}"
            if fid not in data:
                return None  # incomplete -> scaffold
            total += data[fid]
        # Accompanying proofs measured outside the cycle (e.g. CL's R_{CL-Enc}):
        # add prove + verify, from the same zk_proofs group as build_zk_table.py.
        for pid in zk_proofs:
            for op in ("prove", "verify"):
                fid = f"{pid}/{op}"
                if fid not in data:
                    return None  # incomplete -> scaffold
                total += data[fid]
        return total * 1e-6

    def comm_kb(slug, zk_proofs):
        s = comm.get(f"mta/{slug}/sender")
        r = comm.get(f"mta/{slug}/receiver")
        # Add the serialized size of each accompanying proof (e.g. R_{CL-Enc}).
        # A declared-but-unmeasured proof makes the whole cell incomplete.
        proof_bytes = 0
        for pid in zk_proofs:
            if pid not in sizes:
                return None  # run `zk_once` to record this proof's size
            proof_bytes += sizes[pid]
        if s is None and r is None and not zk_proofs:
            return None
        return ((s or 0) + (r or 0) + proof_bytes) / 1024.0

    label_w = max(len(label) for _, label, *_ in ROWS)
    zk_w = max(len(zk) for _, _, zk, *_ in ROWS)
    for slug, label, zk, phases, zk_proofs in ROWS:
        ms = fmt(mta_ms(slug, phases, zk_proofs))
        kb = fmt(comm_kb(slug, zk_proofs))
        print(f"{label:<{label_w}} & {zk:<{zk_w}} & {ms:>9} & {kb:>9} \\\\")


if __name__ == "__main__":
    if not CRITERION_DIR.is_dir():
        sys.exit(f"error: {CRITERION_DIR} not found (run from repo root)")
    main()
