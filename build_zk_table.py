#!/usr/bin/env python3
"""Generate the rows of tab:zk-impl (ZK proofs on the protocols' critical path).

Mirrors build_mta_table.py: two measured sources, nothing hand-entered.

  * Prove (ms) / Verify (ms) -- criterion point estimates (slope when sampled
    linearly, else mean), ns -> ms, from the `zk_proofs` benches under
    target/criterion/**/{new,base}/{benchmark.json,estimates.json}; newest run
    (new/) wins.

  * Size (KB) -- the serialized proof size recorded once by the `zk_once`
    binary into target/zk_sizes/*.tsv (`<proof-id>\\t<bytes>`). serde proofs are
    sized with the orchestrator's bincode config; the CL R_Ped proof (a Qfi)
    via its native to_bytes -- the same conventions as tab:mta's comm column.
    Every *.tsv is merged (newest file wins per key).

Each table row names one or two ZK proofs; the cell is the SUM over the named
proofs (so a two-proof row is the total prove/verify/size of that MtA's
proofs), consistent with how the MtA conversions are reported in tab:mta.

The row -> proof-id mapping below is the only configuration; all numbers are
read from the measured artifacts. Cells are "--" until measured.

Run order to (re)populate the artifacts:
    cargo bench -p tecdsa-bench --bench primitives      # not needed here
    cargo bench -p tecdsa-bench --bench zk_proofs       # Prove/Verify (slow)
    cargo run  -p tecdsa-bench --bin   zk_once          # Size (fast, one-shot)
    python3 build_zk_table.py
"""

import json
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

CRITERION_DIR = Path("target/criterion")
ZK_SIZES_DIR = Path("target/zk_sizes")
SCAFFOLD = "--"

# Sections of tab:zk-impl. Each row is
#   (name LaTeX, statement, [proof-ids], cite-key)
# where each proof-id is both the criterion group (<id>/prove, <id>/verify) and
# the zk_once size key (<id>). Multi-proof rows are summed.
SECTIONS = [
    ("MtA proofs", [
        (r"$\mathcal{R}_\text{MtA-A},\mathcal{R}_\text{MtA-B}$",
         "Paillier MtA inputs in range",
         ["zk/paillier/alice_range", "zk/paillier/bob"],
         "GG18/gennaro2018fast"),
        (r"$\mathcal{R}_\text{enc},\mathcal{R}_\text{aff-g}$",
         "Paillier ciphertext and affine operation in range",
         ["zk/paillier_zk_facade/pi_enc", "zk/paillier_zk_facade/pi_aff_g"],
         "CGGMP20/canetti2020uc"),
        (r"$\mathcal{R}_\text{JL-enc},\mathcal{R}_\text{JL-aff}$",
         "JL encryption and affine operation in range",
         ["zk/joye_libert/zkjl_enc", "zk/joye_libert/zkjl_aff"],
         "XAL+23/xue2023efficient"),
        (r"$\mathcal{R}_\text{Ped}$",
         "CL and EC Pedersen commitments hold the same value",
         ["zk/class_group/r_ped_ec"],
         "LLZ+25/lyu2025threshold"),
        (r"$\mathcal{R}_\text{CL-Enc}$", "CL ciphertext is a well-formed encryption of a known value", ["zk/class_group/r_enc"], "WMC24/wong2024secure")
    ]),
    ("One-time setup proofs", [
        (r"$\mathcal{R}_\text{ck}$",
         "Paillier modulus is well formed",
         ["zk/paillier/correct_key_ni"],
         "GG18/gennaro2018fast"),
        (r"$\mathcal{R}_\text{mod}$",
         "modulus is a Paillier--Blum integer",
         ["zk/pedersen_mod/pi_mod"],
         "CGGMP20/canetti2020uc"),
        (r"$\mathcal{R}_\text{prm}$",
         "Ring-Pedersen parameters are well formed",
         ["zk/pedersen_mod/pi_prm"],
         "CGGMP20/canetti2020uc"),
        (r"$\mathcal{R}_\text{JLmod}$",
         "modulus has the JL structure",
         ["zk/joye_libert/zkjlmod"],
         "XAL+23/xue2023efficient"),
    ]),
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


def load_sizes(size_dir: Path) -> dict:
    """Merge zk_once's per-process size TSVs ('<proof-id>\\t<bytes>').

    Reads every <size_dir>/*.tsv oldest-first so the newest run wins per key.
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
    """5 significant figures for v > 1; 4 decimals for v <= 1; '--' if None."""
    if v is None:
        return SCAFFOLD
    if abs(v) > 1:
        d = Decimal(repr(v))
        quant = Decimal(1).scaleb(d.adjusted() - 4)  # 5 sig figs
        return str(d.quantize(quant, rounding=ROUND_HALF_UP))
    return f"{v:.4f}"


def sum_or_none(values):
    """Sum, or None if any component is missing (-> '--' cell)."""
    total = 0.0
    for v in values:
        if v is None:
            return None
        total += v
    return total


def main():
    data = load_all(CRITERION_DIR)
    sizes = load_sizes(ZK_SIZES_DIR)

    def prove_ms(pids):
        return sum_or_none([
            data[f"{p}/prove"] * 1e-6 if f"{p}/prove" in data else None for p in pids
        ])

    def verify_ms(pids):
        return sum_or_none([
            data[f"{p}/verify"] * 1e-6 if f"{p}/verify" in data else None for p in pids
        ])

    def size_kb(pids):
        return sum_or_none([
            sizes[p] / 1024.0 if p in sizes else None for p in pids
        ])

    rows = [r for _, sect in SECTIONS for r in sect]
    name_w = max(len(name) for name, *_ in rows)
    stmt_w = max(len(stmt) for _, stmt, *_ in rows)

    for i, (sect_name, sect_rows) in enumerate(SECTIONS):
        if i > 0:  # the first section follows the header \midrule in the template
            print(r"\midrule")
        print(rf"\multicolumn{{6}}{{l}}{{\emph{{{sect_name}}}}} \\")
        for name, stmt, pids, cite in sect_rows:
            pr = fmt(prove_ms(pids))
            ve = fmt(verify_ms(pids))
            sz = fmt(size_kb(pids))
            print(f"{name:<{name_w}} & {stmt:<{stmt_w}} & {pr:>8} & {ve:>8} "
                  f"& {sz:>8} & \\cite{{{cite}}} \\\\")


if __name__ == "__main__":
    if not CRITERION_DIR.is_dir():
        sys.exit(f"error: {CRITERION_DIR} not found (run from repo root)")
    main()
