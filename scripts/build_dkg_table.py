#!/usr/bin/env python3
"""Generate the (a) Key-generation rows of tab:multiparty from criterion results.

For each multi-party protocol this reads
  target/criterion/multiparty_<group>/<bench>/{new,base}/{benchmark.json,estimates.json},
picks criterion's point estimate (slope if present, else mean -- identical to
build_sign_table.py / summarize_multiparty_benches.py) and reports:

  Setup (s)         = multiparty/<g>/setup/<g>                      (seconds)
  Time (ms) at t=n  = multiparty/<g>/dkg/<g>/n{n}_t{n}/party1       (ms), per
                      party at t=n for n in {2,3,7,11,15,20}.

Mapping notes:
  * Setup (s) is the protocol's one-time local key material (Paillier+RP /
    threshold-Paillier dealer / JL keypair / CL CRS+key), measured by the
    dedicated `setup/<g>` bench. It is EXCLUDED from the DKG series (the heavy
    local key material is generated untimed inside the DKG builder), so the DKG
    cell is the core interactive DKG only.
  * DKLs23 has no setup bench (base OT is produced within DKG)  -> Setup = "--".
  * JTX25 keygen is shared by the normal/robust variants and is only benched
    under `jtx25_robust`, so the single JTX25 row uses jtx25_robust.
  * CGGMP20 additionally has an interactive aux-info phase (Paillier/RP proofs +
    key-refresh). It is surfaced INSIDE the DKG cell as "<core dkg> (+<aux>)" for
    every n, and Rounds as "3 (+3)" (3 core DKG rounds + 3 aux-info rounds).
    Setup stays the plain one-time local Paillier+RP keygen (`setup/<g>`). The
    aux term is the directly-measured interactive rounds only,
    `aux_info_rounds/<g>/n{N}/party1` (drain+handle+finish, EXCLUDING the
    AuxInfoMachine constructor/local keygen that the Setup column already
    reports) -- i.e. the real "aux - setup", with no cross-run subtraction.
  * LN18 has no one-time setup bench: its Paillier+Ring-Pedersen are generated
    per signing session (build_signing_setup, untimed), not at DKG time, so
    Setup = "--" while the DKG cells are its Feldman-VSS keygen.

Formatting (matches build_sign_table.py): values > 1 are rounded to 5
significant figures; values <= 1 keep 4 decimal places (applied to Setup in s
and to each DKG time in ms).
"""

import json
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

CRITERION_DIR = Path("target/criterion")
N_VALUES = [2, 3, 7, 11, 15, 20]
SCAFFOLD = "--"  # cell with no criterion measurement (DKLs23 setup / LN18)

# Protocols with an extra interactive aux-info phase shown INSIDE the DKG cell as
# "<core dkg> (+<aux>)" for every n (Rounds shown as "3 (+3)"), not in Setup. The
# aux term is the directly-measured interactive rounds only,
# `aux_info_rounds/<slug>/n{N}/party1` (excludes the constructor/local keygen that
# the Setup column reports); n-dependent, pairs with the DKG column at the same n.
AUX_IN_DKG = {"cggmp20"}

# (display name, cite key, dkg/setup slug | None=ignore, has_setup,
#  DKG Type, Settings, Rounds)  -- the last three are copied verbatim from the
#  .tex (the script does NOT derive them; it only fills Setup(s) + the 6 times).
META = [
    ("CGGMP20", "CGGMP20/canetti2020uc",       "cggmp20",      True,
     r"Feldman VSS $+$ Schnorr",              r"Paillier $+$ Ring-Pedersen",          "3 (+3)"),
    ("GG18",    "GG18/gennaro2018fast",         "gg18",         True,
     r"Feldman VSS $+$ Paillier $+$ Schnorr", r"Paillier $+$ Ring-Pedersen",          "4"),
    ("GGN16",   "GGN16/gennaro2016threshold",   "ggn16",        True,
     r"Commit $+$ shared threshold Paillier", r"Threshold Paillier $+$ Ring-Pedersen", "2"),
    ("LN18",    "LN18/lindell2018fast",         "ln18",         False,
     r"Additive $+$ ElGamal-in-exponent",     r"Paillier $+$ Ring-Pedersen",          "5"),
    ("XAL23",   "XAL+23/xue2023efficient",      "xal23",        True,
     r"Feldman VSS $+$ JL",                   r"JL modulus",                          "2"),
    ("DKLs23",  "DKLs23/doerner2024threshold",  "dkls23",       False,
     r"Commit-release Shamir VSS",            r"Base OT",                             "3"),
    ("TX25",    "TX25/tang2025robust",          "tx25",         True,
     r"PVSS $+$ CL",                          r"Transparent CL group",                "3"),
    ("WMY23",   "WMY23/wong2023real",           "wmy23",        True,
     r"Pedersen VSS $+$ CL",                  r"Transparent CL group",                "4"),
    ("JTX25",   "JTX25/jiang2025three",         "jtx25_robust", True,
     r"PVSS $+$ threshold CL",                r"Transparent CL group",                "3"),
    ("LLZ+25",  "LLZ+25/lyu2025threshold",      "llz25",        True,
     r"Feldman VSS $+$ NIM",                  r"Transparent CL group",                "3"),
    ("DNP25",   "DNP25/dahari2025trout",        "trout",        True,
     r"Feldman VSS $+$ threshold CL $+$ eVRF", r"Transparent CL group $+$ eVRF",      "3"),
    ("WMC24",   "WMC24/wong2024secure",         "wmc24",        True,
     r"Dual-code PVSS $+$ threshold CL",      r"Transparent CL group",                "3"),
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


def fmt(v) -> str:
    """5 significant figures for v > 1; 4 decimals for v <= 1."""
    if v is None:
        return "MISSING"
    if abs(v) > 1:
        d = Decimal(repr(v))
        quant = Decimal(1).scaleb(d.adjusted() - 4)  # 5 sig figs
        return str(d.quantize(quant, rounding=ROUND_HALF_UP))
    return f"{v:.4f}"


def main():
    data = load_all(CRITERION_DIR)

    def get(fid, factor):
        return data[fid] * factor if fid in data else None

    def setup_s(slug, has_setup):
        if slug is None or not has_setup:
            return SCAFFOLD
        return fmt(get(f"multiparty/{slug}/setup/{slug}", 1e-9))  # ns -> s

    def aux_ms(slug, n):
        # Interactive aux-info rounds only (excludes the constructor == setup),
        # directly measured -- no cross-run subtraction.
        return get(f"multiparty/{slug}/aux_info_rounds/{slug}/n{n}/party1", 1e-6)

    def dkg_parts(slug, n):
        """(core_dkg_ms_str, aux_ms_str | None) for the cell at party count n."""
        if slug is None:
            return SCAFFOLD, None
        core = fmt(get(f"multiparty/{slug}/dkg/{slug}/n{n}_t{n}/party1", 1e-6))  # ns -> ms
        aux = fmt(aux_ms(slug, n)) if slug in AUX_IN_DKG else None
        return core, aux

    def dkg_inline(slug, n):  # plain "core (+aux)" for the % diagnostic view
        core, aux = dkg_parts(slug, n)
        return core if aux is None else f"{core} (+{aux})"

    def dkg_cell(slug, n):  # LaTeX: split AUX_IN_DKG cells over two lines
        core, aux = dkg_parts(slug, n)
        # upper line = core DKG time, lower line = aux time "(+aux)"
        return core if aux is None else rf"\shortstack{{{core} \\ (+{aux})}}"

    namecites = [f"{name}~\\cite{{{cite}}}" for name, cite, *_ in META]
    w = max(len(s) for s in namecites)
    wt = max(len(dkg_type) for *_, dkg_type, _, _ in META)
    ws = max(len(settings) for *_, settings, _ in META)

    # --- diagnostic view ---
    print("% --- (a) Key generation: Setup(s) + per-party DKG time (ms) at t=n ---")
    hdr = ["protocol", "Setup(s)"] + [f"n={n}" for n in N_VALUES]
    print("% " + " | ".join(f"{h:>10}" for h in hdr))
    for name, cite, slug, has_setup, *_ in META:
        row = [name, setup_s(slug, has_setup)] + [dkg_inline(slug, n) for n in N_VALUES]
        print("% " + " | ".join(f"{c:>10}" for c in row))

    # --- aux-in-DKG breakdown (DKG cell = core_dkg (+aux), both ms, per n). ---
    for slug in AUX_IN_DKG:
        setup_val = fmt(get(f"multiparty/{slug}/setup/{slug}", 1e-9))
        print(f"% [{slug}] Setup (local keygen) = {setup_val} s; DKG = core_dkg "
              f"(+aux_info_rounds), ms per n=2,3,7,11,15,20:")
        core = [fmt(get(f"multiparty/{slug}/dkg/{slug}/n{n}_t{n}/party1", 1e-6))
                for n in N_VALUES]
        aux = [fmt(aux_ms(slug, n)) for n in N_VALUES]
        full = [fmt(get(f"multiparty/{slug}/aux_info/{slug}/n{n}/party1", 1e-6))
                for n in N_VALUES]
        print(f"%   core dkg        : {' | '.join(core)}")
        print(f"%   aux_info_rounds : {' | '.join(aux)}   (used)")
        print(f"%   full aux_info   : {' | '.join(full)}   (ref; incl. constructor)")

    print()
    # --- complete drop-in LaTeX rows for sub-table (a) ---
    print(r"% ---- (a) Key generation rows ----")
    for (name, cite, slug, has_setup, dkg_type, settings, rounds), nc in zip(META, namecites):
        s = setup_s(slug, has_setup)
        times = " & ".join(dkg_cell(slug, n) for n in N_VALUES)
        print(f"{nc:<{w}} & {dkg_type:<{wt}} & {settings:<{ws}} & {s} & {rounds} & {times} \\\\")


if __name__ == "__main__":
    if not CRITERION_DIR.is_dir():
        sys.exit(f"error: {CRITERION_DIR} not found (run from repo root)")
    main()
