#!/usr/bin/env python3
"""Generate the two-party rows of tab:twoparty from existing criterion results.

For each two-party protocol (Lin17, KGG24, XAL21, ABC24) measured only at
(t,n)=(2,2), this reads
  target/criterion/twoparty_<proto>/<bench>/{new,base}/{benchmark.json,estimates.json},
picks criterion's point estimate (slope if present, else mean -- identical to
build_sign_table.py / summarize_multiparty_benches.py) and converts ns -> ms.

The two roles are asymmetric, so each phase is reported separately per party
(party1 = P1, party2 = P2). The criterion benches expose a one-time setup plus three phases per party:

  (a) Setup   = one-time, per-party key material generation (Paillier keygen;
                XAL21 also Ring-Pedersen N~), measured on its own and excluded
                from DKG -> setup/<proto>  (reported in SECONDS)
  (a) DKG     = interactive keygen rounds only, with the Setup key material
                injected untimed -> dkg/<proto>/n2_t2/party{1,2}
  (b) Offline = per-party presigning time   -> presign/<proto>/n2_t2/party{1,2}
  (b) Online  = per-party online-sign time  -> online_sign/<proto>/n2_t2/party{1,2}

Comm.\\ (KB) in (b) is the per-party TOTAL communication (offline + online),
merged from the per-process TSVs under `target/comm_online/` (written by the
`protocol_once` binary, which sizes each party's messages via the orchestrator's
bincode config; bare points are sized as compressed SEC1). Every `*.tsv` is
merged (newest file wins per key), so parallel/subset runs never clobber each
other. Cells are "--" until measured.

Setup (s) shows "--" until the `setup/<proto>` benches have been run.

Formatting (matches build_sign_table.py): values > 1 ms are rounded to 5
significant figures; values <= 1 ms keep 4 decimal places.

Output: complete LaTeX rows for sub-tables (a) and (b).
"""

import json
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

CRITERION_DIR = Path("target/criterion")
COMM_DIR = Path("target/comm_online")  # per-process comm TSVs, written by protocol_once
SCAFFOLD = "--"  # cell with no measurement
# Phase that does not exist for a role (as opposed to one not yet measured):
# ABC+24's P2 has no presigning work, so its bench reads ~0 rather than a time.
NO_PHASE = "/"

# (slug, name, cite, DKG Type, Material, DKG rounds,
#  Paradigm, Primitive, Rounds(o/s), parties with no offline phase)
# Row order and the last four fields are copied verbatim from the .tex; the
# script only fills Time (s), the DKG/Offline/Online times and Comm.
META = [
    ("lin17", "Lin17", "Lin17/lindell2021fast",
     r"Commit $+$ Paillier $+$ PDL", r"Paillier $+$ PDL", "3",
     r"$x_1 x_2,\, k_1 k_2$", "PL", "3/1", ()),
    ("xal21", "XAL+21", "XAL+21/xue2021efficient",
     r"Commit $+$ DL PoK", r"MtA primitive (PL/CL/OT)", "3",
     r"$x_1{+}x_2,\, k_1(r_1{+}k_2)$", "PL", "3/1", ()),
    ("kgg24", "KGG24", "KGG24/koziel2024fast",
     r"Commit $+$ Paillier $+$ DL-equality proof", r"Paillier", "3",
     r"$x_1{+}x_2,\, k_1 k_2$", "PL", "2/1", ()),
    ("abc24", "ABC+24", "ABC+24/adjedj2024two",
     r"Commit $+$ DL PoK $+$ Paillier-OLE", r"Paillier $+$ DF (server)", "2",
     r"$x_1{+}x_2,\, k_1 k_2$", "PL", "1/1", (2,)),
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
    """Merge protocol_once's per-process comm TSVs ('<key>\\t<bytes>').

    Reads every <comm_dir>/*.tsv, oldest file first, so the newest run's value
    wins per key. Parallel/subset runs each write their own file, so none
    clobbers another (and stale duplicates are harmless -- comm is deterministic).
    """
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


def fmt(v) -> str:
    """5 significant figures for v > 1 ms; 4 decimals for v <= 1 ms."""
    if v is None:
        return "MISSING"
    if abs(v) > 1:
        d = Decimal(repr(v))
        quant = Decimal(1).scaleb(d.adjusted() - 4)  # 5 sig figs
        return str(d.quantize(quant, rounding=ROUND_HALF_UP))
    return f"{v:.4f}"


def main():
    data = load_all(CRITERION_DIR)

    def ms(fid):
        return data[fid] * 1e-6 if fid in data else None

    def cell(slug, phase, party):
        return fmt(ms(f"twoparty/{slug}/{phase}/{slug}/n2_t2/party{party}"))

    def setup_s(slug):
        """One-time setup time in SECONDS, or "--" if not yet benchmarked."""
        fid = f"twoparty/{slug}/setup/{slug}"
        return fmt(data[fid] * 1e-9) if fid in data else SCAFFOLD

    comm = load_comm(COMM_DIR)

    def comm_kb(slug, party):
        # Per-party TOTAL signing communication (KB) = offline (presign) + online,
        # from protocol_once; "--" if absent. Online is the bare key
        # "<slug>/n2_t2/party{p}"; offline is ".../party{p}/presign".
        online = comm.get(f"{slug}/n2_t2/party{party}")
        offline = comm.get(f"{slug}/n2_t2/party{party}/presign")
        if online is None and offline is None:
            return SCAFFOLD
        return fmt(((online or 0) + (offline or 0)) / 1024.0)

    namecites = [f"{name}~\\cite{{{cite}}}" for _, name, cite, *_ in META]
    w = max(len(s) for s in namecites)
    wt = max(len(m[3]) for m in META)
    wm = max(len(m[4]) for m in META)
    wp = max(len(m[6]) for m in META)

    # ---- (a) Key generation ----
    # Protocol | Rounds | DKG Type | Material | Time (s) | P1 | P2
    print(r"% ---- (a) Key generation rows ----")
    for m, nc in zip(META, namecites):
        slug, dkg_type, material, rounds = m[0], m[3], m[4], m[5]
        p1, p2 = cell(slug, "dkg", 1), cell(slug, "dkg", 2)
        print(f"{nc:<{w}} & {rounds} & {dkg_type:<{wt}} & {material:<{wm}} & "
              f"{setup_s(slug)} & {p1} & {p2} \\\\")

    print()
    # ---- (b) Signing ----
    # Protocol | Paradigm | Primitive | Rounds (o/s) | Offline P1/P2 | Online P1/P2 | Comm P1/P2
    print(r"% ---- (b) Signing rows (Comm. is per-party offline+online, KB) ----")
    for m, nc in zip(META, namecites):
        slug, paradigm, primitive, ros, no_offline = m[0], m[6], m[7], m[8], m[9]
        off = [NO_PHASE if i in no_offline else cell(slug, "presign", i) for i in (1, 2)]
        on = [cell(slug, "online_sign", i) for i in (1, 2)]
        cm = [comm_kb(slug, i) for i in (1, 2)]
        print(f"{nc:<{w}} & {paradigm:<{wp}} & {primitive} & {ros} & "
              + " & ".join(off + on + cm) + r" \\")

if __name__ == "__main__":
    if not CRITERION_DIR.is_dir():
        sys.exit(f"error: {CRITERION_DIR} not found (run from repo root)")
    main()
