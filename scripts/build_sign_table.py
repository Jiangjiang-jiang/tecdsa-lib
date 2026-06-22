#!/usr/bin/env python3
"""Generate the multi-party rows of tab:sign from existing criterion results.

For each multi-party protocol at n=20 and threshold t in {2,3,7,11,20} this
reads target/criterion/<group>/<bench>/{new,base}/{benchmark.json,estimates.json},
picks criterion's point estimate (slope if present, else mean -- identical to
summarize_multiparty_benches.py) and converts ns -> ms.

  Offline = per-party presigning time   = presign/<p>/n20_t{t}/party1
  Online  = per-party online-sign time  = online_sign/<p>/n20_t{t}/party1

Note: per_party::bench_party_replay pools every participating party's active
time, so each "party1" series is really the *average per-party active time*.

Formatting: values > 1 ms are rounded to 5 significant figures; values <= 1 ms
keep 4 decimal places.

Special cases:
  * Trout has 0 offline rounds (Table 1 convention) -> Offline = \textemdash.
  * CGGMP20 online sign is "partial_sign + combine" (per the bench comment),
    so its Online cell sums the two cggmp20_sign sub-benchmarks.

Comm. (per-party TOTAL communication = offline + online, KB) is merged from the
per-process TSVs under `target/comm_online/` (written by the `protocol_once`
binary, which counts each signer's bytes_sent via the orchestrator's bincode
serialization, under "<slug>/n{N}_t{t}" for online and ".../presign" for
offline). Every `*.tsv` is merged (newest file wins per key), so parallel/subset
runs never clobber each other. Cells are "--" until measured. LN18 timing is from
its Criterion benches (Paillier MtA backend): Offline = presign/ln18, Online =
online_sign/ln18. Two-party protocols are not handled here.

Output: complete LaTeX rows (Protocol/cite, Para./Prim., Rounds + 15 cells).
"""

import json
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

CRITERION_DIR = Path("target/criterion")
COMM_DIR = Path("target/comm_online")  # per-process comm TSVs, written by protocol_once
T_VALUES = [2, 3, 7, 11, 20]
SIGN_N = 20  # signing reported at n=20
EMDASH = "\\textemdash"
SCAFFOLD = object()  # sentinel for "--" (missing measurement)

# protocol_once records LN18 comm under the Paillier-backend name; every other
# row's comm key equals its online slug.
COMM_SLUG = {"ln18": "ln18-paillier"}

# (name, cite key, Para./Prim., Rounds(o/s), offline kind, online kind)
#   offline kind: protocol slug (presign bench) | "EMDASH" | None (scaffold)
#   online  kind: protocol slug (online_sign bench) | "cggmp20" | None (scaffold)
META = [
    ("CGGMP20", "CGGMP20/canetti2020uc",         "P1, PL", "3/1", "cggmp20",      "cggmp20"),
    ("GG18",    "GG18/gennaro2018fast",          "P2, PL", "4/4", "gg18",         "gg18"),
    ("GGN16",   "GGN16/gennaro2016threshold",    "P1, PL", "4/2", "ggn16",        "ggn16"),
    ("LN18",    "LN18/lindell2018fast",          "P1, PL", "2/6", "ln18",         "ln18"),
    ("XAL23",   "XAL+23/xue2023efficient",       "P2, JL", "4/1", "xal23",        "xal23"),
    ("DKLs23",  "DKLs23/doerner2024threshold",   "P1, OT", "2/1", "dkls23",       "dkls23"),
    ("TX25",    "TX25/tang2025robust",           "P1, CL", "2/1", "tx25",         "tx25"),
    ("WMY23",   "WMY23/wong2023real",            "P2, CL", "4/1", "wmy23",        "wmy23"),
    ("JTX25-N", "JTX25/jiang2025three",          "P1, CL", "2/1", "jtx25",        "jtx25"),
    ("JTX25-R", "JTX25/jiang2025three",          "P1, CL", "2/1", "jtx25_robust", "jtx25_robust"),
    ("LLZ+25",  "LLZ+25/lyu2025threshold",       "P1, CL", "1/1", "llz25",        "llz25"),
    ("Trout",   "DNP25/dahari2025trout",         "P1, CL", "0/2", "EMDASH",       "trout"),
    ("WMC24",   "WMC24/wong2024secure",          "P2, CL", "3/1", "wmc24",        "wmc24"),
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
    wins per key. (Comm is deterministic, so stale duplicates are harmless, and
    parallel/subset runs each write their own file -> none clobbers another.)
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
    if v is SCAFFOLD:
        return "--"
    if v is EMDASH:
        return EMDASH
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

    def offline(kind, t):
        if kind is None:
            return SCAFFOLD
        if kind == "EMDASH":
            return EMDASH
        return ms(f"multiparty/{kind}/presign/{kind}/n20_t{t}/party1")

    def online(kind, t):
        if kind is None:
            return SCAFFOLD
        if kind == "cggmp20":
            ps = ms(f"multiparty/cggmp20/online_sign/cggmp20/n20_t{t}/party1/partial_sign")
            cb = ms(f"multiparty/cggmp20/online_sign/cggmp20/n20_t{t}/combine")
            return None if ps is None or cb is None else ps + cb
        return ms(f"multiparty/{kind}/online_sign/{kind}/n20_t{t}/party1")

    comm = load_comm(COMM_DIR)

    def comm_kb(on_kind, t):
        # Per-party TOTAL signing communication (KB) = offline (presign) + online,
        # from protocol_once's TSV. "--" if not measured yet. Online is the bare
        # key "<slug>/n{N}_t{t}"; offline is "<slug>/n{N}_t{t}/presign".
        if on_kind is None:
            return SCAFFOLD
        slug = COMM_SLUG.get(on_kind, on_kind)
        online = comm.get(f"{slug}/n{SIGN_N}_t{t}")
        offline = comm.get(f"{slug}/n{SIGN_N}_t{t}/presign")
        if online is None and offline is None:
            return SCAFFOLD
        return ((online or 0) + (offline or 0)) / 1024.0

    namecites = [f"{name}~\\cite{{{cite}}}" for name, cite, *_ in META]
    w = max(len(s) for s in namecites)

    print("% Multi-party rows of tab:sign (Offline/Online/Comm. filled)")
    print("% Times in ms (>1 at 5 sig figs, <=1 at 4 decimals); Comm. per-party online in KB.")
    for (name, cite, para, rounds, off_kind, on_kind), nc in zip(META, namecites):
        cells = []
        for t in T_VALUES:
            cells.append(fmt(offline(off_kind, t)))
            cells.append(fmt(online(on_kind, t)))
            cells.append(fmt(comm_kb(on_kind, t)))
        print(f"{nc:<{w}} & {para:<7} & {rounds} & " + " & ".join(cells) + r" \\")


if __name__ == "__main__":
    if not CRITERION_DIR.is_dir():
        sys.exit(f"error: {CRITERION_DIR} not found (run from repo root)")
    main()
