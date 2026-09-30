#!/usr/bin/env python3
"""Generate the honest-majority comparison table from criterion results.

Unlike `build_dkg_table.py` (which sweeps n at t=n) and `build_sign_table.py`
(which fixes n=20 and sweeps the quorum t), this table sweeps *honest-majority
security configurations* (n, t) = (3,2), (5,3), (7,4), (11,6) -- i.e. n = 2t-1,
the tightest honest majority -- and reports DKG, Offline, Online and Comm. for
each.

Reads target/criterion/<group>/<bench>/{new,base}/{benchmark.json,
estimates.json}, picks criterion's point estimate (slope if present, else mean
-- identical to build_sign_table.py) and converts ns -> ms.

  DKG     = dkg/<slug>/n{n}_t{t}/party1
  Offline = presign/<slug>/n{n}_t{t}/party1          (unbatched rows)
            presign/<slug>/n{n}_t{t}_m{m}/party1     (batched rows)
  Online  = online_sign/<slug>/n{n}_t{t}/party1

All three are per-party active time: per_party::bench_party_replay pools every
participating party's time, so each "party1" series is really the average
per-party active time.

!! PARTICIPANT-COUNT CAVEAT !!
(n, t) denotes a *security configuration*, not a participant count. DKG runs all
n parties in every row, so those cells divide by n throughout and compare
directly. Offline/Online do not: the quorum-signing protocols run presign+sign
among only t parties (config::first_signers), so their cells are total/t, while
KU24 runs all n (reconstruction needs 2t-1 = n shares at these configurations)
so its cells are total/n. Rows marked `all` in META divide by n; `quorum` rows
divide by t.

!! BATCHING !!
KU24 is the only protocol here with a batch parameter (one presign run yields m
presignatures in 4 rounds regardless of m). It is reported at m = 1 -- one
presignature per run, like every other row -- so no cell is amortized. To add a
batched variant, append another KU24 Row with a different `batch` and a
`variant` label; the merge logic below handles it.

Rows that differ only in their variant (e.g. KU24's two batch sizes) are
merged: the shared metadata and any data cell whose value is identical across
the variants are emitted once via \\multirow, so only the genuinely differing
cells (Offline, Comm.) repeat. The variant label is appended to the Protocol
cell, so no extra column is needed.

Comm. (per-party TOTAL signing communication = offline + online, KB) is merged
from the per-process TSVs under target/comm_online/ written by the
`protocol_once` binary, exactly as in build_sign_table.py: online lives under
"<slug>/n{N}_t{t}" and offline under "<slug>/n{N}_t{t}/presign" (or
".../n{N}_t{t}_m{m}/presign" for a batched row, which is then divided by m).
Cells are "--" until measured.

Usage:
    python3 scripts/build_hm_table.py [--rows-only]
"""

import argparse
import json
import sys
from pathlib import Path
from typing import NamedTuple, Optional

CRITERION_DIR = Path("target/criterion")
COMM_DIR = Path("target/comm_online")

# Honest-majority security configurations: n = 2t-1.
CONFIGS = [(3, 2), (5, 3), (7, 4), (11, 6)]

SCAFFOLD = object()  # sentinel for "--" (no measurement)


class Row(NamedTuple):
    """One table row.

    `participants` is "quorum" (presign/sign run among t parties, so per-party
    figures are total/t) or "all" (all n parties, total/n).

    `variant` is appended to the Protocol cell to distinguish sub-rows of the
    same protocol; rows sharing `group_key` are merged with \\multirow and
    differ only by it.

    `batch` is the presign batch size m, or None for protocols without a batch
    parameter.
    """

    name: str
    cite: str
    src: str
    thm: str
    para: str
    rounds: str
    slug: str
    participants: str
    variant: str
    batch: Optional[int]

    @property
    def group_key(self):
        return (
            self.name, self.cite, self.src, self.thm,
            self.para, self.rounds, self.slug, self.participants,
        )


META = [
    Row("WMYC23",  "WMY23/wong2023real",   "Pub", "App.~C", "P2, CL", "4/1",
        "wmy23",        "quorum", "",                 None),
    Row("WMC24",   "WMC24/wong2024secure", "Pub", "2",      "P2, CL", "3/1",
        "wmc24",        "quorum", "",                 None),
    Row("KU24",    "KU24/katz2024honest",  "Pub", "1",      "P1, SS", "4/1",
        "ku24",         "all",    "",                 1),
    Row("TX25",    "TX25/tang2025robust",  "Pub", "2",      "P1, CL", "2/1",
        "tx25",         "quorum", "",                 None),
    Row("JTX25-R", "JTX25/jiang2025three", "Pub", "2",      "P1, CL", "2/1",
        "jtx25_robust", "quorum", "",                 None),
]

# Meta columns: Protocol, Src., Thm., Para./Prim., Rounds.
N_META_COLS = 5


def pick_estimate_ns(estimates: dict) -> float:
    slope = estimates.get("slope")
    est = slope if slope else estimates["mean"]
    return est["point_estimate"]


def load_all(root: Path) -> dict:
    """full_id -> point estimate in ns (prefer the most recent run, new/)."""
    found = {}
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


def fmt(v) -> str:
    """Compact fixed-point: 2 dp at >= 0.1, 3 dp at >= 0.01, else 4 dp.

    The table carries 16 numeric columns under \\adjustbox, so cells must stay
    narrow; this keeps two significant figures across the whole measured range
    without the ragged width of a pure sig-fig rule.
    """
    if v is SCAFFOLD:
        return "--"
    if v is None:
        return "MISSING"
    if abs(v) >= 0.1:
        return f"{v:.2f}"
    if abs(v) >= 0.01:
        return f"{v:.3f}"
    return f"{v:.4f}"


def multirow(span: int, value: str) -> str:
    return value if span == 1 else rf"\multirow{{{span}}}{{*}}{{{value}}}"


def emit_group(group, cells) -> list:
    """LaTeX lines for one protocol, merging cells constant across variants.

    `cells[i]` is the data cell list for `group[i]`. Any column whose value is
    the same for every variant is emitted once as a \\multirow on the first
    line and left blank afterwards; the variant column is never merged, since
    it is what distinguishes the sub-rows.
    """
    span = len(group)
    lines = []
    for i, row in enumerate(group):
        # The Protocol cell cannot be merged when a group has variants: it is
        # what names them. Everything else identical across the group is.
        label = f"{row.name}~\\cite{{{row.cite}}}"
        if row.variant:
            label += f" {row.variant}"
        if i == 0:
            meta = [
                label,
                multirow(span, row.src),
                multirow(span, row.thm),
                multirow(span, row.para),
                multirow(span, row.rounds),
            ]
        else:
            meta = [label, "", "", "", ""]

        data = []
        for col in range(len(cells[0])):
            values = [cells[j][col] for j in range(span)]
            if len(set(values)) == 1:
                data.append(multirow(span, values[0]) if i == 0 else "")
            else:
                data.append(cells[i][col])
        lines.append(" & ".join(meta + data) + r" \\")
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--rows-only",
        action="store_true",
        help="emit only the \\midrule..\\bottomrule body rows",
    )
    args = ap.parse_args()

    data = load_all(CRITERION_DIR)
    comm = load_comm(COMM_DIR)

    def ms(fid):
        return data[fid] * 1e-6 if fid in data else None

    def dkg(slug, n, t):
        return ms(f"multiparty/{slug}/dkg/{slug}/n{n}_t{t}/party1")

    def offline(slug, n, t, batch):
        """Per-presignature offline time.

        Rows without a batch parameter (batch=None) produce one presignature
        per run, so their bench id carries no `_m` suffix. Batched rows read
        the `_m{batch}` series, which the bench already divides by the batch
        size before reporting.
        """
        if batch is None or batch == 1:
            return ms(f"multiparty/{slug}/presign/{slug}/n{n}_t{t}/party1")
        return ms(f"multiparty/{slug}/presign/{slug}/n{n}_t{t}_m{batch}/party1")

    def online(slug, n, t):
        return ms(f"multiparty/{slug}/online_sign/{slug}/n{n}_t{t}/party1")

    def comm_kb(slug, n, t, batch):
        """Per-party offline+online bytes -> KB, per presignature.

        A batched row's offline comm is recorded for the whole batch under
        "<slug>/n{n}_t{t}_m{m}/presign", so it is divided by m to stay on the
        same per-presignature footing as its Offline time column (and as every
        unbatched row). Online comm is already per signature, never divided.
        """
        on = comm.get(f"{slug}/n{n}_t{t}")
        if batch is not None and batch != 1:
            raw = comm.get(f"{slug}/n{n}_t{t}_m{batch}/presign")
            off = None if raw is None else raw / batch
        else:
            off = comm.get(f"{slug}/n{n}_t{t}/presign")
        if on is None and off is None:
            return SCAFFOLD
        return ((on or 0) + (off or 0)) / 1024.0

    # --- group consecutive rows that differ only by variant ---
    groups = []
    for row in META:
        if groups and groups[-1][0].group_key == row.group_key:
            groups[-1].append(row)
        else:
            groups.append([row])

    body = []
    for group in groups:
        cells = []
        for row in group:
            row_cells = []
            for (n, t) in CONFIGS:
                d = dkg(row.slug, n, t)
                off = offline(row.slug, n, t, row.batch)
                on = online(row.slug, n, t)
                row_cells += [
                    fmt(d if d is not None else SCAFFOLD),
                    fmt(off if off is not None else SCAFFOLD),
                    fmt(on if on is not None else SCAFFOLD),
                    fmt(comm_kb(row.slug, n, t, row.batch)),
                ]
            cells.append(row_cells)
        body += emit_group(group, cells)

    if not args.rows_only:
        n_data = 4 * len(CONFIGS)
        total = N_META_COLS + n_data
        print(r"% Honest-majority comparison: (n,t) = " +
              ", ".join(f"({n},{t})" for n, t in CONFIGS) + r" (n = 2t-1).")
        print(r"% Times are per-party active time in ms; Comm. is per-party "
              r"offline+online in KB.")
        print(r"% DKG runs all n parties in every row (total/n).")
        print(r"% Offline/Online divide by the signing-path size:")
        quorum = sorted({r.name for r in META if r.participants == "quorum"})
        everyone = sorted({r.name for r in META if r.participants == "all"})
        print(r"%   total/t (quorum of t): " + ", ".join(quorum))
        print(r"%   total/n (all n):       " + ", ".join(everyone) +
              r"  -- needs 2t-1 = n shares to reconstruct")
        for (n, t) in CONFIGS:
            print(rf"%   at ({n},{t}): {t} vs {n} parties in the signing path")
        for r in META:
            if r.batch is not None and r.batch != 1:
                print(rf"% {r.name} {r.variant}: Offline and Comm. amortized over "
                      rf"m={r.batch} presignatures (4 rounds regardless of m).")
        print(r"\adjustbox{max width=\textwidth}{%")
        # Meta columns grouped in pairs for readability, e.g. 5 -> "cc cc c".
        meta_spec = " ".join(
            "c" * min(2, N_META_COLS - i) for i in range(0, N_META_COLS, 2)
        )
        print(rf"\begin{{tabular}}{{{meta_spec} *{{{n_data}}}{{c}}}}")
        print(r"\toprule")
        hdr = (r"\multirow{2}{*}{Protocol} & \multirow{2}{*}{Src.} & "
               r"\multirow{2}{*}{Thm.} & \multirow{2}{*}{\shortstack{Para./Prim.}} & "
               r"\multirow{2}{*}{\shortstack{Rounds (o/s)}}")
        for (n, t) in CONFIGS:
            hdr += rf" & \multicolumn{{4}}{{c}}{{$({n},{t})$}}"
        print(hdr + r" \\")
        print("".join(
            rf"\cmidrule(lr){{{N_META_COLS + 1 + 4 * i}-{N_META_COLS + 4 + 4 * i}}}"
            for i in range(len(CONFIGS))
        ))
        print(" & ".join([""] * N_META_COLS +
                         ["DKG", "Offline", "Online", "Comm."] * len(CONFIGS)) +
              r" \\")
        print(r"\midrule")
        assert total == N_META_COLS + n_data
    for row in body:
        print(row)
    if not args.rows_only:
        print(r"\bottomrule")
        print(r"\end{tabular}}")


if __name__ == "__main__":
    if not CRITERION_DIR.is_dir():
        sys.exit(f"error: {CRITERION_DIR} not found (run from repo root)")
    main()
