#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
"""Cross-run statistics for foreshadow-ssa-warm VOTE_DUMP files.

Collector mode -- run the harness N times, then aggregate:

    python3 warm_vote_stats.py --collect ./app -n 30 --votes 24

Interleaved Phase-0 A/B (alternate ORACLE_LO_OFF in one boot; N is total runs,
so -n 30 with two arms -> 15 each):

    python3 warm_vote_stats.py --collect ./app -n 30 --votes 24 \
        --alt-env ORACLE_LO_OFF=0,0x400 --raw-lat \
        --outdir /tmp/ssawarm-votes-shift

Aggregate mode -- existing dumps:

    python3 warm_vote_stats.py /tmp/ssawarm-votes/*.votes

What it answers: for every GPRSGX byte offset, is a miss deterministic (present
in ~every run -> geometry/placement fix) or stochastic (varies across runs ->
votes/noise fix)?  Each offset is also mapped to its register, its physical
GPRSGX cache line and its L1D set ({61,62,63} for a page-aligned frame whose
GPRSGX region starts at page offset 0xF48).

Dump format v1 (written by foreshadow-ssa-warm when VOTE_DUMP=<path> is set;
'#' starts a comment; counts are decimal, addresses/off are 0x...):

    # ssawarm-votes v1
    # votes_per_trace <n>
    # aex <n>
    # faults <n>
    # alias_ssa 0x...
    # oracle_lo_alloc 0x...
    # oracle_lo 0x...          used lo-oracle base (shifted if ORACLE_LO_OFF)
    # oracle_lo_off 0x...
    # oracle_lo_set N          L1D set of the used base
    # oracle_hi 0x...
    E <off> <byte>        edbgrd ground truth for this run
    D <off> <byte>        byte decoded from this run's votes
    L <off> <64 ints>     lo-trace vote counts (low six bits, 64 classes)
    H <off> <4 ints>      hi-trace vote counts (high two bits, 4 classes)
"""

import argparse
import glob
import os
import subprocess
import sys

GPRSGX_PAGE_OFF = 0xF48   # GPRSGX = last 184 bytes of the 4 KiB SSA frame
LO_CLASSES = 64
HI_CLASSES = 4

REGS = [("rax", 0), ("rcx", 8), ("rdx", 16), ("rbx", 24),
        ("rsp", 32), ("rbp", 40), ("rsi", 48), ("rdi", 56),
        ("r8", 64), ("r9", 72), ("r10", 80), ("r11", 88),
        ("r12", 96), ("r13", 104), ("r14", 112), ("r15", 120),
        ("rflags", 128), ("rip", 136), ("ursp", 144)]

# The 12 planted-canary GPRs (not rsp/rbp/rsi/rdi, not rflags/rip/ursp).
CANARY_REGS = ["rax", "rcx", "rdx", "rbx",
               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def reg_name(off):
    if off >= 152:
        return "rsvd"
    for name, base in REGS:
        if base <= off < base + 8:
            return "%s[%d]" % (name, off - base)
    return "?"


def parse(path):
    meta, e, d, lo, hi = {}, {}, {}, {}, {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                parts = line[1:].split()
                if len(parts) >= 2:
                    meta[parts[0]] = parts[1]
                continue
            parts = line.split()
            kind = parts[0]
            if kind == "E":
                e[int(parts[1])] = int(parts[2])
            elif kind == "D":
                d[int(parts[1])] = int(parts[2])
            elif kind == "L":
                lo[int(parts[1])] = [int(x) for x in parts[2:]]
            elif kind == "H":
                hi[int(parts[1])] = [int(x) for x in parts[2:]]
    return {"path": path, "meta": meta, "E": e, "D": d, "L": lo, "H": hi}


def argmax(xs):
    best = 0
    for i in range(1, len(xs)):
        if xs[i] > xs[best]:
            best = i
    return best


HOT_CYCLES = 150  # same threshold as foreshadow-ssa-warm.c


def rawlat_summary(paths):
    """Per-offset fraction of traces whose TRUE lo-class slot is hot.

    Distinguishes deposit (true class < HOT_CYCLES) from argmin-on-noise.
    """
    by_off = {}
    for path in paths:
        truth_cls = {}
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("# off"):
                    parts = line.split()
                    # # off <o> truth <byte> lo_class <c> traces <n>
                    try:
                        off = int(parts[2])
                        cls = int(parts[6])
                    except (IndexError, ValueError):
                        continue
                    truth_cls[off] = cls
                elif line.startswith("R "):
                    parts = line.split()
                    try:
                        off = int(parts[1])
                    except (IndexError, ValueError):
                        continue
                    if ":" not in line or off not in truth_cls:
                        continue
                    lats = [int(x) for x in line.split(":", 1)[1].split()]
                    cls = truth_cls[off]
                    hot = 0 <= cls < len(lats) and lats[cls] < HOT_CYCLES
                    by_off.setdefault(off, []).append(hot)
    if not by_off:
        print("  (no rawlat traces)")
        return
    print("-- true-class deposit (t < %d) --" % HOT_CYCLES)
    for off in sorted(by_off):
        hs = by_off[off]
        print("  off %3d: %d/%d (%.2f)" %
              (off, sum(hs), len(hs), float(sum(hs)) / len(hs)))


def parse_alt_env(spec):
    """Parse --alt-env VAR=v1,v2 into (VAR, [v1, v2, ...])."""
    if not spec:
        return None
    if "=" not in spec:
        sys.exit("--alt-env needs VAR=v1,v2")
    var, rest = spec.split("=", 1)
    vals = [v for v in rest.split(",") if v != ""]
    if len(vals) < 2:
        sys.exit("--alt-env needs at least two comma-separated values")
    return var, vals


def collect(binary, n, votes, outdir, alt_env=None, raw_lat=False):
    """Run BIN N times. If alt_env=(VAR, [v1,v2,...]), interleave those values
    in one boot (run i gets values[(i-1) % len]) and write each arm to its own
    subdirectory so the two geometries are never mixed in one report."""
    wd = os.path.dirname(os.path.abspath(binary)) or None
    arms = alt_env[1] if alt_env else [None]
    files_by_arm = []
    n_arms = len(arms)
    for a_i, arm in enumerate(arms):
        arm_dir = outdir if arm is None else os.path.join(
            outdir, "%s=%s" % (alt_env[0], arm))
        os.makedirs(arm_dir, exist_ok=True)
        files_by_arm.append((arm, arm_dir, []))

    for i in range(1, n + 1):
        a_i = (i - 1) % n_arms
        arm, arm_dir, files = files_by_arm[a_i]
        arm_i = (i - 1) // n_arms + 1
        dump = os.path.join(arm_dir, "run%02d.votes" % arm_i)
        log = os.path.join(arm_dir, "run%02d.log" % arm_i)
        env = dict(os.environ)
        env["VOTE_DUMP"] = dump
        if votes is not None:
            env["WARM_VOTES"] = str(votes)
        if arm is not None:
            env[alt_env[0]] = arm
        if raw_lat:
            env["RAW_LAT_DUMP"] = os.path.join(arm_dir, "run%02d.rawlat" % arm_i)
            env.setdefault("RAW_LAT_OFF", "120,80")
        with open(log, "wb") as lf:
            rc = subprocess.call([binary], env=env, stdout=lf,
                                 stderr=subprocess.STDOUT, cwd=wd)
        tag = "" if arm is None else " %s=%s" % (alt_env[0], arm)
        if rc != 0 or not os.path.exists(dump):
            print("run %d%s: FAILED (rc=%d, dump=%s) -- see %s" %
                  (i, tag, rc, "yes" if os.path.exists(dump) else "no", log),
                  file=sys.stderr)
            continue
        files.append(dump)
        print("run %d%s: ok (%s)" % (i, tag, dump))
    return files_by_arm


def report(files, csv_path=None):
    runs = [parse(p) for p in files]
    if not runs:
        sys.exit("no dumps to aggregate")
    offs = sorted(runs[0]["D"])
    for r in runs:
        if sorted(r["D"]) != offs:
            sys.exit("dumps disagree on byte offsets (mix of builds?)")

    alias = None
    for r in runs:
        if "alias_ssa" in r["meta"]:
            try:
                alias = int(r["meta"]["alias_ssa"], 16)
                break
            except ValueError:
                pass

    def geo(off):
        a = (alias + off) if alias is not None else (GPRSGX_PAGE_OFF + off)
        return (a & 0xFFF) & ~0x3F, (a >> 6) & 63

    def fmt_offsets(offs_):
        if not offs_:
            return "none"
        sets_ = sorted(set(geo(o)[1] for o in offs_))
        return "%s (L1D sets %s)" % (",".join(str(o) for o in offs_),
                                     ",".join(str(s) for s in sets_))

    n = len(runs)
    as_s = ("0x%x" % alias) if alias is not None else ("page 0x%03x" % GPRSGX_PAGE_OFF)
    vpt = sorted(set(r["meta"].get("votes_per_trace", "?") for r in runs))

    print("== warm SSA vote stats ==")
    print("runs: %d   bytes/run: %d   alias: %s   votes/trace: %s" %
          (n, len(offs), as_s, ",".join(vpt)))
    if len(vpt) > 1:
        print("WARNING: runs used different votes/trace values: %s" %
              ",".join(vpt))

    rows = []
    for off in offs:
        flags = ""
        n_ok = n_truth = 0
        truths = set()
        for r in runs:
            if off in r["E"] and off in r["D"]:
                n_truth += 1
                truths.add(r["E"][off])
                if r["D"][off] == r["E"][off]:
                    n_ok += 1
                    flags += "#"
                else:
                    flags += "."
            else:
                flags += "-"
        lsum = [0] * LO_CLASSES
        hsum = [0] * HI_CLASSES
        for r in runs:
            lv = r["L"].get(off)
            if lv:
                for c in range(min(LO_CLASSES, len(lv))):
                    lsum[c] += lv[c]
            hv = r["H"].get(off)
            if hv:
                for c in range(min(HI_CLASSES, len(hv))):
                    hsum[c] += hv[c]
        pooled = ((argmax(hsum) & 3) << 6) | (argmax(lsum) & 0x3F)
        rows.append({"off": off, "reg": reg_name(off),
                     "rate": (float(n_ok) / n_truth) if n_truth else float("nan"),
                     "n_ok": n_ok, "n_truth": n_truth, "flags": flags,
                     "pooled": pooled, "truth": sorted(truths)})

    bad = [x for x in rows if x["n_truth"] and x["n_ok"] < x["n_truth"]]
    print("\n-- failing offsets (%d/%d) --" % (len(bad), len(rows)))
    if not bad:
        print("none: every offset decoded correctly in every run")
    for x in bad:
        lo, st = geo(x["off"])
        if x["rate"] <= 0.1:
            note = "systematic"
        elif x["rate"] < 0.9:
            note = "stochastic"
        else:
            note = "rare"
        tv = ""
        if len(x["truth"]) > 1:
            tv = " (truth varies: %s)" % ",".join("0x%02x" % t for t in x["truth"])
        print(" off %3d  %-9s line 0x%03x  set %2d  %s  rate %4.2f  "
              "pooled 0x%02x  %s%s" %
              (x["off"], x["reg"], lo, st, x["flags"], x["rate"],
               x["pooled"], note, tv))

    sys_offs = [x["off"] for x in rows if x["n_truth"] and x["rate"] <= 0.1]
    sto_offs = [x["off"] for x in rows if x["n_truth"] and 0.1 < x["rate"] < 1.0]
    print("\n-- classification --")
    print("systematic (fails in >=90%% of runs): %s" % fmt_offsets(sys_offs))
    print("stochastic (fails in a fraction):     %s" % fmt_offsets(sto_offs))

    print("\n-- registers (runs fully correct / %d) --" % n)
    canary_ok = 0
    for r in runs:
        ok12 = True
        for name, base in REGS:
            if name not in CANARY_REGS:
                continue
            roffs = [o for o in offs if base <= o < base + 8]
            if not all((o in r["E"] and o in r["D"] and r["D"][o] == r["E"][o])
                       for o in roffs):
                ok12 = False
                break
        if ok12:
            canary_ok += 1
    for name, base in REGS:
        roffs = [o for o in offs if base <= o < base + 8]
        okruns = 0
        for r in runs:
            if all((o in r["E"] and o in r["D"] and r["D"][o] == r["E"][o])
                   for o in roffs):
                okruns += 1
        bads = [str(o) for o in roffs
                if any(o in r["E"] and o in r["D"] and r["D"][o] != r["E"][o]
                       for r in runs)]
        print(" %-6s %2d/%d%s" % (name, okruns, n,
                                   ("  bad bytes: " + ",".join(bads)) if bads else ""))
    print("\n-- canary 12/12 (rax,rcx,rdx,rbx,r8..r15) --")
    print("single-run 12/12: %d/%d" % (canary_ok, n))
    sets = sorted(set(r["meta"].get("oracle_lo_set", "?") for r in runs))
    offs_meta = sorted(set(r["meta"].get("oracle_lo_off", "?") for r in runs))
    if len(sets) > 1 or len(offs_meta) > 1:
        print("WARNING: mixed oracle_lo geometry in this report: "
              "set=%s off=%s (split arms; do not compare as one pool)" %
              (",".join(sets), ",".join(offs_meta)))
    else:
        print("oracle_lo_off=%s  oracle_lo_set=%s" %
              (offs_meta[0] if offs_meta else "?",
               sets[0] if sets else "?"))

    if csv_path:
        with open(csv_path, "w") as f:
            f.write("offset,register,line,set,rate,n_ok,n_truth,pooled,"
                    "truth_majority,truth_varies\n")
            for x in rows:
                lo, st = geo(x["off"])
                tmaj = x["truth"][0] if len(x["truth"]) == 1 else ""
                f.write("%d,%s,0x%03x,%d,%.3f,%d,%d,%d,%s,%d\n" %
                        (x["off"], x["reg"], lo, st, x["rate"], x["n_ok"],
                         x["n_truth"], x["pooled"], tmaj,
                         1 if len(x["truth"]) > 1 else 0))
        print("\ncsv written: %s" % csv_path)
    return {"n": n, "canary_12": canary_ok,
            "oracle_lo_off": offs_meta[0] if len(offs_meta) == 1 else "mixed",
            "oracle_lo_set": sets[0] if len(sets) == 1 else "mixed"}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dumps", nargs="*", help="VOTE_DUMP files (globs allowed)")
    ap.add_argument("--collect", metavar="BIN",
                    help="run BIN N times with VOTE_DUMP set, then aggregate")
    ap.add_argument("-n", type=int, default=20,
                    help="runs in collect mode (default 20)")
    ap.add_argument("--votes", type=int,
                    help="WARM_VOTES per trace in collect mode")
    ap.add_argument("--outdir", default="/tmp/ssawarm-votes",
                    help="collect output dir (default /tmp/ssawarm-votes)")
    ap.add_argument("--alt-env", metavar="VAR=v1,v2",
                    help="interleave collect: run i gets v[(i-1)%%N] "
                         "(e.g. ORACLE_LO_OFF=0,0x400). Each arm is reported "
                         "separately; -n is the TOTAL run count")
    ap.add_argument("--raw-lat", action="store_true",
                    help="also set RAW_LAT_DUMP per run (RAW_LAT_OFF=120,80)")
    ap.add_argument("--csv", metavar="FILE", help="also write per-offset CSV")
    a = ap.parse_args()

    files = [f for pat in a.dumps for f in glob.glob(pat)]
    summaries = []
    if a.collect:
        alt = parse_alt_env(a.alt_env)
        by_arm = collect(a.collect, a.n, a.votes, a.outdir, alt, a.raw_lat)
        if alt:
            print("")
            for arm, arm_dir, arm_files in by_arm:
                print("======== arm %s=%s  (%d dumps in %s) ========" %
                      (alt[0], arm, len(arm_files), arm_dir))
                if not arm_files:
                    print("(no successful dumps)")
                    continue
                csv_path = None
                if a.csv:
                    root, ext = os.path.splitext(a.csv)
                    csv_path = "%s_%s%s" % (root, arm, ext or ".csv")
                summaries.append((arm, report(arm_files, csv_path)))
                raws = sorted(glob.glob(os.path.join(arm_dir, "run*.rawlat")))
                if raws:
                    rawlat_summary(raws)
                print("")
            print("======== Phase-0 A/B (single-run canary 12/12) ========")
            for arm, s in summaries:
                print("  %s=%-8s  12/12 = %d/%d   oracle_lo_set=%s" %
                      (alt[0], arm, s["canary_12"], s["n"], s["oracle_lo_set"]))
            return
        files += by_arm[0][2]
    if not files:
        ap.error("give dump files or --collect BIN")
    report(files, a.csv)


if __name__ == "__main__":
    main()
