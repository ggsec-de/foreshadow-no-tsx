#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
"""Summarise Phase-0 dumps: per-run 12/12-ish scores from logs, lo-vote
on the true class for the 12 canary GPRs, rawlat hotness."""
import glob
import os
import sys

CANON = {
    0: 0xbe, 1: 0xba, 2: 0xfe, 3: 0xca, 4: 0xef, 5: 0xbe, 6: 0xad, 7: 0xde,  # rax
    8: 0xad, 9: 0xaa, 10: 0xaa, 11: 0xaa, 12: 0xdb, 13: 0x00, 14: 0x00, 15: 0xd0,  # rcx
    16: 0x0d, 17: 0xf0, 18: 0xad, 19: 0xba, 20: 0xde, 21: 0xc0, 22: 0xad, 23: 0xde,  # rdx
    24: 0x00, 25: 0xad, 26: 0xbb, 27: 0xda, 28: 0x00, 29: 0xad, 30: 0xbb, 31: 0xda,  # rbx
    64: 0x88, 65: 0x88, 66: 0x88, 67: 0x88, 68: 0x88, 69: 0x88, 70: 0x88, 71: 0x88,
    72: 0x99, 73: 0x99, 74: 0x99, 75: 0x99, 76: 0x99, 77: 0x99, 78: 0x99, 79: 0x99,
    80: 0x10, 81: 0x10, 82: 0x10, 83: 0x10, 84: 0x10, 85: 0x10, 86: 0x10, 87: 0x10,
    88: 0x11, 89: 0x11, 90: 0x11, 91: 0x11, 92: 0x11, 93: 0x11, 94: 0x11, 95: 0x11,
    96: 0x12, 97: 0x12, 98: 0x12, 99: 0x12, 100: 0x12, 101: 0x12, 102: 0x12, 103: 0x12,
    104: 0x13, 105: 0x13, 106: 0x13, 107: 0x13, 108: 0x13, 109: 0x13, 110: 0x13, 111: 0x13,
    112: 0x14, 113: 0x14, 114: 0x14, 115: 0x14, 116: 0x14, 117: 0x14, 118: 0x14, 119: 0x14,
    120: 0x15, 121: 0x15, 122: 0x15, 123: 0x15, 124: 0x15, 125: 0x15, 126: 0x15, 127: 0x15,
}
HOT = 150


def parse_votes(path):
    e, d, lo, hi = {}, {}, {}, {}
    meta = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                p = line[1:].split()
                if len(p) >= 2:
                    meta[p[0]] = p[1]
                continue
            p = line.split()
            if p[0] == "E":
                e[int(p[1])] = int(p[2])
            elif p[0] == "D":
                d[int(p[1])] = int(p[2])
            elif p[0] == "L":
                lo[int(p[1])] = [int(x) for x in p[2:]]
            elif p[0] == "H":
                hi[int(p[1])] = [int(x) for x in p[2:]]
    return meta, e, d, lo, hi


def argmax(xs):
    b = 0
    for i in range(1, len(xs)):
        if xs[i] > xs[b]:
            b = i
    return b


def summarize_arm(d):
    print("==== %s ====" % d)
    logs = sorted(glob.glob(os.path.join(d, "run*.log")))
    for lg in logs:
        with open(lg) as f:
            for line in f:
                if "TRANSIENT-WARM" in line or "oracle_lo used" in line:
                    print(os.path.basename(lg), line.strip())
    votes = sorted(glob.glob(os.path.join(d, "run*.votes")))
    # per-offset: fraction of votes on true lo-class, averaged over runs
    true_frac = {off: [] for off in CANON}
    hi_ok = {off: [] for off in CANON}
    byte_ok = {off: [] for off in CANON}
    for vp in votes:
        meta, e, dcd, lo, hi = parse_votes(vp)
        for off, val in CANON.items():
            if off not in lo or off not in e:
                continue
            tlo = val & 0x3f
            thi = val >> 6
            s = sum(lo[off]) or 1
            true_frac[off].append(lo[off][tlo] / float(s))
            h = hi.get(off, [0, 0, 0, 0])
            hi_ok[off].append(1.0 if (h and argmax(h) == thi) else 0.0)
            byte_ok[off].append(1.0 if dcd.get(off) == e.get(off) == val else 0.0)
    print("-- canary lo-vote on TRUE class (mean over runs) --")
    for name, base in [("rax", 0), ("rcx", 8), ("rdx", 16), ("rbx", 24),
                       ("r8", 64), ("r9", 72), ("r10", 80), ("r11", 88),
                       ("r12", 96), ("r13", 104), ("r14", 112), ("r15", 120)]:
        xs = []
        hx = []
        bx = []
        for off in range(base, base + 8):
            if true_frac[off]:
                xs.append(sum(true_frac[off]) / len(true_frac[off]))
                hx.append(sum(hi_ok[off]) / len(hi_ok[off]))
                bx.append(sum(byte_ok[off]) / len(byte_ok[off]))
        print("  %-4s lo-true %.2f  hi-ok %.2f  byte-ok %.2f   per-byte lo %s" %
              (name, sum(xs) / 8, sum(hx) / 8, sum(bx) / 8,
               " ".join("%.2f" % v for v in xs)))
    raws = sorted(glob.glob(os.path.join(d, "run*.rawlat")))
    if not raws:
        return
    hot = {}
    ntr = {}
    for rp in raws:
        truth = {}
        with open(rp) as f:
            for line in f:
                line = line.strip()
                if line.startswith("# off"):
                    p = line.split()
                    truth[int(p[2])] = int(p[6])
                elif line.startswith("R "):
                    p = line.split()
                    off = int(p[1])
                    lats = [int(x) for x in line.split(":", 1)[1].split()]
                    cls = truth.get(off)
                    if cls is None or cls >= len(lats):
                        continue
                    ntr[off] = ntr.get(off, 0) + 1
                    if lats[cls] < HOT:
                        hot[off] = hot.get(off, 0) + 1
                    # also: any slot hot?
                    anyh = any(t < HOT for t in lats)
                    hot.setdefault(("any", off), 0)
                    ntr.setdefault(("any", off), 0)
                    ntr[("any", off)] += 1
                    if anyh:
                        hot[("any", off)] += 1
    print("-- rawlat true-class hot / any-slot hot --")
    for off in sorted(k for k in ntr if not isinstance(k, tuple)):
        print("  off %d  true %d/%d  any %d/%d" %
              (off, hot.get(off, 0), ntr[off],
               hot.get(("any", off), 0), ntr[("any", off)]))


def main():
    arms = sys.argv[1:] or [
        "/tmp/ssawarm-votes-shift/ORACLE_LO_OFF=0",
        "/tmp/ssawarm-votes-shift/ORACLE_LO_OFF=0x400",
    ]
    for a in arms:
        summarize_arm(a)
        print("")


if __name__ == "__main__":
    main()
