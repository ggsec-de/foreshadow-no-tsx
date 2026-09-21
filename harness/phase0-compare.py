#!/usr/bin/env python3
"""Phase-0 arm comparison on canary GPRs. Ignores stale rawlat."""
import glob, os, time

CANON = {
    0: 0xbe, 1: 0xba, 2: 0xfe, 3: 0xca, 4: 0xef, 5: 0xbe, 6: 0xad, 7: 0xde,
    8: 0xad, 9: 0xaa, 10: 0xaa, 11: 0xaa, 12: 0xdb, 13: 0x00, 14: 0x00, 15: 0xd0,
    16: 0x0d, 17: 0xf0, 18: 0xad, 19: 0xba, 20: 0xde, 21: 0xc0, 22: 0xad, 23: 0xde,
    24: 0x00, 25: 0xad, 26: 0xbb, 27: 0xda, 28: 0x00, 29: 0xad, 30: 0xbb, 31: 0xda,
    64: 0x88, 65: 0x88, 66: 0x88, 67: 0x88, 68: 0x88, 69: 0x88, 70: 0x88, 71: 0x88,
    72: 0x99, 73: 0x99, 74: 0x99, 75: 0x99, 76: 0x99, 77: 0x99, 78: 0x99, 79: 0x99,
    80: 0x10, 81: 0x10, 82: 0x10, 83: 0x10, 84: 0x10, 85: 0x10, 86: 0x10, 87: 0x10,
    88: 0x11, 89: 0x11, 90: 0x11, 91: 0x11, 92: 0x11, 93: 0x11, 94: 0x11, 95: 0x11,
    96: 0x12, 97: 0x12, 98: 0x12, 99: 0x12, 100: 0x12, 101: 0x12, 102: 0x12, 103: 0x12,
    104: 0x13, 105: 0x13, 106: 0x13, 107: 0x13, 108: 0x13, 109: 0x13, 110: 0x13, 111: 0x13,
    112: 0x14, 113: 0x14, 114: 0x14, 115: 0x14, 116: 0x14, 117: 0x14, 118: 0x14, 119: 0x14,
    120: 0x15, 121: 0x15, 122: 0x15, 123: 0x15, 124: 0x15, 125: 0x15, 126: 0x15, 127: 0x15,
}
REGS = [("rax", 0), ("rcx", 8), ("rdx", 16), ("rbx", 24),
        ("r8", 64), ("r9", 72), ("r10", 80), ("r11", 88),
        ("r12", 96), ("r13", 104), ("r14", 112), ("r15", 120)]


def parse(path):
    e, d, lo, meta = {}, {}, {}, {}
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
    return meta, e, d, lo


def load_arm(d):
    files = sorted(glob.glob(os.path.join(d, "run*.votes")))
    runs = [parse(p) for p in files]
    logs = sorted(glob.glob(os.path.join(d, "run*.log")))
    scores = []
    for lg in logs:
        with open(lg) as f:
            for line in f:
                if "TRANSIENT-WARM" in line:
                    scores.append(line.strip())
    raws = sorted(glob.glob(os.path.join(d, "run*.rawlat")))
    return files, runs, scores, raws


def reg_ok(run, base):
    _, e, d, _ = run
    offs = list(range(base, base + 8))
    return all(o in e and o in d and d[o] == e[o] for o in offs)


def byte_rate(runs, off):
    n = ok = 0
    for _, e, d, _ in runs:
        if off in e and off in d:
            n += 1
            if d[off] == e[off]:
                ok += 1
    return ok, n


def lo_true_frac(runs, off, val):
    tlo = val & 0x3f
    xs = []
    for _, e, d, lo in runs:
        if off not in lo:
            continue
        s = sum(lo[off]) or 1
        xs.append(lo[off][tlo] / float(s))
    return (sum(xs) / len(xs)) if xs else float("nan")


def main():
    for label, d in [
        ("off=0", "/tmp/ssawarm-votes-shift/ORACLE_LO_OFF=0"),
        ("off=0x400", "/tmp/ssawarm-votes-shift/ORACLE_LO_OFF=0x400"),
    ]:
        files, runs, scores, raws = load_arm(d)
        print("==== %s  n=%d dumps ====" % (label, len(runs)))
        if runs:
            print("  meta", runs[0][0])
        print("  votes mtimes:",
              " ".join(time.strftime("%H:%M:%S", time.localtime(os.path.getmtime(p)))
                       for p in files[:3]), "...")
        print("  rawlat files", len(raws),
              "mtimes", " ".join(time.strftime("%H:%M:%S", time.localtime(os.path.getmtime(p)))
                                 for p in raws[:3]) if raws else "")
        for s in scores:
            print(" ", s)
        n12 = sum(1 for r in runs if all(reg_ok(r, b) for _, b in REGS))
        print("  single-run 12/12: %d/%d" % (n12, len(runs)))
        print("  -- registers fully-correct --")
        for name, base in REGS:
            ok = sum(1 for r in runs if reg_ok(r, base))
            bads = []
            for off in range(base, base + 8):
                o, n = byte_rate(runs, off)
                if o < n:
                    bads.append("%d=%d/%d" % (off, o, n))
            print("   %-4s %2d/%d  %s" % (name, ok, len(runs),
                                          ("bad " + ",".join(bads)) if bads else "ok"))
        print("  -- lo-vote on TRUE class (mean)  value  class  set_if_off0  set_if_400 --")
        for name, base in REGS:
            val = CANON[base]
            cls = val & 0x3f
            fr = [lo_true_frac(runs, off, CANON[off]) for off in range(base, base + 8)]
            print("   %-4s 0x%02x cls %2d  set %2d/%2d  lo-true %.2f  %s" %
                  (name, val, cls, cls, (cls + 16) & 63,
                   sum(fr) / 8, " ".join("%.2f" % x for x in fr)))
        print("")


if __name__ == "__main__":
    main()
