#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
"""Adjudicate the value-vs-line hypothesis on existing VOTE_DUMP runs.

Tests, root-free, on the 30 dumps we already have:
  T0  oracle base L1D set per run (is the geometry fixed across runs?)
  T1  identical failure bitmaps for equal constant-truth VALUES across
      different offsets/lines (colleague's central claim)
  T2  per-run failure count (is there a per-run global quality gate?)
  T3  touched L1D set of failing values (lo-class, hi-class) -- concentrated
      on the SSA sets 61/62/63, or spread?
  T4  is the set of failing values fixed across runs or re-drawn each run?
  T5  composite majority/N correctness for constant-truth bytes
"""
import sys, glob

LO, HI, STRIDE = 64, 4, 0x1040
REGS = [("rax",0),("rcx",8),("rdx",16),("rbx",24),("rsp",32),("rbp",40),
        ("rsi",48),("rdi",56),("r8",64),("r9",72),("r10",80),("r11",88),
        ("r12",96),("r13",104),("r14",112),("r15",120),
        ("rflags",128),("rip",136),("ursp",144)]

def reg(off):
    if off >= 152: return "rsvd"
    for n,b in REGS:
        if b <= off < b+8: return "%s[%d]"%(n,off-b)
    return "?"

def parse(path):
    meta,e,d,lo,hi = {},{},{},{},{}
    for line in open(path):
        line=line.strip()
        if not line: continue
        if line[0]=="#":
            p=line[1:].split()
            if len(p)>=2: meta[p[0]]=p[1]
            continue
        p=line.split(); k=p[0]
        if k=="E": e[int(p[1])]=int(p[2])
        elif k=="D": d[int(p[1])]=int(p[2])
        elif k=="L": lo[int(p[1])]=[int(x) for x in p[2:]]
        elif k=="H": hi[int(p[1])]=[int(x) for x in p[2:]]
    return {"meta":meta,"E":e,"D":d,"L":lo,"H":hi,"path":path}

def amax(xs):
    b=0
    for i in range(1,len(xs)):
        if xs[i]>xs[b]: b=i
    return b

files=sorted(f for pat in sys.argv[1:] for f in glob.glob(pat))
runs=[parse(f) for f in files]
N=len(runs)
offs=sorted(runs[0]["E"])
print("runs=%d bytes=%d"%(N,len(offs)))

# T0: oracle base set + ssa set per run
print("\n== T0  geometry per run (set = (VA>>6)&63) ==")
b_lo=set(); b_hi=set(); ssa_set=set()
for r in runs:
    olo=int(r["meta"]["oracle_lo"],16); ohi=int(r["meta"]["oracle_hi"],16)
    ssa=int(r["meta"]["alias_ssa"],16)
    b_lo.add((olo>>6)&63); b_hi.add((ohi>>6)&63); ssa_set.add((ssa>>6)&63)
print("oracle_lo base sets across runs:", sorted(b_lo))
print("oracle_hi base sets across runs:", sorted(b_hi))
print("ssa GPRSGX-start sets across runs:", sorted(ssa_set),
      "(page off 0xf48 -> set 61)")
# slot c -> set (base_lo + c) mod 64 ; with base 0 that's c
print("=> if base sets are a single value, oracle->L1Dset map is FIXED "
      "across runs (ASLR does NOT move L1D sets: index = VA bits 6-11 = "
      "page offset).")

# constant-truth offsets only
const={}   # off -> truth
for off in offs:
    ts=set(r["E"][off] for r in runs if off in r["E"])
    if len(ts)==1: const[off]=next(iter(ts))
print("\nconstant-truth offsets: %d/%d (rest vary per run -> voting N/A)"
      %(len(const),len(offs)))

# failure bitmap per constant-truth offset
def bmap(off):
    return tuple(1 if (off in r["D"] and r["D"][off]!=r["E"][off]) else 0
                 for r in runs)
bm={off:bmap(off) for off in const}

# T1: equal value -> identical bitmap?  group by value
print("\n== T1  identical failure bitmap for equal VALUE across offsets? ==")
byval={}
for off,v in const.items():
    byval.setdefault(v,[]).append(off)
worst=0; multi=0
for v,os in sorted(byval.items()):
    if len(os)<2: continue
    lines=set(((0xf48+o)&0xfc0) for o in os)  # distinct cache lines (page off)
    if len(lines)<2: continue                 # only interesting across lines
    multi+=1
    base=bm[os[0]]
    ham=max(sum(a!=b for a,b in zip(base,bm[o])) for o in os)
    worst=max(worst,ham)
    fr=sum(base)  # failing runs for this value
    if ham>0 or fr>0:
        print(" v=0x%02x lines=%s offs=%s failing_runs=%d maxHamming=%d %s"
              %(v,sorted("0x%03x"%l for l in lines),os,fr,ham,
                "IDENTICAL" if ham==0 else "DIFFER"))
print("multi-line values checked=%d  worst intra-value Hamming=%d"%(multi,worst))

# T2: per-run failure count over constant-truth bytes
print("\n== T2  per-run failure count (constant-truth bytes) ==")
per=[sum(bm[off][i] for off in const) for i in range(N)]
order=sorted(range(N),key=lambda i:per[i])
print("min=%d max=%d  sorted:"%(min(per),max(per)),
      " ".join("%d"%per[i] for i in order))

# T3: touched sets of failing values
print("\n== T3  touched L1D set of failing values (aggregated) ==")
lo_fail={}; hi_fail={}
for off,v in const.items():
    f=sum(bm[off])
    if f==0: continue
    lc=v&0x3f; hc=(v>>6)&3
    lo_fail[lc]=lo_fail.get(lc,0)+f
    hi_fail[hc]=hi_fail.get(hc,0)+f
print("lo-class(set) : failing-run-count  (set==class for page-aligned oracle)")
for c in sorted(lo_fail): print("  set %2d : %d"%(c,lo_fail[c]))
print("hi-class : failing-run-count :", dict(sorted(hi_fail.items())))
print("(SSA read touches sets 61/62/63; if failing lo-sets are NOT 61/62/63, "
      "the miss is NOT an oracle-slot<->SSA-line set collision)")

# T4: is the failing-value set fixed or re-drawn each run?
print("\n== T4  failing VALUE set per run (const-truth) ==")
for i in range(N):
    vs=sorted(set("0x%02x"%const[off] for off in const if bm[off][i]))
    print(" run%02d n=%2d %s"%(i+1,len(vs),vs))

# T5: composite majority/N for constant-truth bytes
print("\n== T5  composite (majority over %d runs) for const-truth bytes =="%N)
ok=0
badcomp=[]
for off in sorted(const):
    ls=[0]*LO; hs=[0]*HI
    for r in runs:
        lv=r["L"].get(off);  hv=r["H"].get(off)
        if lv:
            for c in range(min(LO,len(lv))): ls[c]+=lv[c]
        if hv:
            for c in range(min(HI,len(hv))): hs[c]+=hv[c]
    pooled=((amax(hs)&3)<<6)|(amax(ls)&0x3f)
    if pooled==const[off]: ok+=1
    else: badcomp.append((off,reg(off),const[off],pooled))
print("composite correct: %d/%d constant-truth bytes"%(ok,len(const)))
for off,rn,t,p in badcomp:
    print("  MISS off %d %s truth 0x%02x pooled 0x%02x"%(off,rn,t,p))
