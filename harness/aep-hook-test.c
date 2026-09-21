/*
 *  B.1 milestone 1: enable SGX-Step's AEP callback on the STOCK PSW 2.27 runtime
 *  by binary-hooking the untrusted runtime's async-exit-pointer at runtime.
 *
 *  The stock urts has no sgx_set_aep (aep_stub.c stubs it), so register_aep_cb()
 *  cannot redirect the AEP and the callback never fires. But the stock urts's
 *  default AEP is a fixed routine `.Lasync_exit_pointer` (= `ENCLU; ud2`,
 *  byte pattern 0f 01 d7 0f 0b, unique in libsgx_urts.so). We overwrite its
 *  entry at runtime with `movabs $sgx_step_aep_trampoline, %rax; jmp *%rax`
 *  (rax is dead here -- the trampoline reloads it with the ERESUME leaf). On the
 *  first AEX the CPU jumps to the (patched) AEP -> our trampoline -> the C
 *  callback -> ERESUME with RCX = trampoline, so every later AEX lands directly
 *  on the trampoline. This gives the warm CPL3 hook the transient SSA read needs,
 *  without rebuilding the runtime.
 *
 *  This milestone only proves the hook + callback fire: it triggers one AEX via a
 *  page fault on the enclave's trigger page and checks the callback ran.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

#include <sgx_urts.h>
#include "Enclave/encl_u.h"

#include "libsgxstep/config.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"

#define ENCLAVE_SO      "Enclave/encl.so"

/* provided by libsgxstep (aep_trampoline.S / enclave.c) */
extern void sgx_step_aep_trampoline(void);
extern aep_cb_t sgx_step_aep_cb;

sgx_enclave_id_t eid = 0;
void *secret_ptr = NULL, *secret_page = NULL;
volatile int aep_fired = 0, fault_fired = 0;

/* -------- binary hook of the stock urts AEP -------- */

static int hook_urts_aep(void)
{
    const unsigned char pat[5] = { 0x0f, 0x01, 0xd7, 0x0f, 0x0b }; /* ENCLU; ud2 */
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    uint64_t start, end;
    char perm[8], path[256];
    unsigned char *hit = NULL;

    ASSERT(f);
    while (fgets(line, sizeof(line), f))
    {
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255[^\n]",
                   &start, &end, perm, path) < 3)
            continue;
        if (perm[2] != 'x' || !strstr(path, "libsgx_urts.so"))
            continue;

        info("scanning urts exec map %#lx-%#lx (%s)", start, end, path);
        for (unsigned char *p = (unsigned char *) start; p + 5 <= (unsigned char *) end; p++)
        {
            if (memcmp(p, pat, 5) == 0) { hit = p; break; }
        }
        if (hit) break;
    }
    fclose(f);

    if (!hit)
    {
        info("AEP pattern not found");
        return -1;
    }

    info("stock AEP (.Lasync_exit_pointer) at %p; patching -> trampoline %p",
         hit, (void *) sgx_step_aep_trampoline);

    void *page = (void *) ((uintptr_t) hit & ~0xfffUL);
    /* the 12-byte patch may straddle a page boundary; unlock two pages */
    ASSERT( !mprotect(page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) );

    /* movabs $trampoline, %rax ; jmp *%rax */
    unsigned char patch[12] = { 0x48, 0xb8, 0,0,0,0,0,0,0,0, 0xff, 0xe0 };
    uint64_t tramp = (uint64_t) sgx_step_aep_trampoline;
    memcpy(patch + 2, &tramp, 8);
    memcpy(hit, patch, sizeof(patch));

    ASSERT( !mprotect(page, 0x2000, PROT_READ | PROT_EXEC) );
    __builtin___clear_cache((char *) hit, (char *) hit + 12);
    return 0;
}

/* -------- callback + fault handler -------- */

void aep_cb(void)
{
    aep_fired++;
}

void fault_handler(int sig)
{
    (void) sig;
    fault_fired++;
    /* make the trigger page present again so ERESUME can finish the enclave */
    ASSERT( !mprotect(secret_page, 0x1000, PROT_READ | PROT_WRITE) );
}

int main(int argc, char **argv)
{
    sgx_launch_token_t token = {0};
    int updated = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);

    info("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave(ENCLAVE_SO, /*debug=*/1, &token, &updated, &eid, NULL) );

    ASSERT( !claim_cpu(VICTIM_CPU) );
    ASSERT( signal(SIGSEGV, fault_handler) != SIG_ERR );

    /* install the warm CPL3 hook */
    ASSERT( !hook_urts_aep() );
    sgx_step_aep_cb = aep_cb;      /* set the callback directly (no sgx_set_aep needed) */

    SGX_ASSERT( enclave_generate_secret(eid, &secret_ptr) );
    secret_page = (void *) ((uint64_t) secret_ptr & ~UINT64_C(0xfff));

    info("revoking enclave trigger page to force one AEX...");
    ASSERT( !mprotect(secret_page, 0x1000, PROT_NONE) );

    info("entering enclave (expect: fault -> AEX -> AEP trampoline -> aep_cb)...");
    SGX_ASSERT( enclave_run(eid) );

    info("RESULT: aep_cb fired=%d ; SIGSEGV handled=%d ; eresume_cnt=%d",
         aep_fired, fault_fired, sgx_step_eresume_cnt);
    if (aep_fired > 0)
        info("[OK] AEP hook works on the stock runtime -- warm CPL3 callback is live");
    else
        info("[FAIL] AEP callback did not fire");

    return 0;
}
