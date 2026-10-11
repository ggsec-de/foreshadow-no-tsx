/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/*
 * Link stubs for SGX-Step's patched untrusted runtime.
 *
 * libsgxstep/enclave.c declares and calls three helpers that only exist in
 * SGX-Step's *patched* Intel SDK urts (they let an attacker swap in a custom
 * asynchronous-exit pointer):
 *
 *     void *sgx_get_aep(void);
 *     void  sgx_set_aep(void *aep);
 *     void *sgx_get_tcs(void);
 *
 * The Foreshadow application never calls register_aep_cb(), i.e. it never asks
 * for a custom AEP: the fault path it needs (revoked PTE -> enclave access ->
 * asynchronous exit -> SIGSEGV in the untrusted process) is exactly what the
 * stock runtime provides. Building its enclave therefore only needs the stock
 * Linux PSW 2.27 runtime -- the one that still implements Launch Enclave based
 * launch, which is what a CPU without flexible launch control requires.
 *
 * These stubs exist purely so that the linker is satisfied. Nothing in this
 * program's path reaches them; see README section 13.
 *
 * Build it by extending the application's source list, so that SGX-Step's own
 * Makefile stays untouched:
 *
 *     make SGX_SDK=$HOME/sgxsdk/sdk227 SOURCES="main.c aep_stub.c"
 */

void *sgx_get_aep( void )
{
    return 0;
}

void sgx_set_aep( void *aep )
{
    (void) aep;
}

void *sgx_get_tcs( void )
{
    return 0;
}
