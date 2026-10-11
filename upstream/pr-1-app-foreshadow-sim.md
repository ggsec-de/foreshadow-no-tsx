<!--
GGSEC modifications and additions:
Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
-->

# `app/foreshadow-sim`: enclave-free Foreshadow/L1TF PoC (no SDK required)

## Motivation

`app/foreshadow` needs `EENTER`, which needs an SGX driver and a CPU that can
create enclaves. Several perfectly good research machines cannot do either:

- consumer Skylake and later client parts have **no flexible launch control**, so
  the in-tree `/dev/sgx_enclave` driver disables itself
  (`sgx: SGX disabled: SGX launch control CPU feature is not available`);
- with a microcode update in place, the L1D flush on enclave entry/exit means the
  extraction returns no hits anyway;
- installing the patched Intel SDK (v2.29 + GCC 15 on a rolling distro) is a
  project of its own.

The interesting part of the PoC -- clear the *present* bit of the PTE while
keeping the PFN, read the page transiently, recover bytes through the
Flush+Reload oracle -- does not need SGX at all. This app is that part.

## What it adds

- `app/foreshadow-sim/Makefile` -- built with `NO_SGX=1` like `app/selftest/*`,
  links only against `libsgxstep`, no Intel SDK, no `Enclave/` subdirectory.
- `app/foreshadow-sim/main.c` -- mirrors the `SIM_ENCLAVE=1` path of
  `app/foreshadow/main.c`: same globals, same `fault_handler()`, same
  `unmap_alias()` / `sim_reload()` / `foreshadow()` loop. `sim-enclave.c` is
  copied in verbatim rather than added as a second translation unit, because
  these app Makefiles build a single `main.c`.
- `libsgxstep/transient.S` -- bounded retry loop, as discussed in the issue
  referenced below. Required: without it the new app hangs on a secret that
  contains a `0x00` byte.

Additions on top of the upstream SIM path, both optional:

- a per-byte retry that re-revokes the PTE between attempts (the built-in retry
  cannot leak because the handler has already restored the mapping -- it also
  never runs, see the sibling issue);
- a `SIGALRM` watchdog (`WATCHDOG=<sec>`, default 30) so a stuck measurement is
  reported instead of spinning forever, plus `SEED=<n>` / `RETRIES=<n>` knobs so
  a failing run can be reproduced.

## What it does not do

It does **not** attack an enclave. There is no `EENTER`, no SSA/GPRSGX
extraction, and the secret is a plain aligned array written from the same
process. It is a faithful reproduction of the primitive and of the three attack
phases, not of the enclave scenario.

## Testing

Intel Core i3-6100, Kali Linux, kernel `7.1.5+kali-amd64`, firmware microcode
`0xba`, boot parameters from the top-level README, `/dev/sgx-step` built from
this tree with the two changes described in the kernel PR. Three consecutive
runs with random secrets:

| seed | result | handled SIGSEGV |
|---|---|---|
| `0x6aaacd93` | 64/64 bytes | 64 |
| `0x6aaacd9e` | 64/64 bytes | 128 |
| `0x6aaacd85` | 64/64 bytes | 122 |

`dmesg` shows a clean IDT/APIC save-restore cycle for every run and the machine
stays healthy afterwards (all `Local timer interrupts` counters keep
increasing). A copy of the app is also runnable as a plain file, so it doubles as
a smoke test for `/dev/sgx-step` on new kernels.

## Notes

- `main.c` is GPLv3, derived from `app/foreshadow/sim-enclave.c` and
  `app/foreshadow/main.c`.
- If you would rather keep the tree free of duplicated `sim-enclave.c`, the
  alternative is to add a `SIM_ENCLAVE`-style switch to `app/foreshadow` that
  also guards the SDK includes -- happy to rework the PR that way.
