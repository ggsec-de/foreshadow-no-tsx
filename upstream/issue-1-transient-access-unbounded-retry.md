<!--
GGSEC modifications and additions:
Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
-->

# `transient_access()` can spin forever when the measured byte is `0x00`

## Summary

`libsgxstep/transient.S` re-issues the speculative load until the shifted index
is non-zero. The loop has no iteration bound, so if the load keeps yielding
`0x00` the process spins at 100% CPU forever. A caller that re-presents the page
from its `SIGSEGV` handler (which is what `app/foreshadow` does) can hit this
with an ordinary secret that happens to contain a zero byte.

## Affected code

    transient_access:

        mov $0, %rax
        tzcnt  %rdx, %rcx             # slot_size <- log2( slot_size )

        #prefetcht0 (%rsi)

    retry:
        movb (%rsi), %al
        shl %cl, %rax
        jz retry                      # <-- unbounded
        movq (%rdi, %rax), %rdi
        retq

`rax = byte << 12`, so `byte == 0x00` keeps the branch taken. The load only
stops faulting after the handler has made the mapping present again, at which
point it keeps returning the real (zero) value -- hence no progress and no
additional page faults.

## Environment

- Intel Core i3-6100 (Skylake, 2C/4T, no flexible launch control)
- Kali Linux, kernel `7.1.5+kali-amd64`, firmware microcode `0xba`,
  `custom` boot parameters from the README (`pti=off`, `nosmep`, `nosmap`, ...)
- `libsgxstep` built with `NO_SGX=1`

## Observed behaviour

The producer was an enclave-free harness that reuses `app/foreshadow/main.c`'s
logic: revoke the alias PTE, `sim_reload()`, `foreshadow(alias_ptr + i)`, with
the same `fault_handler()` that restores `MARK_PRESENT(pte_alias_unmapped)` and
`mprotect(PROT_READ | PROT_WRITE)`. With random secrets, some runs completed
(64/64 bytes recovered) and one run whose secret contained a zero byte never
returned:

    $ ps -o pid,stat,etime,time,pcpu,min_flt,wchan:25 -C app
      PID STAT     ELAPSED     TIME %CPU MINFL WCHAN
     5641 R+         05:07 00:05:07 99.9   363 -

Two details worth noting, they are what pointed at `retry:`:

- `STAT R+` / `WCHAN -` -- spinning in user space, not blocked in a syscall;
- `MINFL` almost static at 363 while `TIME` tracks `ELAPSED` -- the loop is
  *not* faulting repeatedly, i.e. the load succeeds and returns zero.

`foreshadow_round()` itself is fully bounded (256 `flush` + 256 `reload`), and so
is the caller loop, so the spin has to come from the assembly above.

We could not test stock `app/foreshadow` on this machine (no flexible launch
control, so the in-tree SGX driver refuses to load, and the patched SDK was not
installed), so we are explicitly *not* claiming that it hangs. Its
`fault_handler()` restores the mapping in exactly the same way, which is why we
think the same path is reachable there.

## Suggested fix

Bound the retry, keeping the behaviour identical for non-zero bytes:

    +    mov $64, %r8                  # bound the retry loop for 0x00 values
     retry:
         movb (%rsi), %al
         shl %cl, %rax
    -    jz retry
    +    jnz done
    +    dec %r8
    +    jnz retry
    +done:
         movq (%rdi, %rax), %rdi
         retq

With the bound, a genuine `0x00` byte falls through with `rax == 0`, encodes
oracle slot 0, and reaches the caller as value 0 -- which is what the caller
already has to treat as "no hit" (see the zero-bias comment in
`foreshadow.h`).

Alternative if you prefer to keep the loop unbounded: document the requirement
that callers must not let the measured byte be `0x00` while the mapping is
present, and/or leave the page revoked for the whole transient block.

Patch attached: `0002-libsgxstep-bound-transient-retry.patch`.
