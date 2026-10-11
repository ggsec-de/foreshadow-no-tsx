<!--
GGSEC modifications and additions:
Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
-->

# `libsgxstep/foreshadow.c`: stray semicolon makes `FORESHADOW_ZERO_RETRIES` a no-op

## Summary

`foreshadow()` is documented to be sceptical about `0x00` results and to retry
the measurement, but the `for` header is terminated by a semicolon. The loop body
is therefore empty, `foreshadow_round()` is called exactly once, and the retry
budget is never used.

## Affected code

    int foreshadow(void *adrs)
    {
        int j, rv = 0xff;

        if (!fs_reload_threshold)
            foreshadow_init();

        /* Be sceptic about 0x00 bytes to compensate for the bias */
        for(j=0; (rv==0x00 || rv==0xff) && j < FORESHADOW_ZERO_RETRIES; j++, fs_zero_retries++);
            rv = foreshadow_round(adrs);

        return rv;
    }

The `;` after the `for(...)` header ends the statement: the loop body is empty
and `rv = foreshadow_round(adrs);` runs once, after the loop. The increment
clause still runs, so `j++` and `fs_zero_retries++` both execute while the
condition holds. The retry counter increases even though no additional
measurements occur.

## Consequences

- No extra measurement happens, so a spurious `0x00` from the zero bias of
  speculative reads is reported as the value of the secret byte.
- `fs_zero_retries` does increase (it is in the `for` increment, not in the
  empty body). A printed `0x00 retries=0` is not evidence that the increment
  was skipped: the `Foreshadow perf:` line that carries the counter is compiled
  out of `NO_SGX` builds.

Observed in every run of our harness (`NO_SGX=1`, Kali kernel 7.1.5,
i3-6100):

    [foreshadow.c] Foreshadow conf: 0X00_RETRIES=20 SSA_0x00_RETRIES=20

(the `Foreshadow perf:` line is compiled out of `NO_SGX` builds, so the
increment was checked in the source. A first pass had 9 spurious zeros out of
64 bytes; restoring the loop body would have remeasured those bytes.)

## Suggested fix

    -    for(j=0; (rv==0x00 || rv==0xff) && j < FORESHADOW_ZERO_RETRIES; j++, fs_zero_retries++);
    +    for(j=0; (rv==0x00 || rv==0xff) && j < FORESHADOW_ZERO_RETRIES; j++, fs_zero_retries++)
             rv = foreshadow_round(adrs);

Patch attached: `0003-libsgxstep-foreshadow-zero-retry.patch`.

Note for review: once the body is restored, a genuinely zero byte costs up to
`FORESHADOW_ZERO_RETRIES` extra rounds. Callers that retry at a higher level
(revoking the PTE between attempts, as discussed in the sibling issue) may
prefer a smaller budget.
