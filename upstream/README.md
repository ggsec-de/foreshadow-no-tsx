<!--
GGSEC modifications and additions:
Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
-->

# Upstream submission pack -- jovanbulck/sgx-step

Ready-to-post material for reporting the two defects found while reproducing
`app/foreshadow` and for contributing the enclave-free variant back.

Everything here is **English** and matches the upstream repository conventions
(GPLv3, `app/<name>/main.c` + Makefile, `NO_SGX=1` for SDK-free apps).

## Order of submission

| # | Artifact | Kind | File |
|---|---|---|---|
| 1 | `transient_access()` can spin forever on a 0x00 byte | issue | `issue-1-transient-access-unbounded-retry.md` |
| 2 | Stray semicolon makes `FORESHADOW_ZERO_RETRIES` a no-op | issue | `issue-2-foreshadow-zero-retry-noop.md` |
| 3 | `app/foreshadow-sim`: enclave-free PoC, no SDK required | PR | `pr-1-app-foreshadow-sim.md` |
| 4 | Kernel 7.1.x port for `/dev/sgx-step` | PR (optional) | `pr-2-kernel-7.1-port.md` |

Issues first, then the PRs -- the hanging loop is a user-visible defect and the
`app/foreshadow-sim` PR depends on its fix (otherwise a secret containing `0x00`
hangs the new app as well).

Attach alongside the issue text:

- `patches/0002-libsgxstep-bound-transient-retry.patch` (for issue 1)
- `patches/0003-libsgxstep-foreshadow-zero-retry.patch` (for issue 2)

## Checklist before posting

- [ ] `git -C <sgx-step> fetch origin && git apply --check patches/0003-*.patch`
      against current `master`.
- [ ] Post issue 1 and issue 2 with the environment line (CPU, kernel, distro,
      microcode) -- both were verified on:
      Intel Core i3-6100 (Skylake, no flexible launch control), Kali Linux,
      kernel `7.1.5+kali-amd64`, firmware microcode `0xba`.
- [ ] Only after a reaction, open the PRs and reference the issues.

## Verification already performed (2026-09-16)

Run on the real tree (`~/sgx-step`, `master` plus the local 7.1.x port):

| patch | `git apply --check` | meaning |
|---|---|---|
| `patches/0001-sgxstep-kernel-7.1.5-port.patch` | `--reverse` = 0 | valid, already applied |
| `patches/0002-libsgxstep-bound-transient-retry.patch` | `--reverse` = 0 | valid, already applied |
| `patches/0003-libsgxstep-foreshadow-zero-retry.patch` | forward = 0 | valid, applies to clean `master` |

All three are LF-only and were produced with `git diff` on the target tree.
Two earlier hand-written versions were rejected by `git apply` (CRLF endings,
and one context line missing its leading space), so the checks above are the
evidence that the shipped files are usable.

## What not to claim

- Do **not** claim that the stock `app/foreshadow` hangs: that was not observed.
  What was observed is the hang in an enclave-free harness that shares the same
  `transient_access()` code path and uses the same fault-handler behaviour as
  `app/foreshadow/main.c`. Say exactly that.
- Do **not** generalise the kernel port to "any recent kernel": only
  `7.1.5+kali-amd64` was tested. On that kernel, upstream needs exactly two
  changes and both are backwards compatible.
- The enclave-free harness proves the page-table manipulation, the transient
  read and the Flush+Reload oracle. It does **not** attack a real enclave -- say
  so up front, in the PR description.

## License

The harness derives from upstream GPLv3 code (`app/foreshadow/sim-enclave.c` is
copied verbatim, `app/foreshadow/main.c` is adapted), so any PR or snippet
posted here is under the same GPLv3 terms as the project.
