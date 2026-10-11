<!--
SPDX-License-Identifier: GPL-2.0-only
Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
-->

# License scope and attribution

Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG

Files carrying `SPDX-License-Identifier: GPL-2.0-only` are licensed under the GNU General Public License, version 2 only. The full text is in [LICENSE](LICENSE).

This is a file-specific declaration, not a relicensing of upstream material. Existing authorship credits and third-party license terms remain in effect. Copyright notices marked "GGSEC modifications and additions" refer only to those contributions.

## GPL-2.0-only files

- `README.md`
- `REPRODUCE.md`
- `STATUS.md`
- `WRITEUP-no-tsx.txt`
- `harness/dump-dual-gadget.sh`
- `harness/phase0-analyze.py`
- `harness/phase0-collect.sh`
- `harness/phase0-compare.py`
- `harness/phase0-diag.sh`
- `harness/phase0-oneshot.sh`
- `harness/phase0-prep.sh`
- `harness/phase1-collect.sh`
- `harness/phase1-oneshot.sh`
- `harness/read-dual.py`
- `harness/read-oneshot.py`
- `harness/value_corr.py`
- `harness/warm_vote_stats.py`
- `setup/00-diagnose.sh`
- `setup/10-grub-cmdline.sh`
- `setup/20-build-driver.sh`
- `setup/30-tune-libsgxstep.sh`
- `setup/40-build-poc.sh`
- `setup/45-build-leaktest.sh`
- `setup/90-start-lab.sh`
- `LICENSE_SCOPE.md`

## Files retaining their existing upstream or unresolved terms

- `harness/aep-hook-test.c`
- `harness/aep_stub.c`
- `harness/foreshadow-encl-split.Makefile`
- `harness/foreshadow-encl-split.c`
- `harness/foreshadow-ssa-warm.c`
- `harness/foreshadow-ssa.c`
- `harness/l1tf-mp-probe.c`
- `harness/leaktest.c`
- `harness/main.c`
- `harness/mispredict_gadget.h`
- `harness/mp-debug.c`
- `harness/selftest-decode.c`
- `harness/selftest-mispredict.c`
- `harness/selftest-mispredict2.c`
- `harness/selftest-mispredict3.c`
- `setup/25-patch-libsgxstep.sh`
- `setup/50-port-isgx.sh`
- `upstream/README.md`
- `upstream/issue-1-transient-access-unbounded-retry.md`
- `upstream/issue-2-foreshadow-zero-retry-noop.md`
- `upstream/pr-1-app-foreshadow-sim.md`
- `upstream/pr-2-kernel-7.1-port.md`

SGX-Step-derived harness code and upstream submission material retain the GPLv3 terms documented in [upstream/README.md](upstream/README.md). Patch files under `patches/` and `upstream/patches/` are unchanged and retain the terms of the code they modify. The GPL-2.0-only declaration for independent tooling does not cover code embedded in patches.
