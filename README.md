# Foreshadow (L1TF) PoC -- lab reconstruction on `.86`

Goal: rebuild the upstream SGX-Step Foreshadow PoC on the lab host
`Detox-01` (Kali Linux, kernel `7.1.5+kali-amd64`) so the L1TF/L1D
extraction can be reproduced and measured locally.

Upstream: <https://github.com/jovanbulck/sgx-step/tree/master/app/foreshadow>
Paper: <https://foreshadowattack.eu/foreshadow.pdf> (USENIX Security '18)

> **This directory deliberately weakens the machine** (KPTI off, SMEP/SMAP/UMIP
> off, microcode updates disabled, `iomem=relaxed`). Run it only on the
> dedicated lab box, never on a machine that holds real data or keys.

---

## Status (2026-09-21)

**Both halves reproduce on this host.** A real SGX enclave is created and
initialised through the legacy `isgx` driver plus Intel's Launch Enclave, and the
Foreshadow attack runs end to end against it, recovering real secret bytes from
L1D with unpatched microcode (see `[sched.c] continuing on CPU 1` and
`[foreshadow.c] cache hit/miss=…` in a PoC run). The GPRSGX register frame is
recovered on the SIGSEGV path without TSX: a single run is typically 10-12/12
(a clean 12/12 occurs), and the cross-run majority over 30 runs is 12/12,
96/96 on the fixed canaries. The public write-up is
[`WRITEUP-no-tsx.txt`](WRITEUP-no-tsx.txt). Detail is in [`STATUS.md`](STATUS.md).

What it took — the 2 MiB mapping alignment, the TCS capture for the stock
runtime, the PSW/protobuf library paths — is in [`STATUS.md`](STATUS.md).
How to run it from a cold boot is [`REPRODUCE.md`](REPRODUCE.md).

The attack-yield gap (~10% with the flat library oracle) is now understood: the
enclave path is purely transient (the sim's 64/64 relies on architectural
re-execution, which reads the 0xff abort page on a real enclave), and the
256-slot / 0x1000 oracle collapses into one L1D set here, so it cannot be decoded
transiently. The fix — the split lo/hi oracle already validated at 0/64 by
`leaktest.c` — is implemented and build-verified as two deliverables (section 14
and `STATUS.md`): **(a)** an `FS_SPLIT_ORACLE=1` path patched into `libsgxstep` +
`app/foreshadow`, and **(b)** a dedicated `app/foreshadow-encl-split`. Both were verified 64/64 on
the real enclave on 2026-09-17: (a) `[OK] Foreshadow correctly derived all 64
bytes!`, (b) `[OK] trial 0: recovered all 64 bytes!` with `faults=68` per byte.

Start-up after a reboot is one script: `setup/90-start-lab.sh`.

## 1. What "the missing driver" actually is

There is no *Foreshadow* driver. The PoC needs three distinct things, and on
`.86` the first one is the missing piece:

| # | Component | Source | Device / artifact | Symptom when missing |
|---|-----------|--------|-------------------|----------------------|
| 1 | SGX-Step LKM | `kernel/sgxstep.c` | `/dev/sgx-step` | `ASSERT ... /dev/sgx-step` in `libsgxstep` |
| 2 | SGX driver | submodule `kernel/linux-sgx-driver` (legacy `isgx`) **or** in-tree `CONFIG_X86_SGX` | `/dev/isgx` or `/dev/sgx_enclave` | `sgx_create_enclave` fails |
| 3 | `msr` module | distro | `/dev/cpu/*/msr` | warnings / MSR gates unusable |

What `/dev/sgx-step` is for (README of the framework):

* lets `libsgxstep` map the local APIC MMIO page and arbitrary PTEs from user space;
* fires a kretprobe on `devmem_is_allowed` to bypass `CONFIG_STRICT_DEVMEM`;
* saves/restores the original IDT and APIC `LVTT`/`TDCR` on `open()`/`release()`.

Why the PoC needs it: the attack's step 2 clears the *present* bit of the
enclave's PTE. Since August 2018 Linux sanitizes the PFN on `mprotect`, so the
unprivileged `mprotect(PROT_NONE)` trick no longer works -- PTE manipulation must
go through the driver (`libsgxstep/pt.c` -> `/dev/mem`).

---

## 2. Phase 0 -- feasibility gate

```bash
cd labs/foreshadow/setup
sudo ./00-diagnose.sh | tee ~/foreshadow-phase0.txt
sudo ./check_sys.sh          # lives in the sgx-step tree root
```

Hard blockers, in order of severity:

1. **Not an Intel CPU** -> Foreshadow/L1TF does not exist on AMD. Stop.
2. **No SGX** (`sgx` flag missing, or BIOS has SGX disabled / no PRMRR) -> the
   `EENTER` path is impossible. `SIM_ENCLAVE=1` still demonstrates the L1TF
   primitive, but you are no longer attacking a real enclave.
3. **No flexible launch control (FLC)** -> the in-tree `/dev/sgx_enclave` driver
   disables itself (`sgx: SGX disabled: SGX launch control CPU feature is not
   available`). Check for the `sgx_lc` flag in `/proc/cpuinfo`. The only
   remaining enclave route is the legacy out-of-tree `isgx` driver, which then
   needs its own port to a modern kernel. Consumer Skylake (e.g. i3-6100) has
   no FLC, so this is expected there.
4. **L1TF mitigated by microcode** -> `dis_ucode_ldr` only skips the *early
   initrd* microcode; when the mitigation came from the BIOS ROM the L1D flush
   on enclave entry/exit stays in place and the extraction yields no hits. A/B
   test: boot with and without `dis_ucode_ldr` and compare the `microcode` field
   in `/proc/cpuinfo`. `Vulnerable` in
   `/sys/devices/system/cpu/vulnerabilities/l1tf` is what you want; a
   `Mitigation: ...` string means the enclave-based variant cannot produce hits
   and the enclave-free variant is the target.

---

## 3. Boot parameters

Required set (this is exactly what `check_sys.sh` greps out of the top-level
README and asserts against `/proc/cmdline`):

```
iomem=relaxed no_timer_check clearcpuid=308,295,514 pti=off isolcpus=1 \
nmi_watchdog=0 rcupdate.rcu_cpu_stall_suppress=1 msr.allow_writes=on vdso=0
```

`setup/10-grub-cmdline.sh` merges these idempotently into
`GRUB_CMDLINE_LINUX_DEFAULT` and adds:

* `dis_ucode_ldr` -- required for the Foreshadow extraction (disable with `DIS_UCODE=0`);
* `no5lvl` -- automatically, if the running kernel was built with `CONFIG_X86_5LEVEL=y`
  (`libsgxstep` cannot walk 5-level page tables);
* `intel_idle.max_cstate=1 processor.max_cstate=1` -- execution-time stability;
* **no** `nox2apic`, because `libsgxstep/config.h` uses `X2APIC=1` by default and
  recent CPUs with `LEGACY_XAPIC_DISABLED` only support x2APIC together with SGX.

It also drops `vm.mmap_min_addr=0` into `/etc/sysctl.d/99-sgx-step.conf`.

Notes on the flags: `clearcpuid=308,295,514` disables SMEP (308), SMAP (295) and
UMIP (514) -- required because SGX-Step installs the interrupt handler *in user
space*. `pti=off` is required to avoid kernel panics with user IRQ handlers.

The script prints the merged line and needs `--apply` to actually write anything.

---

## 4. Building `/dev/sgx-step`

The running kernel on this box is `7.1.5+kali-amd64`. The notes below were
written against the first port (6.19); the patches that actually build
`sgx-step` and legacy `isgx` on 7.1.5 are `patches/0001-sgxstep-kernel-7.1.5-port.patch`
and `patches/0004-isgx-kernel-7.1.5-port.patch`. `setup/20-build-driver.sh` and
`setup/50-port-isgx.sh` apply that path.

```bash
export SGXSTEP_DIR=$HOME/sgx-step          # or wherever the clone lives
git clone --recursive https://github.com/jovanbulck/sgx-step.git "$SGXSTEP_DIR"
cd "$SGXSTEP_DIR/kernel" && make           # capture everything
```

`setup/20-build-driver.sh` wraps this: it checks headers, builds, captures a
per-kernel log, and on success loads the module and verifies `dmesg`.

Upstream's own bootstrap is `kernel/install_SGX_driver.sh`, which first tries the
in-tree `/dev/sgx_enclave` and only otherwise builds the out-of-tree `isgx`
v2.14 submodule. Stock `isgx` v2.14 does not compile on these kernels; this lab
uses the 7.1.5 port above, not the in-tree driver (no flexible launch control
on this CPU).

### Porting notes (get the log first, patch minimally)

The module is actively maintained upstream (CET/CR4 handling, `pin_user_pages_fast`
for >= 5.6, 2024-era CPU table), so the port is usually small. Most likely
breakage points, in order:

1. **`apic->read()` / `apic->write()`** (in `save_apic()` / `restore_apic()`).
   If the `struct apic` hookup or the `apic` symbol changed/is no longer
   exported, read and write the local APIC through the x2APIC MSR interface
   instead -- equivalent when `X2APIC=1`:
   * `LVTT`  -> MSR `0x832` (`IA32_X2APIC_LVT_TIMER`)
   * `TMICT` -> MSR `0x838` (`IA32_X2APIC_TMICT`)
   * `TDCR`  -> MSR `0x83E` (`IA32_X2APIC_TDCR`)
   Both paths act on the *current* CPU, so keep the same preemption/interrupt
   discipline as the original code.
2. **`pin_user_pages_fast(..., FOLL_LONGTERM | FOLL_WRITE, ...)`** in
   `SGX_STEP_IOCTL_SETUP_ISR_MAP`. If pinning now fails (`cannot pin all ISR pages`),
   the ISR mapping must be created from an anonymous mapping; verify with
   `dmesg` right after the ioctl.
3. **5-level paging** (`CONFIG_PGTABLE_LEVELS > 4`) -> `no5lvl` kernel parameter,
   or the PTE walk in `sgx_step_get_pt_mapping` returns garbage.
4. `kretprobe` on `devmem_is_allowed` fails to register -> the driver loads but
   `/dev/mem` still refuses the APIC page, and `libsgxstep` fails later with a
   confusing error.
5. Any remaining API drift (header moves, `vm_flags`, `kallsyms` visibility).
   Patch it locally and note the exact diff in this file (Phase 4).

### Verified port: kernel `7.1.5+kali-amd64` (2026-09-16)

Two changes were needed. The verified diff is archived as
`patches/0001-sgxstep-kernel-7.1.5-port.patch` (apply from the tree root with
`patch -p1 < ...`, or use the sed commands below). First change:

```c
 #include <linux/slab.h>
+#include <linux/vmalloc.h>
```

Kernel 7.1.x no longer pulls `<linux/vmalloc.h>` in transitively, so `vmap()`
and `vunmap()` became implicit declarations:

```
sgxstep.c:199: error: implicit declaration of function 'vunmap'
sgxstep.c:338: error: implicit declaration of function 'vmap'
```

Everything else compiled unchanged: APIC register access via
`apic->read()`/`apic->write()` and the CET/CR4 handling are still fine on 7.1.5.
The `#warning 5-level page tables currently not supported` is expected (the
kernel is built with `CONFIG_PGTABLE_LEVELS=5`) and harmless on a CPU without
LA57, which falls back to 4 levels at run time.

The matching headers are only available for the kernel version currently in the
rolling repo, so on Kali the practical sequence is: install
`linux-image-amd64` + `linux-headers-amd64` (they arrive as a matched pair),
apply the boot parameters, reboot into the new kernel, and only then build.

Second change: kernel 7.1.x enforces `module_init()`/`module_exit()`. objtool
rejects the legacy magic function names that upstream still uses:

```
sgx-step.o: error: objtool: init_module(): Magic init_module() function name is
            deprecated, use module_init(fn) instead
make[4]: *** [scripts/Makefile.build:512: sgx-step.o] Error 255
```

```c
-int init_module(void)
+static int __init sgxstep_init(void)

-void cleanup_module(void)
+static void __exit sgxstep_exit(void)

+module_init(sgxstep_init);
+module_exit(sgxstep_exit);
```

When objtool fails, `make` deletes the intermediate object, so a following
`insmod` reports `No such file or directory` -- that is the same failure showing
up twice, not a second problem.

Status (2026-09-16): with both changes applied, `sgx-step.ko` links cleanly on
`7.1.5+kali-amd64`:
```
  CC [M]  sgxstep.o
  LD [M]  sgx-step.o
  LD [M]  sgx-step.ko
  BTF [M] sgx-step.ko
```

`libsgxstep` also builds in full on this kernel/toolchain once `libelf-dev` is
installed (`elf_parser.c` needs `gelf.h`), including the `NO_SGX=1` mode used by
`app/selftest/*`.

---

## 5. Milestone ladder

| Milestone | Command | Needs SGX SDK? | Needs enclave? |
|-----------|---------|----------------|----------------|
| M1 -- driver + IDT/APIC plumbing | `cd app/selftest/idt && make run` | no | no |
| M2 -- APIC/timer accuracy | `cd app/selftest/apic` | no | no |
| M3 -- patched Intel SDK + PSW | `cd sdk/intel-sdk && ./install_SGX_SDK.sh` | yes | no |
| M4 -- Foreshadow with simulated enclave | `cd app/foreshadow && make run` with `SIM_ENCLAVE 1` | yes | no |
| M5 -- full PoC | `cd app/foreshadow && make run` with `SIM_ENCLAVE 0` | yes | yes |

`app/foreshadow/main.c` switches:

* `SIM_ENCLAVE 1` -- adds `sim-enclave.c`, runs the whole L1TF pipeline *without*
  `EENTER`, i.e. it still works on CPUs with patched microcode. Use it to prove
  the covert channel and the PTE manipulation before touching SGX.
* `SIM_ENCLAVE 0` -- real enclave secret in L1D, the actual attack.

`setup/40-build-poc.sh` drives M1 and M4/M5.

### Two variants, and which one a given host allows

| Variant | What it needs | What it proves |
|---|---|---|
| **A -- enclave-free (sim)** | `/dev/sgx-step`, `libsgxstep` built with `NO_SGX=1`, a small harness reusing `sim-enclave.c` | the whole L1TF/L1D pipeline: page-table manipulation, transient read, Flush+Reload oracle. No Intel SDK, no SGX driver, works with patched microcode |
| **B -- upstream `app/foreshadow`** | Variant A plus the patched Intel SDK (and for `SIM_ENCLAVE=0` a working SGX driver + unmitigated microcode) | the upstream PoC including `EENTER` on a real enclave |

`SIM_ENCLAVE=1` in the upstream `main.c` guards out `sgx_create_enclave()`
completely, so no SGX driver is needed at *run* time -- but the app still
*links* against `libsgx_urts`/`encl_proxy`, therefore it cannot be built without
the Intel SDK. Variant A removes exactly that build dependency: `libsgxstep`
supports it natively (`NO_SGX=1`, the mode used by `app/selftest/*`) and
`sim-enclave.c` is dependency-free plain C (`rand()` + an aligned array + one
`movl`).

---

## 6. Running the PoC and what to expect

```bash
cd "$SGXSTEP_DIR/app/foreshadow"
source /opt/intel/sgxsdk/environment      # after M3
sudo -E make run
```

The Makefile's `run` target takes care of `LD_LIBRARY_PATH` for the locally
built, patched `libsgx_urts.so` (see the "local installation" note in the
top-level README).

Success looks like the upstream sample output: the PTE dump before/after
revoking access rights, then

```
[foreshadow.c] cache hit/miss=52/246; reload threshold=134
shadow[ 0]=0x37; enclave[ 0]=0x37    shadow[ 1]=0xa8; enclave[ 1]=0xa8
...
[OK] Foreshadow correctly derived all 64 bytes!
```

Evidence to keep: the full program output plus `uname -a`, CPU model, microcode
revision, `/proc/cmdline`, and the `l1tf` vulnerability status. No packet
captures needed here.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ASSERT ... /dev/sgx-step` | LKM not loaded | Phase 1 |
| `[pt.c] /dev/mem opened!` never appears | `CONFIG_STRICT_DEVMEM` not bypassed | check kretprobe in `dmesg`, verify `iomem=relaxed` |
| Kernel oops / timer dies after a run | IDT or APIC not restored | check `/proc/interrupts`; reboot, then investigate `restore_idt()` |
| `sgx_create_enclave` error 0x... | no/incompatible SGX driver | in-tree `/dev/sgx_enclave` vs `isgx`; check `aesmd` |
| `cache hit/miss=0/...` | microcode flush active (or `dis_ucode_ldr` not effective) | check `l1tf` status; use `SIM_ENCLAVE=1` |
| `/dev/sgx_enclave` missing, dmesg: "launch control CPU feature is not available" | CPU has no FLC (Skylake client) | Variant A, or port the out-of-tree `isgx` driver |
| `/boot/config-*` reports KPTI "not set" but dmesg says it is enabled | kernel >= 6.9 renamed the symbol | it is `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION` now |
| SDK build fails on Kali | linux-sgx v2.29 vs modern GCC | build with `CC=gcc-12 CXX=g++-12` |
| PoC hangs at `ERESUME` | 5-level paging / KPTI | `no5lvl`, `pti=off` |
| Stepping unreliable | C-states / SpeedStep | `intel_idle.max_cstate=1 processor.max_cstate=1`, disable in BIOS |

---

## 8. Scripts in this directory

| Script | Purpose | Safe? |
|---|---|---|
| `setup/00-diagnose.sh` | Phase 0 read-only checks + verdict | read-only |
| `setup/10-grub-cmdline.sh` | merge kernel parameters, sysctls | writes only with `--apply` |
| `setup/20-build-driver.sh` | build + load `/dev/sgx-step`, log per kernel | loads a module |
| `setup/25-patch-libsgxstep.sh` | bound libsgxstep's `transient_access()` retry loop | writes `transient.S` (backup kept) |
| `setup/30-tune-libsgxstep.sh` | patch `libsgxstep/config.h` (X2APIC, CPU, cores) | writes config.h (backup kept) |
| `setup/40-build-poc.sh` | milestone M1 / M4 / M5 driver | builds + runs PoC |

Scripts are plain bash with LF line endings. If the files were copied through
Windows and fail with `\r: command not found`, run
`sed -i 's/\r$//' *.sh` in `setup/` first, then `chmod +x *.sh`.

---

## 9. Deployed copy on `.86`

The lab host keeps this content under `~/CPU/` with the `labs/` prefix stripped:
`~/CPU/foreshadow/...` plus `~/CPU/todo.md`. Paths written as `labs/foreshadow/...`
throughout this document are relative to the repository, not to the deployed copy.

---

## 10. Enclave-free harness (`harness/main.c`)

Variant A from section 5. It reproduces the three attack phases without an
enclave and without the Intel SGX SDK, by reusing the upstream `SIM_ENCLAVE=1`
path and a verbatim copy of `sim-enclave.c`.

Install it into the sgx-step tree by reusing the selftest app that is already
known to build in this exact configuration (it needs `libsgxstep` only):

```bash
mkdir -p ~/sgx-step/app/foreshadow-sim
cp ~/sgx-step/app/selftest/idt/Makefile ~/sgx-step/app/foreshadow-sim/Makefile
sed -i 's|\.\./\.\./\.\.|../..|g' ~/sgx-step/app/foreshadow-sim/Makefile
cp ~/CPU/foreshadow/harness/main.c ~/sgx-step/app/foreshadow-sim/main.c
cd ~/sgx-step/app/foreshadow-sim && make 2>&1 | tail -20
sudo ./app
```

`harness/main.c` is deliberately self-contained: the app Makefiles in the tree
build a single `main.c`, so `sim-enclave.c` is copied inside rather than added as
a second translation unit (which would duplicate its symbols).

Expected output mirrors the upstream sample: the PTE dump before/after revoking
the alias access rights, then `[foreshadow.c] cache hit/miss=...; reload
threshold=...`, the `shadow[i]` vs `enclave[i]` table, and
`[OK] Foreshadow correctly derived all 64 bytes!` printed by
`foreshadow_compare_secret()`.

### First run on this host (2026-09-16)

```
[foreshadow.c] cache hit/miss=58/262; reload threshold=144
** shadow[ 5]=0x00; enclave[ 5]=0xff     (likewise 7, 10, 12, 30, 45, 50, 51, 62)
[foreshadow.c] [FAIL] Foreshadow missed 9 bytes out of 64 :/
[main.c] harness summary: mismatched bytes=9/64; handled SIGSEGV=64
```

55/64 bytes recovered, and every miss is a `0x00` -- the documented zero bias of
transient reads, not random noise. The `handled SIGSEGV=64` counter shows why
the built-in retries could not help: exactly one fault per byte means the fault
handler restored `P=1` right after the first attempt, so all subsequent
`foreshadow()` retries read an ordinary, present mapping and leak nothing.

The harness therefore retries at the byte level and re-revokes the PTE before
every attempt (`ZERO_RETRIES`, 20, mirroring the upstream constant). Retry
counts are printed per byte whenever they are needed.

Second run, with that retry in place (seed `0x6aaac640`): **64/64 bytes**,
`handled SIGSEGV=77` -- only 13 extra attempts for the whole cache line.

### Final state (2026-09-16)

Three consecutive runs with the bounded `transient_access()` retry, a per-byte
watchdog and random secrets:

| seed | result | handled SIGSEGV |
|---|---|---|
| `0x6aaacd93` | 64/64 | 64 |
| `0x6aaacd9e` | 64/64 | 128 |
| `0x6aaacd85` | 64/64 | 122 |

No watchdog trips, no hangs, and `dmesg` shows a clean IDT/APIC save-restore
cycle after every run. The enclave-free reconstruction of the Foreshadow/L1TF
PoC is therefore complete on this host: kernel `7.1.5+kali-amd64`, no flexible
launch control, no Intel SGX SDK, microcode `0xba` from the firmware.

A later run with a different seed stalled inside the measurement of a single
byte, so the harness now runs with line-buffered output and prints a progress
line per byte; `SEED=<n>` reproduces a run and `RETRIES=<n>` changes the retry
budget. A stall is therefore observable: the last printed byte is where it sits.
The stall itself is an upstream defect, see section 11: the harness arms a
per-byte `SIGALRM` watchdog (`WATCHDOG=<sec>`, default 30) so a stuck run reports
and exits instead of spinning forever.

If the build fails with `libsgxstep/pt.h: No such file or directory`, the copied
Makefile uses `-I$(LIBSGXSTEP_DIR)/libsgxstep`; strip the prefix instead:

```bash
sed -i 's|libsgxstep/||g' ~/sgx-step/app/foreshadow-sim/main.c
```

---

## 11. Upstream defects found while reproducing

Both were found on this host and neither is caused by the Kali port; they are
worth reporting upstream.

### 1. The zero-byte retry in `libsgxstep/foreshadow.c` is a no-op

```c
    /* Be sceptic about 0x00 bytes to compensate for the bias */
    for(j=0; (rv==0x00 || rv==0xff) && j < FORESHADOW_ZERO_RETRIES; j++, fs_zero_retries++);
        rv = foreshadow_round(adrs);
```

The semicolon after the `for(...)` header makes the loop body empty.
`foreshadow_round()` runs once. The increment clause still runs, so
`fs_zero_retries` increases even though no additional measurements occur.
`FORESHADOW_ZERO_RETRIES` therefore never retries a measurement. A printed
`0x00 retries=0` came from `NO_SGX` builds, where the perf line that prints
the counter is compiled out, not from the increment being skipped. The
harness compensates by retrying at the byte level, where the PTE can be revoked
again between attempts.

### 2. `transient_access()` spins forever on a 0x00 byte

```asm
retry:
    movb (%rsi), %al
    shl %cl, %rax
    jz retry            <-- unbounded
    movq (%rdi, %rax), %rdi
    retq
```

`rax = byte << 12`, so a zero byte keeps the loop spinning. Because the harness
SIGSEGV handler re-presents the page, the retried load succeeds and keeps
returning the real value, so a `0x00` byte in the secret produces an endless
100% CPU loop: `STAT R+`, `WCHAN -`, and a low `min_flt` count (only the first
access faults). That is exactly what happened on the run whose random secret
contained a zero byte.

Mitigations shipped here:

- `setup/25-patch-libsgxstep.sh --apply` bounds the loop: identical behaviour for
  non-zero bytes, a `0x00` byte now reaches the caller as value 0 instead of
  hanging;
- the harness arms a per-byte `SIGALRM` watchdog so a stuck run reports and exits,
  letting the driver restore IDT/APIC through its release path.

---

## 12. Decisive experiment: transient execution vs architectural re-execution

`harness/leaktest.c` exists because the reproduction in section 10 does **not**
by itself prove that the secret was read transiently. Its `fault_handler()` calls
`MARK_PRESENT()` + `mprotect(PROT_READ|PROT_WRITE)`, so the faulting load is
re-executed *architecturally* and the oracle slot can be filled by an ordinary
read of a page the process can map anyway. Upstream's own comment in
`transient.S` describes that restore as "proof-of-concept only". The zero-bias
observation is suggestive but not proof: cache-timing noise and the decoding rule
can also produce spurious zeros.

`leaktest.c` removes the ambiguity. Its handler never touches the mapping; it
redirects `RIP` past the whole transient block, so the secret-dependent oracle
access is **never executed architecturally** -- only whatever the out-of-order
engine did before the fault was delivered can leave a trace in L1D. The block is
local to the harness, so the library's `transient_access()` (and its unbounded
retry) is not involved either.

### Controls

| `HANDLER` | `PFN` | `RELOAD` | what it answers |
|---|---|---|---|
| `skip` | `keep` | `1` | the attack: PFN preserved, page revoked, no architectural re-execution |
| `skip` | `zero` | `1` | is a valid physical address in the PTE required? |
| `skip` | `keep` | `0` | is L1D residency required (the L1TF property)? |
| `restore` | `zero` | `1` | how much can an architectural read explain? |

### How to read the result

- `skip` + `keep` recovers the secret while `skip` + `zero` does not ->
  the leak came through the preserved physical address, transiently.
- `skip` + `keep` + `RELOAD=0` recovers nothing -> consistent with L1TF requiring
  the data to be in L1D.
- `restore` + `zero` recovers only part of the secret, and the log shows why: the
  kernel work around the handler's `mprotect()` pollutes 122 of the 256 trace
  measurements (visible as `2 hot`). The section-10 handler cannot distinguish
  transient from architectural execution -- that is the reason for this experiment,
  not a contradiction.
- `faults=0` on a byte means the block ran architecturally (nothing was revoked)
  and that measurement must be discarded.

Every byte prints the decoded value, the true value, the best reload time and the
audit counters (`lo`/`hi` class with the number of hot candidates, fault count), so
the decoding rule can be audited instead of trusted, and `TRIALS=<n>` repeats each
byte to show whether the decode is stable.

Build and run with `setup/45-build-leaktest.sh`.

### Measured result on `.86` (2026-09-16)

```
cd ~/sgx-step/app/foreshadow-leak
sudo HANDLER=skip    PFN=keep RELOAD=1 TRIALS=2 ./app > ~/leak-1-attack.txt
sudo HANDLER=skip    PFN=zero RELOAD=1 TRIALS=2 ./app > ~/leak-2-nopfn.txt
sudo HANDLER=skip    PFN=keep RELOAD=0 TRIALS=2 ./app > ~/leak-3-nol1d.txt
sudo HANDLER=restore PFN=zero RELOAD=1 TRIALS=2 ./app > ~/leak-4-oldhandler.txt
sudo NOBLOCK=1       PFN=keep RELOAD=1 TRIALS=1 ./app > ~/leak-5-noblock.txt
```

| run | mode | mismatched bytes | `faults`/byte | hot candidates per trace |
|---|---|---|---|---|
| `leak-1` | `skip` + `keep` + `RELOAD=1` | **0/64, both trials** | `68` (`64`+`4`) | `1` in all 256 measurements |
| `leak-2` | `skip` + `zero` + `RELOAD=1` | 64/64 | `68` | (negative control) |
| `leak-3` | `skip` + `keep` + `RELOAD=0` | 63/64 (one chance hit) | `68` | (negative control) |
| `leak-4` | `restore` + `zero` (old handler) | 48/64 and 42/64 | `68` | 134 clean, 122 with `2 hot` |
| `leak-5` | `NOBLOCK=1` (no block at all) | 64/64 | **`0`** | none |

Sample line, `leak-1`, byte 0:

```
t0 byte  0: true=0x8d decoded=141 lo=13(1 hot,46 cyc) hi=2(1 hot,44 cyc) faults=68
```

`141 & 0x3f = 13` (low trace) and `141 >> 6 = 2` (high trace), so both traces decoded
their class and the byte is exact.

What this establishes:

- **The secret is recovered although the faulting access is never executed
  architecturally.** The handler only redirects `RIP`; the secret-dependent oracle
  access happened before the fault was delivered.
- **The trace comes from the block, not from the fault machinery.** Without the block
  (`NOBLOCK=1`) the very same measurement loop sees `faults=0` and recovers nothing.
- **Both a preserved PFN and L1D residency are required** (`leak-2`, `leak-3`), which
  is the L1TF property: the value is taken from the cache, not from a translation.

### Why the oracle is indexed by L1D *set*, not by cache line

The harness does not use the paper's 256-slot byte layout. On this L1D a flush+reload
pair cannot resolve a single line, and the reason was measured with minimal probes
(`flush(slot)`, then the same with one intervening load, then `reload(slot)`):

| probe | cycles | reading |
|---|---|---|
| no intervening access | 264 | miss (correct) |
| intervening load **4 KiB away** (same L1D set) | 47 (harness probe: 52) | **hit** |
| intervening load in another L1D set | 308 | miss (correct) |

Any access to a line of the candidate's L1D set between the flush and the reload makes
the freshly flushed line read back as a hit -- even when the intervening load targets a
completely different array, so it is the set, not the tag, that matters. With a 4 KiB
stride all 256 slots sit at offset 0 of their page and therefore in one set (the set
index `(addr>>6)&63` advances by `64 == 0 mod 64`), so the access the transient block
performs marks four candidates at once. The self-test reproduces that exactly --
`touched=v` always yields `{v, v+64, v+128, v+192}` -- which is what made every earlier
run of this experiment report `best ≈ second` and a uniformly "hot" oracle.

The decoder therefore measures *classes*: `oracle_lo` holds 64 slots (one per low six
bits) in 64 different sets, `oracle_hi` holds 4 slots (one per high two bits) in four
different sets, and each trace gets its own run of the block -- two accesses in one run
would pollute each other, because 64 classes already tile all 64 sets. One slot per
distinguishable class makes the argument of the minimum unambiguous again, and the two
traces still add up to the whole byte. The kernel's fault handling runs between flush
and reload in every round; the `1 hot` in all 256 measurements of `leak-1` shows that it
does not disturb the measurement.

`SELFTEST=1 ./app` validates all of this without any privilege (nothing touches
`/dev/mem`), replacing the transient access with the same access done architecturally:

```
timing sanity: cold=282 hot=46
probe: flush+reload=266, +load(same set)+reload=52, +load(other set)+reload=324
selftest: touched=0xec lo=44 (1 hot) hi=3 (1 hot) -> OK
selftest: touched=0xff lo=63 (1 hot) hi=3 (1 hot) -> OK
```

Run it before any `sudo` run: unless it is 6/6 `OK` with exactly one hot candidate per
trace, every attack measurement is meaningless.

---

## 13. Variant B -- the enclave path: what this host needs

The enclave-free result above proves the mechanism, not the attack on an enclave. This
section records what the enclave variant requires and how far it is on this host.

### Why the in-tree SGX driver cannot be used

The i3-6100 (Skylake, model 0x5E) has SGX enabled by firmware but **no Flexible Launch
Control**: `CPUID.07H.0:ECX[30] = 0`, and the kernel says so itself at boot:

```
sgx: EPC section 0x90200000-0x95f7ffff
sgx: SGX disabled: SGX launch control CPU feature is not available, /dev/sgx_enclave disabled.
```

`/dev/sgx_enclave` therefore never appears (and the `sgx` CPU flag is cleared from
`/proc/cpuinfo`). The firmware state, read with `rdmsr`:

| MSR | value | meaning |
|---|---|---|
| `0x3a` `IA32_FEATURE_CONTROL` | `0x40005` | bit 0 LOCK=1, bit 2 VMX=1, **bit 17 SGX_LAUNCH_CONTROL=0**, **bit 18 SGX_ENABLE=1** |
| `0x10` (TSC) | `0x1636ef45e3cc` | control: reading MSRs works on this host |
| `0x8d`-`0x90` `IA32_SGXLEPUBKEYHASH0..3` | *not readable* (`#GP`) | as expected without FLC: on such parts the Launch Enclave key is fixed in silicon, there is no MSR to read or write |

### The legacy `/dev/isgx` driver

SGX-Step's `kernel/install_SGX_driver.sh` falls back to Intel's out-of-tree driver
(`kernel/linux-sgx-driver`, v2.14) when `/dev/sgx_enclave` is absent; it reaches `ENCLS`
through `CPUID` and therefore still works without FLC. Porting it to 7.1.5 needed seven
mechanical changes, archived as `patches/0004-isgx-kernel-7.1.5-port.patch` and applied
by `setup/50-port-isgx.sh`:

| change | reason |
|---|---|
| `vm_flags_set(vma, ...)` | `vm_flags` is read-only since 6.3 |
| `zap_vma_ptes` -> `zap_vma_range` (7 sites) | old API removed |
| `mk_vma_flags(VMA_NORESERVE_BIT)` | `shmem_file_setup()` takes an opaque `vma_flags_t` now |
| `sgx_drv_remove()` returns `void` | changed signature |
| `wrmsrl_safe` -> `wrmsr_safe(msr, lo, hi)` | MSR API merged |
| `mm->get_unmapped_area` -> `mm_get_unmapped_area()` | the only exported variant; `__get_unmapped_area()` and `vm_unmapped_area()` are not exported to modules |
| `#include <linux/sched/mm.h>` | home of that prototype |

The result builds, loads, finds the EPC bank and creates `/dev/isgx`:

```
intel_sgx INT0E0C:00: EPC bank 0x90200000-0x95f80000
intel_sgx:  can not reset SGX LE public key hash MSRs   <- expected without FLC, harmless
```

### The Launch Enclave is what `EINIT` needs on this CPU

Without FLC, `EINIT` requires an **EINIT token signed by the platform's Launch Enclave**
(precisely the value those missing MSRs would pin). That LE is an Intel-signed binary,
`libsgx_le.signed.so`, together with the aesmd plugin that drives it. Two facts matter:

- **Intel removed LE-based launch in PSW v2.28**, straight from the source:
  `psw/uae_service/linux/uae_service.lds` calls `get_launch_token` a *hollow definition
  kept for ABI compat - returns SGX_ERROR_FEATURE_NOT_SUPPORTED*, and `psw/urts/urts_com.h`
  says *support for LE-based launch removed in v2.28*. An SDK 2.29/2.30 stack therefore
  cannot launch an enclave here at all.
- **The LE is still published for the last pre-2.28 releases** (2.18 ... 2.27) in Intel's
  apt repository (`https://download.01.org/intel-sgx/sgx_repo/ubuntu`, suite `jammy`):
  `libsgx-ae-le`, `libsgx-aesm-launch-plugin`, `sgx-aesm-service`, `libsgx-launch`,
  `libsgx-enclave-common`, `libsgx-urts`, `libsgx-headers` - version `2.27.100.1` is the
  last one that has all of them. The LE/plugin are not in the SDK source tree; only the
  *signed blob* can be used.

`app/foreshadow/main.c` matches that generation exactly -- it uses the token-based API:

```c
sgx_launch_token_t token = {0};
SGX_ASSERT( sgx_create_enclave( ENCLAVE_SO, ENCLAVE_MODE, &token, &updated, &eid, NULL ) );
```

and `sgx_2.27`'s `common/inc/sgx_urts.h` still declares that signature. The app does not
use SGX-Step's custom AEP (`register_aep_cb()` is what needs `sgx_set_aep()`), so the
stock asynchronous-exit path is enough here; only the *link* needs that symbol.

### Plan for the enclave run (status 2026-09-16)

1. driver: `isgx` v2.14 ported and loaded (done), plus `/dev/sgx-step` (done).
2. token service: **done**. PSW 2.27.100.1 unpacked from Intel's apt repo --
   `libsgx_le.signed.so.1.25.100.1` (the Intel-signed Launch Enclave),
   `bundles/lible_launch_service_bundle.so` and `aesm_service`. `aesmd` runs on Kali once
   the old `libprotobuf.so.23` is on `LD_LIBRARY_PATH` (Kali ships .32 only); the service
   itself needs `LD_LIBRARY_PATH=.` because it loads `libCppMicroServices`, `libipc`,
   `liboal` and `libutils` from its own directory.
3. runtime: **prebuilt 2.27 `libsgx_urts` + `libsgx_uae_service`**. The latter exports a
   real `get_launch_token` (`nm -D` shows `T get_launch_token`), which is what asks aesmd
   for the token. By 2.29 the very same parameter is documented as
   `reserved1 /* formerly launch_token ... Ignored, may be a nullptr */`, which is why a
   modern SDK cannot launch on this CPU while 2.27 can.
4. tools: `sgx_sign` and `sgx_edger8r` have to be built from the source tree (`sgx_2.27`,
   or 2.29 for the tools only -- the header signature is identical). `sgx_edger8r` is
   written in OCaml, so the build needs `ocaml ocamlbuild ocaml-findlib`; the prebuilt
   `external/toolset` only contains binutils.
5. gate: launch a debug enclave first (the Foreshadow app's own `Enclave/`, or an SDK
   sample). `EINIT` succeeding means the Launch Enclave path works on this CPU and
   `app/foreshadow` with `SIM_ENCLAVE=0` is next; a failure gives the error code that
   documents the blocker.
6. microcode A/B (`0xba` from ROM vs `0xf0` from the installed initrd) tells whether the
   L1D flush on enclave entry is active.

---

## 14. Deliverables (a)/(b) -- closing the enclave yield gap (2026-09-17)

The enclave path (section 13) runs end to end but recovers only ~10% of the 64
bytes with the flat library oracle. Root cause and fix are in `STATUS.md`
("Open item"): the enclave attack is purely transient (the sim's 64/64 leans on
architectural re-execution, which reads the 0xff abort page on a real enclave),
and the 256-slot / 0x1000 oracle collapses into one L1D set on this host, where
it cannot be decoded transiently. Both deliverables apply the split lo/hi oracle
that `harness/leaktest.c` already validated at 0/64 on this exact L1D.

Common environment:

```bash
L=$HOME/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu
P=$HOME/sgxsdk/psw227/libs/protobuf23/usr/lib/x86_64-linux-gnu
SDK=$HOME/sgxsdk/sdk227
FIX=$HOME/sgx-step/libsgxstep/fixalign.so
```

### Deliverable (b) -- dedicated app `app/foreshadow-encl-split`

Source: `harness/foreshadow-encl-split.c`, Makefile
`harness/foreshadow-encl-split.Makefile`. It links against the already-built
`app/foreshadow/Enclave` (via an `Enclave` symlink) and reuses `aep_stub.c`, so
the enclave is never regenerated (no `sgx_edger8r`/`sgx_sign` needed).

```bash
# build (no root)
cd $HOME/sgx-step/app/foreshadow-encl-split
make SGX_SDK=$SDK

# pre-flight gate (no root; must be 6/6 OK, one hot per trace)
SELFTEST=1 LD_LIBRARY_PATH=$L:$P:$SDK/lib64 ./app

# the attack (root): split oracle, real enclave, prime per candidate,
# per-byte majority vote (REPEAT), five random-secret trials
cd $HOME/sgx-step/app/foreshadow-encl-split
sudo timeout 900 env TRIALS=5 REPEAT=9 LD_PRELOAD=$FIX \
    LD_LIBRARY_PATH=$L:$P:$SDK/lib64 ./app 2>&1 | grep -E 'trial|OK|FAIL'
```

Controls (env): `HANDLER=skip|restore`, `PFN=keep|zero`, `RELOAD=0|1`,
`NOBLOCK=1`, `TRIALS=<n>`, `REPEAT=<n>` (per-byte majority vote, default 5). The
attack is `HANDLER=skip PFN=keep RELOAD=1` (defaults). A single read is ~99%
correct per byte; the vote lifts it to a reliable `[OK] trial N: recovered all
64 bytes!`.

### Deliverable (a) -- patched `libsgxstep` + `app/foreshadow`

Patch: `patches/0005-libsgxstep-app-foreshadow-split-oracle.patch` (already
applied on `.86`; `git apply` verified both directions). The split path is
compiled into `libsgxstep` and gated by `FS_SPLIT_ORACLE=1`; the app handler
skips RIP when it is set.

```bash
# rebuild after the patch (SOURCES adds aep_stub.c for the stock runtime)
cd $HOME/sgx-step/app/foreshadow
make SOURCES="main.c aep_stub.c" SGX_SDK=$SDK
# if sgx_edger8r is not on PATH, do not rebuild Enclave/; compile + link only:
#   gcc <CFLAGS> -I$SDK/include/ -I../.. -c main.c -o main.o
#   gcc <CFLAGS> -I$SDK/include/ -I../.. -c aep_stub.c -o aep_stub.o
#   gcc main.o aep_stub.o -lsgx-step -lencl_proxy -lsgx_urts -lsgx_uae_service \
#       -pthread -LEnclave -L../../libsgxstep -L$SDK/lib64/ \
#       -Wl,-rpath-link,$SDK/lib64 -Wl,-rpath-link,$L \
#       -L../../linux-sgx/psw/urts/linux -o app

# run with the split oracle + per-byte majority vote (FS_SPLIT_REPEAT, default 5;
# FORESHADOW_ZERO_RETRIES is unused in split mode)
sudo timeout 600 env FS_SPLIT_ORACLE=1 FS_SPLIT_REPEAT=9 LD_PRELOAD=$FIX \
    LD_LIBRARY_PATH=$L:$P:$SDK/lib64 ./app | tee /tmp/foreshadow-split.log
```

Expected: `[OK] Foreshadow correctly derived all 64 bytes!`. `FS_SPLIT_ORACLE`
unset reproduces the old ~10% flat-oracle behaviour for comparison.

### If yield is still short

Disable the L1D/L2 hardware prefetchers on the victim core and re-run -- the
set-scoped false hit (README section 12) is consistent with a prefetcher refill,
and this hygiene is not yet in the boot parameters:

```bash
sudo modprobe msr
sudo wrmsr -p1 0x1a4 0xf ; rdmsr -p1 0x1a4   # expect f
```

---

## 15. SSA/GPRSGX vote dumps -- cross-run statistics (2026-09-19)

`harness/foreshadow-ssa-warm.c` (see `STATUS.md`, "SSA/GPRSGX register-frame
dump") can dump its raw per-byte vote vectors so that several runs can be
aggregated offline:

```bash
# one run with a dump (from app/foreshadow-ssa-warm)
sudo env VOTE_DUMP=/tmp/ssawarm.1.votes WARM_VOTES=24 ./app

# collect N runs and aggregate in one go. NOTE: --collect spawns ./app, which
# needs the enclave up (run 90-start-lab.sh first) and its shared libs. sudo
# strips LD_PRELOAD/LD_LIBRARY_PATH, so pass them AFTER sudo with `sudo env`,
# or every spawned run fails rc=127 (no libs) / rc=-6 0x2006 (lab not up).
L=$HOME/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu
P=$HOME/sgxsdk/psw227/libs/protobuf23/usr/lib/x86_64-linux-gnu
SDK=$HOME/sgxsdk/sdk227
sudo env LD_PRELOAD=$HOME/sgx-step/libsgxstep/fixalign.so \
    LD_LIBRARY_PATH=$L:$P:$SDK/lib64 TIMER_INTERVAL=5000 \
    python3 harness/warm_vote_stats.py --collect ./app -n 30 --votes 24
```

`harness/warm_vote_stats.py` reads any number of dumps and reports, per byte
offset: the per-run match flags (`#` = match, `.` = mismatch), the failure rate
over the runs, the pooled (cross-run) decode, the owning register, and the
physical GPRSGX cache line / L1D set. It labels an offset *systematic* (fails in
~every run) or *stochastic* (fails in a fraction). Caveat on that label: it
measures **cross-run** determinism only; section 16 shows the miss is in fact
**within-run deterministic** (a function of the byte's value), just re-drawn
across runs by per-run global noise. The dump format is documented in the
harness header; collect mode writes `<run>.votes` + `<run>.log` under `--outdir`
(default `/tmp/ssawarm-votes`).

## 16. The residual error is value-correlated, not position-correlated

The transient GPRSGX leak on the SIGSEGV (no-TSX) fault path is often one
register short of 12/12. That is not one or two wrong bytes: the cited run was
11/12 registers and 88/96 known bytes. A clean 12/12, 96/96 also occurs.
`harness/value_corr.py` aggregates the 30 vote dumps from
2026-09-19 to characterise *what* those misses are. The result is a finding
the 2018 PoC's `RETRIES=N` re-measurement masked:

- **The failure is a function of the leaked VALUE, not the byte's offset or its
  cache line.** Value `0x12` appears in three different SSA cache lines
  (`rsi[1]` @ set 61, `r12[*]` @ set 62, `rip[1]` @ set 63); its 30-run failure
  bitmap is **bit-identical (Hamming 0)** in all three -- it fails in the same
  four runs everywhere. Per-byte noise or SSA-line eviction cannot produce that;
  a value-keyed effect can. (T1)
- **It is not an oracle-slot vs SSA-line set collision, and ASLR does not move
  it.** The oracle is page-aligned in every run (`oracle_lo`/`oracle_hi` base
  L1D set = 0 for all 30), and the L1D set index is VA bits 6-11 = the page
  offset, which ASLR never changes; the GPRSGX page offset is fixed at `0xF48`
  (set 61) too. So the slot->set map is identical across all runs (T0). And the
  oracle slots of the failing values sit in L1D sets 0-30, **never** the SSA read
  sets 61/62/63 (T3) -- so the miss is not the reload contending with the SSA
  line.
- **Mechanism on that dataset: value-specific decode margin + a per-run global gate.**
  Each byte value has a characteristic decode margin (there, `0x15` weakest, then
  `0x12`/`0x14`/`0x13`/`0x11`). A per-run global quality factor (AEX count,
  scheduling, thermal/timing noise) sets how many marginal values tip over that
  run: over 30 runs the per-run failure count ran `0..32` with 7 clean runs (T2).
  Cross-run majority works because that global gate is ~independent between runs.
  A raw-latency dump of one run shows no distinguishable hot slot at reload on a
  miss (true class cold at ~268, no competing hot slot). That does not separate
  a deposit that never happened from one evicted before the reload. `0x10` was
  hot in 23/24 traces. `0x00` is weaker evidence than it looks: an empty lo
  histogram argmax-defaults to class 0. The cross-run figure below pools, for
  each byte offset separately, the low-six-bit class votes and the high-two-bit
  class votes, then takes the most common class. It is not a vote over values.
- **A second oracle base does not beat the plain one (2026-09-20/21).** Shifting
  the lo oracle by `0x400` (class 21 -> set 37) left `0x15` at 15/15 on both
  arms; single-run 12/12 was 3/15 vs 7/15. Touching both bases in one transient
  window collapses lo (the decoder locks onto class `0x27`). Two separate AEXes,
  voting only when both argmins agree, stays at ~93% agreement but lost to a
  clean 12/12 control on the same boot (11/12, 94/96). The reliable 12/12 is
  the cross-run majority. Same conclusion as [`WRITEUP-no-tsx.txt`](WRITEUP-no-tsx.txt).
- **31 of 184 bytes have a run-varying ground truth** (`rflags` low bits, the
  ASLR/AEX-dependent high bytes of `rip`/`ursp`, and `rsvd`). A cross-run vote is
  undefined for those and they must NOT be counted as attack failures. Over the
  **153 constant-truth bytes the composite majority/30 is 153/153** -- which
  includes all 96 fixed-canary GPR bytes (12/12 registers).

Reproduce (root-free, on existing dumps):

```bash
cd /tmp/ssawarm-votes && python3 ~/CPU/labs/foreshadow/harness/value_corr.py run*.votes
```
