# Foreshadow (L1TF) PoC on host `.86` — status

*Last updated: 2026-09-21. Written so that whoever picks this up next does not
have to rediscover any of it.*

## What we are doing

Reproducing the Foreshadow/L1TF PoC from SGX-Step against a **real enclave** on
the lab host `.86` (FUJITSU ESPRIMO D556/2, Intel i3-6100 Skylake, EPC 90 MB).

The host has **no flexible launch control** (`CPUID.07H.0:ECX[30] = 0`), which is
the whole difficulty: the kernel's in-tree SGX driver refuses to run, and the only
way to launch an enclave is Intel's legacy Launch Enclave through the
out-of-tree `isgx` driver.

## Bottom line

**A real SGX enclave runs on this host, and the Foreshadow attack executes end
to end against it, recovering real secret bytes from L1D with unpatched
microcode.** With the split lo/hi oracle it recovers the FULL 64-byte secret
line (64/64), verified on 2026-09-17 (see "Open item" below, now closed). The
flat 256-slot library oracle recovered only ~10% here; that is a decodability
limit of a single-set L1D, not of the attack.

## What works (all measured on `.86`)

| step | evidence |
|---|---|
| `isgx` driver ported to kernel `7.1.5+kali-amd64` | `lsmod` lists `isgx`, `/dev/isgx` is `crw-rw-rw-` |
| Launch Enclave loads | `sgx_create_le(...) -> SGX_SUCCESS, production_le_loaded=1` |
| AESM serves launch tokens | `/var/run/aesmd/aesm.socket` present, `aesm_service` running |
| enclave created and initialised (`EINIT`) | `sgx_create_enclave(Enclave/encl.so, debug) -> SGX_SUCCESS eid=0x2` |
| attack loop runs | `[sched.c] continuing on CPU 1` … `[foreshadow.c] cache hit/miss=46/284` |
| secret bytes leak | several bytes per run match, e.g. `0xe5 0x0a 0xfe 0xcc 0xc9 0xe2` |

## The three things that made the enclave path work

1. **The enclave mapping must be aligned to the enclave size.**
   PSW 2.27's `urts` maps the enclave wherever the kernel puts it (4 KiB
   aligned); the legacy `isgx` driver rejects such a SECS in `ECREATE` with
   `-EINVAL`, because `sgx_validate_secs()` requires `base & (size - 1) == 0`
   (2 MiB here). A small `LD_PRELOAD` shim
   (`libsgxstep/fixalign.so`; `fixalign.c` is built on the lab next to the
   SGX-Step tree and is **not** in this repository)
   intercepts exactly that one mapping and places it at an aligned address.
   Measured: identical `ECREATE` fails `-EINVAL` unaligned, succeeds (`ret=0`)
   aligned. Without the shim the client reports the misleading
   "Failed to open Intel SGX device".

2. **The stock runtime never exposes the TCS.**
   SGX-Step expects `sgx_get_tcs()`/`sgx_get_aep()` from *its* patched untrusted
   runtime. With stock PSW those two symbols are provided by
   `app/foreshadow/aep_stub.c`, which takes the TCS from the address the loader
   itself announces on its debug trace (`add tcs 0x…`, captured by the shim)
   and the AEP from the image entry point. Nothing reads enclave memory
   directly: a host read would fault.

3. **The library search path needs the PSW runtime, not just the SDK.**
   `urts` `dlopen`s `libsgx_launch.so.1` (the AESM client), which in turn needs
   `libprotobuf.so.23`. Both live in the unpacked PSW tree, not in the SDK, and
   a missing `libsgx_launch.so.1` shows up as a confusing
   "unexpected error 0x1001 … should be uRTS/driver bug".

After a reboot the whole environment comes up with ONE command,
`sudo setup/90-start-lab.sh`: it loads both kernel modules + `msr`, recreates
`/var/run/aesmd` (tmpfs, gone on every boot), then drops to the desktop user
(`runuser`) to start AESM with the Launch Enclave and verify the chain. Paths are
derived from `SUDO_USER`'s home, not `$HOME` (sudo resets `$HOME` to `/root`), and
aesmd is launched under `setsid` so it survives the launching shell. Idempotent.

## Open item: attack yield -- root cause and fix (2026-09-17)

Per-run yield with the flat library oracle is ~10% of the 64 bytes (measured: 7,
10, 8, 11, 5, 6, 8 bytes). The cause is now understood, and it is NOT the
transient sequence (the `transient.S` branch was already straight-lined without
moving the yield).

**Two facts combine:**

1. *The enclave path is purely transient.* The sim/harness path reaches 64/64
   only because its #PF handler re-presents the alias and the faulting `movb`
   re-executes **architecturally** on attacker-owned memory. On a real enclave
   that re-execution reads the **0xff abort page**, not the secret, so nothing
   but the transient window can leak -- and the architectural 0xff even poisons
   the flat oracle's slot 255.
2. *The flat oracle is undecodable transiently on this L1D.* `libsgxstep`'s
   oracle is 256 slots at a 0x1000 stride; on a 32 KiB / 8-way / 64-set L1D every
   slot lands in ONE set, and the round decodes "flush all 256 -> one transient
   -> reload all 256 in order". The reload of slots `0..secret-1` evicts
   `slot[secret]` before it is timed, so only small values survive. This is the
   same set-scoped property already measured in README section 12; `leaktest.c`
   worked around it with a split lo/hi oracle (one class per set) and reached
   0/64, but the enclave path never got that fix.

TSX is unavailable here (`grep -oE 'rtm|hle' /proc/cpuinfo` is empty at microcode
0xba), so upstream's `USE_TSX 1` reliable path is off the table; the split
oracle is the route.

**Fix, implemented and VERIFIED on `.86` (2026-09-17, sudo run).** Definitive
repeatability run: `(b) TRIALS=5 REPEAT=9` -> 5/5 trials `[OK] recovered all 64
bytes!`; `(a) FS_SPLIT_ORACLE=1 FS_SPLIT_REPEAT=9` -> `[OK] Foreshadow correctly
derived all 64 bytes!`.

A single split-oracle measurement is ~99% correct per byte: most trials give a
clean 64/64, but the EENTER/EEXIT overhead occasionally evicts the secret line
before the transient, which leaks 0x00 and misses that byte (observed worst case
60/64 in one trial out of ten). A **per-byte majority vote** closes it: the true
value is stable across repeats while the eviction is random, so the mode is
correct. This is the paper's repeated-measurement approach.

* **(a)** `patches/0005-libsgxstep-app-foreshadow-split-oracle.patch` --
  `FS_SPLIT_ORACLE=1` adds the split lo/hi oracle to `libsgxstep/foreshadow.c`
  (with a `FS_SPLIT_REPEAT` majority vote, default 5) and an `SA_SIGINFO`
  RIP-skip handler to `app/foreshadow/main.c`. Default off, no change for other
  apps. `FS_SPLIT_ORACLE=1 ./app` prints `[OK] Foreshadow correctly derived all
  64 bytes!`; the flag unset reproduces the ~10% flat-oracle run.
* **(b)** `app/foreshadow-encl-split` (source `harness/foreshadow-encl-split.c`)
  -- the leaktest-proven measurement on the real enclave, priming per candidate
  via `enclave_reload()`, with a `REPEAT` majority vote (default 5). `[OK] trial
  N: recovered all 64 bytes!`, `faults=68` per byte, one hot candidate per trace
  at ~44-52 cycles. `SELFTEST=1` passes 6/6. Use `REPEAT=9`/`FS_SPLIT_REPEAT=9`
  for a margin on repeated multi-trial runs.

Run commands are in the README "Deliverables (a)/(b)" section. If yield is still
short, disable the HW prefetchers on the victim core
(`sudo modprobe msr; sudo wrmsr -p1 0x1a4 0xf`) -- the set-scoped false hit is
consistent with a prefetcher refill and is standard flush+reload hygiene not yet
in the boot parameters.

## SSA/GPRSGX register-frame dump -- WORKS via a warm transient read (2026-09-17)

The other half of Foreshadow-SGX is leaking the enclave's *register file*: an AEX
writes all GPRs into the SSA GPRSGX region -> read that region transiently. It
**works on this host**: `app/foreshadow-ssa-warm` recovers the register frame by a
pure L1TF transient read (no TSX; EDBGRD is used only as ground truth).

### Result (rigorous run -- EDBGRD removed from the hot path, 2026-09-18)

    done: AEX=8833, transient-read faults=8832          (1 warm leak per AEX)
    [EDBGRD]          12/12 registers                   (ground truth, taken ONCE after the run)
    [TRANSIENT-WARM]  11/12 registers ; 88/96 known bytes   (WARM_VOTES=24, enclave loop 4e9)
    rax..r14                                            8/8 each  [OK]  (11 registers exact)
    r15   transient=0x1012101001021001  edbgrd=0x1515151515151515   0/8  (systematic, see below)
    RIP   transient=0x00007f32 f960 121d  edbgrd=0x00007f1b f960 121d   7/8 bytes
    URSP  transient=0x00007fff 243d 56a0  edbgrd=0x00007fff 243d 56a0   8/8  [MATCH]

**The self-warming confound is ruled out.** `edbgrd()` is `pread("/proc/self/mem")`,
which pulls the SSA into L1D -- so if it ran in the AEP hot path, a following
"transient" read would be trivially hot and prove nothing. In this run edbgrd is
NOT called during the leak at all; ground truth is captured ONCE after
`enclave_spin` returns. The SSA is warm only because the AEX wrote it.

**The decisive proof is the URSP canary.** URSP is the untrusted RSP that the AEX
records in GPRSGX -- a live runtime stack pointer we never plant in any register.
The transient read recovers it **byte-exact (8/8, `[MATCH]`)**. A self-warmed
constant or a coincidence cannot reproduce a runtime pointer to all 8 bytes; only
a genuine read of the AEX-written frame can. RIP (the enclave code pointer, also
AEX-written) comes back 7/8 -- the instruction-offset bytes `..f960121d` exact,
one high base byte mis-voted. Together with the 11 planted registers recovered
8/8, this is a genuine transient Foreshadow-SGX register leak -- not the debug
facility, and not a self-warmed page.

**Honest artifact: 1-2 registers per run land below the decision margin, and it is
a LIVE-PATH SNR limit, not an oracle/decoder bug (2026-09-18, root-caused).** Which
register misses is stochastic across runs and decode thresholds: r15 was 0/8 under
the `+20` rescue in one run but 8/8 in another; the `excl_t+8` variant instead broke
r8/r9; a `b>=HOT_CYCLES` variant scattered the misses (r10, and the RIP/URSP
canaries flaked). No single decode threshold fixes it -- each only moves which
register tips over (measured over 5 runs each; the conservative `+20` is the best
point: 11/12 + stable canaries).

Two earlier explanations were tested and **refuted**:

1. *"r15's true class collides with the excluded SSA-set slot."* Wrong. The GPRSGX
   frame ends exactly on the page boundary, so its page offset is `0x1000-184 =
   0xf48` (confirmed: `ssa_ptr = 0x..f48`). With page-aligned oracles (`base_set=0`)
   the excluded class is `c* = set_of(alias+byte) in {61,62,63}` (bytes 0-55 -> 61,
   56-119 -> 62, 120-183 -> 63) -- **never 21** (r15's class). r15 also shares one
   L1 line (set 63) with RIP/URSP, which recover 7/8 and 8/8.
2. *"The class-21 oracle slot is dead."* Wrong. `harness/selftest-decode.c` runs the
   exact decode path (same `SLOT_SIZE`, `leak_lo/leak_hi`, `set_of`, `+20`
   `decode_trace_warm`) offline on attacker memory at the real page offsets -- no
   SGX, no AEX, no root. Result: **256/256 values correct in all three groups**, and
   the raw latency vector for `v=0x15` shows **class 21 hot at 47 cycles** vs ~260
   for every miss. The decoder and oracle geometry are provably correct.

**Root cause (by elimination): the live transient + fault path, not the oracle.**
Offline the `movb` reads present memory, so the oracle touch retires
architecturally (strong signal) -> 256/256. Live, the `movb` faults: the oracle
touch happens only *transiently* (one weak speculative window), and the SIGSEGV
skip-handler + `sigreturn` then run between that touch and the `reload`, evicting L1
lines and adding latency. A marginal slot occasionally decays below the decision
margin before it is timed -- hence 1-2 stochastic misses per run. This does not
weaken the result: 11/12 registers 8/8 plus the AEX-written URSP canary recovered
byte-exact (`[MATCH]`, repeatable) already prove a genuine live AEX-window leak.

**Fix direction -- measured, not assumed (2026-09-19).** Oracle rewrites (a second
base_set "differential" oracle, or XOR-key slot permutation) are unnecessary -- the
offline 256/256 proves the oracle is sound. Two live-path levers were considered:

- **Branch-misprediction leak gadget instead of a faulting load -- REFUTED by
  measurement.** The idea was to squash the access speculatively so no #PF /
  SIGSEGV / `sigreturn` runs between the transient touch and the reload. But
  `harness/l1tf-mp-probe.c` (faithful: the same page through a real non-present
  alias, fault path vs misprediction, no enclave) shows **L1TF does not forward in
  the misprediction window on this i3-6100**: the fault+skip path recovers class 42
  at 55 cycles (control), the misprediction path leaves it cold at ~303. The
  terminal-fault forward needs the fault to actually occur; the misprediction
  squashes too early. Confirmed offline too (`selftest-mispredict3.c`, PROT_NONE
  proxy: 0/256). The misprediction gadget itself is sound (`selftest-mispredict.c`
  /`-mispredict2.c`: 252-256/256 on present targets) -- it just cannot drive an
  L1TF read here. **So the fault + skip handler is required; the 1-2 misses per run
  are transient-signal noise on that path and cannot be removed this way.**
- **Abstention** -- report `?` when no slot is clearly hot, so a marginal register
  reads as "no signal" instead of a silent wrong value. Still available as an
  honesty improvement; does not change the leak.
- **Cross-run vote statistics -- REACHES 12/12 (2026-09-19).** `VOTE_DUMP=<path>`
  writes the raw per-byte vote vectors after each run; `harness/warm_vote_stats.py`
  aggregates N dumps per offset / register / physical GPRSGX line (sets 61/62/63)
  and classifies every offset as systematic (fails in ~all runs -> geometry fix) or
  stochastic (fails in a fraction of runs -> votes/noise fix). Measured over **N=30
  runs** (`--votes 24`, prefetchers off): every failing byte is classified
  **stochastic; systematic = none**, all confined to the collision sets 61/62/63.
  10/30 runs already scored a lone 12/12, and *which* register tipped over was
  random run-to-run (r11 and r15 were 0/8 in run 01 but recovered in others).
  "Random" is cross-run only: within a run the miss is a deterministic function of
  the byte VALUE, not its offset/line (see "Residual is value-correlated" below).
  Since the frame is fixed and the per-run gate is ~independent, the per-byte
  **majority across the 30 runs, taken per byte offset on the low-six-bit class
  and the high-two-bit class separately, recovers all 12 fixed-canary GPRs, 96/96
  bytes** (153/153 of all constant-truth bytes) -- every pooled byte
  matches the canary (rax `deadbeefcafebabe`, rcx `0d0000dbaaaaaaaad`, ..., r15
  `1515..`; winning rate 0.77-0.97, always > 0.5). This is the same repeated-
  measurement majority vote that closes the 64/64 memory-secret leak, applied to the
  register frame. **The register-frame leak therefore reaches a clean 12/12 here
  without EDBGRD and without TSX** -- by pooling, per byte offset, the low-six-bit
  and high-two-bit class votes from repeated reads. The misprediction gadgets we
  tried are a separate negative result, not part of this recovery.

> Target CPU (i3-6100) does not enumerate TSX. CPUID leaf 7, subleaf 0:
> HLE is EBX[4], RTM is EBX[11], both 0; RTM_ALWAYS_ABORT is EDX[11], also 0.
> /proc/cpuinfo has neither rtm nor hle. The original Foreshadow PoC's TSX-based
> fault suppression is unavailable on this machine. The reproduction uses a
> SIGSEGV skip handler. That is a choice for this CPU, not a claim that no other
> fault-suppression gadget can work.

**Final position:** both halves reproduce. Memory-secret: 64/64. GPRSGX registers:
a single run is typically 10-12/12 (a clean 12/12 does occur; one post-reboot
control on 2026-09-21 was 12/12, 96/96, with RIP and URSP byte-exact) via the
fault path. **The cross-run majority vote over N=30 runs closes it to a clean
12/12, 96/96 bytes** (`warm_vote_stats.py`, 2026-09-19). No TSX on this CPU.
The misprediction gadgets we built produced no recoverable L1TF signal here
(fault path ~55 cycles, those gadgets ~303); that does not generalise to every
Skylake or every gadget. Foreshadow §3.2 offers a mispredicted branch as a TSX
alternative. 12/12 as a reliable claim
is a repeated-measurement result, not a single-shot one, exactly like the 64/64
memory-secret majority vote. A second oracle base does not improve on that; see
the follow-up below.

### Residual is value-correlated, not position-correlated (2026-09-19, adjudicated)

A colleague argued (correctly) that "stochastic noise" mislabels the residual, and
(incorrectly) that the cause is an oracle-slot vs SSA-line set collision re-drawn by
ASLR. Adjudicated on the 30 dumps with `harness/value_corr.py`; full write-up in
README section 16. Summary:

- **Confirmed:** the miss is a function of the leaked VALUE, not the offset or cache
  line. Value `0x12` in three different lines (sets 61/62/63) has a **bit-identical**
  30-run failure bitmap (Hamming 0). Rules out per-byte noise and SSA-line eviction.
- **Confirmed by a controlled swap (2026-09-19), refuting the position hypothesis.**
  The one value that appears in only one register (r15's `0x15`, at the last GPRSGX
  line off 120/set 63) confounds value with position. So we swapped it in
  `enclave_spin`: r15<-0x10, r10<-0x15, rax<-0x15, rebuilt/re-signed the enclave, and
  re-collected 30 runs. The fragility **followed the value**: off 120 (now `0x10`)
  jumped 21/30 -> 27/30 (recovered), while rax (set 61) and r10 (set 62), robust
  before, went to all-8-bytes-marginal once they held `0x15`. So r15 was never a
  "last-line/boundary" artifact -- it was fragile because it carried `0x15`. Composite
  stayed 158/158 with the swapped values. In that collection the weak values
  clustered at low-six-bit classes 17-21 (`0x11`-`0x15`), plus mild 8/25 (`0x88`/`0x99`).
  `0x10` is robust. `0x00` is not the same evidence: the lo argmax starts at class
  0, so an empty histogram decodes as 0 and a true `0x00` can look recovered
  without a deposit.
- **Raw per-vote latency (2026-09-19): no hot slot at reload, not a proved cause.**
  `RAW_LAT_DUMP` records the full 64-class lo-trace latency vector per vote for a
  weak target (off 120 = `0x15`, class 21) and a control (off 80 = `0x10`, class 16).
  A hot slot is ~50 cyc; the rest are ~265. In every CORRECT trace the true class
  is sharply hot (~52). In every WRONG trace the true class is cold (~268) and the
  argmin is another cold slot (~252-256), with no competing hot slot. Failed traces
  showed no distinguishable hot slot at reload time. That does not separate a
  deposit that never happened from one evicted before the reload, and it rules out
  a wrong hot slot (mis-decode). `0x15` was hot in 19/24 traces, `0x10` in 23/24.
  Because the oracle is page-aligned, class = value&0x3f is also the L1D set, so
  one hypothesis is that sets 17-21 are less reliable. That hypothesis is separate
  from the refuted ASLR collision below, and the follow-up bullet is the test.
- **Refuted:** the ASLR/collision mechanism. `oracle_lo`/`oracle_hi` are page-aligned
  in every run (base L1D set = 0 for all 30); the L1D set index is VA bits 6-11 = the
  page offset, which ASLR never moves; the GPRSGX page offset is fixed at `0xF48`. So
  the slot->set map is identical across runs, and the failing values' oracle slots sit
  in sets 0-30, never the SSA read sets 61/62/63. There is no movable collision, so
  an ASLR-motivated re-alignment of an already page-aligned oracle does not apply.
- **Follow-up (2026-09-20/21): a second oracle base is not the single-run fix.**
  Shifting the lo oracle by `0x400` (class c -> set (c+16) mod 64, so class 21
  moves from set 21 to set 37) left r15/`0x15` at 15/15 on both arms. Fragility
  moved between other classes (r13 and r9 up, rbx `0xda` down). Single-run 12/12
  was 3/15 unshifted and 7/15 shifted, not a significant gap. `DUAL_BASE=1` (both
  bases in one transient window, hot-gate) collapsed the lo channel: 4412/4416
  traces had two different hot classes and the decoder locked onto class `0x27`.
  `DUAL_BASE=2` (separate AEX per base, vote only when the two argmins agree)
  stayed healthy (2749/2944 agrees, about 93%) but did not beat the plain oracle
  on the same boot: control 12/12 and 96/96, dual 11/12 and 94/96. The two missed
  dual bytes had no agreed lo vote; the empty-histogram argmax reported them as
  class 0 (`0xda` displayed as `0xc0`). The reliable 12/12 remains the cross-run
  majority.
- **Actual mechanism (measured on the N=30 set):** value-specific decode margin
  (`0x15` weakest there, then `0x12/0x14/0x13/0x11`) gated by a per-run global
  quality factor (per-run failure count 0..32, with 7 clean runs). Voting averages
  that global gate. The later set-remap did not remove the residual, so the vote
  is not masking a geometry bug we know how to fix.
- **Reporting hygiene:** 31/184 bytes have a run-varying ground truth (`rflags` low
  bits, ASLR/AEX-dependent high bytes of `rip`/`ursp`, `rsvd`); a cross-run vote is
  undefined for them and they are not attack failures. Composite over the 153
  constant-truth bytes is **153/153** (includes the 96 GPR canary bytes = 12/12).

This value-correlation is itself a finding: the 2018 PoC's `RETRIES=N` re-measurement
averaged it away, so the structure of the SIGSEGV-path residual was never surfaced.

### What this reproduction adds over the 2018 Foreshadow PoC

Foreshadow (Van Bulck et al., USENIX Security 2018) established the vulnerability:
L1TF forwards an L1D line through a non-present/reserved SGX PTE in the terminal-fault
window, leaking enclave memory and the SSA/GPRSGX register frame, defeating SGX
attestation on pre-fix microcode. This lab does not claim a new vulnerability. What it
adds is a faithful reproduction on a stack quite unlike 2018's, plus two
characterisations the original did not surface. Honest scope: known canaries + a real
RIP/URSP on a debug-launched enclave, on deliberately-vulnerable microcode (0xBA); not
key extraction against a production, patched deployment.

1. **No-TSX reproduction on a stock 2026 stack.** 2018 used TSX (RTM) for fault
   suppression and a patched SGX runtime. This i3-6100 at ucode 0xBA enumerates no TSX
   and the box has no FLC and only stock PSW 2.27. Both halves still reproduce using:
   a SIGSEGV RIP-skip handler instead of TSX; a runtime **binary hook** of the stock
   `urts` default AEP (`ENCLU;ud2`) instead of the patched runtime's `sgx_set_aep`; a
   legacy `isgx` port to kernel 7.1.5. This documents exactly which 2018 primitives
   must be replaced when TSX and the patched runtime are absent.
2. **The upstream oracle is undecodable on this L1D; a split lo/hi oracle fixes it.**
   The flat 256-slot / 0x1000-stride oracle collapses into one L1D set here (32 KiB,
   8-way, 64 sets), capping yield at ~10%; the split one-class-per-set oracle restores
   64/64. A concrete, measured microarchitectural constraint on the classic oracle.
3. **The SIGSEGV-path residual is value-correlated (new characterisation).** See the
   subsection above: on the non-TSX fault path the miss is keyed on the leaked value
   (bit-identical failure across cache lines), not on position; `RETRIES=N` hid this.
   A second oracle base was tested afterwards and does not turn that into a stable
   single-run 12/12. The reliable 12/12 is the cross-run majority.
4. **L1TF does NOT forward under branch misprediction on this part (measured
   negative).** `l1tf-mp-probe.c`: the fault path forwards (55 cyc hot) but a
   Spectre-v1-style squashed access does not (303 cold). The terminal-fault forward
   needs the fault to actually occur -- so the fault + skip handler is required, and a
   "cleaner" mispredict gadget is a dead end here. A crisp, if negative, datapoint on
   how L1TF differs from Meltdown/Spectre forwarding.
5. **A fully self-checking, instrumented artifact:** AEX-written RIP/URSP canaries
   (prove a live-window read, not a self-warmed page), an offline root-free decoder
   selftest (256/256), and cross-run vote statistics. Reproduction packaged for
   teaching and for defensive measurement, not just a one-shot exploit.

### Why the earlier "blocked" conclusion was wrong

An earlier version of this file concluded the transient SSA attack was
structurally blocked. That was an IMPLEMENTATION bug, not a platform limit
(microcode 0xba has no L1D-flush-on-AEX, so the channel is fully open -- the
64/64 memory-secret leak already proves it). Three fixes made it work:

1. **Trigger the AEX with the APIC timer, not a `#PF`.** A `#PF`-triggered AEX
   goes through the kernel `#PF`/signal path, which evicts the SSA before any
   user read (the cold, all-noise result seen before). A periodic-timer AEX is
   serviced by SGX-Step's minimal user-space ISR, then our AEP callback runs in
   normal CPL3 with the SSA still warm.
2. **No page-table writes in the hot path.** The present-cleared SSA alias is set
   up once; the skip handler never re-presents it. Re-arming the PTE per read (as
   the first version did) evicts the warm GPRSGX before it is read.
3. **Correct frame-0 GPRSGX address.** `get_enclave_ssa_gprsgx_adrs()` uses the
   live CSSA (0 at setup), pointing one 4 KiB frame too low. Compute frame 0
   explicitly: `base + OSSA + SSAFRAMESIZE - GPRSGX_SIZE`.

### How the warm CPL3 hook is obtained on the stock runtime (B.1)

SGX-Step's AEP callback needs `sgx_set_aep`, which the stock PSW 2.27 lacks
(`aep_stub.c` stubs it). Instead we **binary-hook the urts' default async-exit
pointer at runtime** (`app/aep-hook-test` validated this): the stock AEP is the
unique `ENCLU; ud2` (`0f 01 d7 0f 0b`) in `libsgx_urts.so`; we overwrite it with
`movabs $sgx_step_aep_trampoline, %rax; jmp *%rax` (rax is dead there), so every
AEX runs SGX-Step's trampoline -> `sgx_step_aep_cb`. No runtime rebuild needed.
The victim is `enclave_spin()` (added to the enclave), which loads known register
values and spins, so any AEX in the loop captures them; the decode uses the split
lo/hi oracle in reload-all mode with a per-trace majority vote.

The leak still runs in the CPL3 AEP callback (fault + skip handler), which turned
out to be warm enough here; a colleague's suggested next step -- leaking in the
ring-0 ISR with a branch-misprediction gadget (no fault to suppress) -- is the
route if a tighter/faster window is ever needed, but was not necessary to succeed.

**Bottom line:** both halves of Foreshadow-SGX reproduce on this host -- the
64/64 memory-secret leak and the transient GPRSGX register-frame leak -- with no
TSX and the stock runtime. A single run recovers 11/12 registers 8/8 plus the
AEX-written URSP canary byte-exact (`[MATCH]`); the cross-run majority vote over
N=30 runs recovers a clean **12/12, 96/96 bytes**. r15 is NOT a systematic
artifact: it misses stochastically (0/8 in some runs, 8/8 in others) and its pooled
value across runs is the correct `1515..` -- the earlier "systematic r15" note was
wrong and is retracted.

## Reproducing

```bash
# once per boot: ONE command (loads modules + aesmd, drops to the user, verifies)
sudo ~/CPU/labs/foreshadow/setup/90-start-lab.sh

# the attack itself (the script prints this line verbatim)
cd $HOME/sgx-step/app/foreshadow && sudo timeout 1800 env \
    FORESHADOW_ZERO_RETRIES=48 \
    LD_PRELOAD=$HOME/sgx-step/libsgxstep/fixalign.so \
    LD_LIBRARY_PATH=$HOME/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu:$HOME/sgxsdk/psw227/libs/protobuf23/usr/lib/x86_64-linux-gnu:$HOME/sgxsdk/sdk227/lib64 \
    ./app
```
