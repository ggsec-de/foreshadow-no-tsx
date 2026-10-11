#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
#
# Foreshadow / SGX-Step lab -- Phase 0 diagnostics.
#
# Read-only: this script changes nothing, it only inspects the host and prints
# a feasibility verdict for reproducing app/foreshadow from
# https://github.com/jovanbulck/sgx-step on this machine.
#
# Usage:  sudo ./00-diagnose.sh
#
set -uo pipefail

PASS=0
FAIL=0
WARN=0

ok()   { printf '  [ OK ]  %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  [FAIL]  %s\n' "$*"; FAIL=$((FAIL + 1)); }
warn() { printf '  [WARN]  %s\n' "$*"; WARN=$((WARN + 1)); }
note() { printf '          %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root (needs dmesg, lsmod, /proc/cmdline)" >&2
    exit 2
fi

hdr "host"
note "$(uname -a)"
note "hostname: $(hostname)"

CMDLINE=$(cat /proc/cmdline)
CPUINFO=$(cat /proc/cpuinfo)

###############################################################################
hdr "CPU vendor and model (Foreshadow/L1TF is Intel-only)"

VENDOR=$(grep -m1 '^vendor_id' <<<"$CPUINFO" | awk '{print $3}')
MODEL=$(grep -m1 '^model name' <<<"$CPUINFO" | awk -F': ' '{print $2}')
UCODE=$(grep -m1 '^microcode' <<<"$CPUINFO" | awk '{print $3}')
note "vendor:    ${VENDOR:-unknown}"
note "model:     ${MODEL:-unknown}"
note "microcode: ${UCODE:-unknown}"

if [[ "$VENDOR" == "GenuineIntel" ]]; then
    ok "Intel CPU -- L1TF/Foreshadow applies"
else
    bad "not an Intel CPU (vendor='${VENDOR:-unknown}') -- Foreshadow is Intel-only"
fi

###############################################################################
hdr "SGX availability"

if grep -qw sgx <<<"$(grep -m1 '^flags' <<<"$CPUINFO")"; then
    ok "CPU reports the 'sgx' flag"
else
    bad "no 'sgx' flag in /proc/cpuinfo"
    note "the flag is hidden both when the CPU/BIOS lacks SGX and when the kernel"
    note "was built without CONFIG_X86_SGX -- check the kernel config section below"
fi

SGX_DMESG=$(dmesg 2>/dev/null | grep -i -E 'sgx' | tail -20)
if [[ -n "$SGX_DMESG" ]]; then
    note "dmesg SGX lines:"
    while IFS= read -r line; do note "  $line"; done <<<"$SGX_DMESG"
    if grep -qi 'disabled by bios' <<<"$SGX_DMESG"; then
        bad "SGX is disabled in the BIOS/UEFI -- enable it (and reserve PRMRR) first"
    fi
    if grep -qi 'EPC' <<<"$SGX_DMESG"; then
        ok "EPC memory reserved by firmware (PRMRR allocated)"
    else
        warn "no EPC section in dmesg -- firmware may not have reserved SGX memory"
    fi
    if grep -qi 'launch control CPU feature is not available' <<<"$SGX_DMESG"; then
        bad "no flexible launch control (FLC): the in-tree /dev/sgx_enclave driver disabled itself"
        note "only the legacy out-of-tree isgx driver works on such a CPU (Skylake client)"
        note "-> the enclave-free SIM_ENCLAVE path is the realistic target on this host"
    fi
else
    warn "no SGX messages in dmesg (driver may not be loaded yet)"
fi

if grep -qw sgx_lc <<<"$(grep -m1 '^flags' <<<"$CPUINFO")"; then
    ok "sgx_lc flag present -- FLC available, in-tree /dev/sgx_enclave is usable"
else
    warn "no sgx_lc flag -- no FLC; in-tree SGX driver cannot be used here"
fi

for dev in /dev/sgx_enclave /dev/sgx_provision /dev/isgx; do
    if [[ -e $dev ]]; then ok "$dev present"; else note "$dev absent"; fi
done

###############################################################################
hdr "microcode mitigation state (decides whether L1D extraction can work)"

L1TF=/sys/devices/system/cpu/vulnerabilities/l1tf
if [[ -r $L1TF ]]; then
    L1TF_STATUS=$(cat "$L1TF")
    note "l1tf: $L1TF_STATUS"
    case "$L1TF_STATUS" in
        Vulnerable)
            ok "CPU reports Vulnerable -- L1D flush is not active, the PoC can extract" ;;
        *Mitigation*)
            warn "mitigation active (often from BIOS microcode, where dis_ucode_ldr cannot help):"
            note "expect cache hit/miss=0/... in the real PoC; use SIM_ENCLAVE=1" ;;
        *)
            warn "unexpected l1tf status, inspect manually" ;;
    esac
else
    warn "$L1TF not readable"
fi

if grep -qE '(^| )dis_ucode_ldr( |$)' <<<"$CMDLINE"; then
    ok "dis_ucode_ldr present on the kernel command line"
else
    warn "dis_ucode_ldr NOT on the command line (required for the Foreshadow extraction)"
fi
note "early microcode log: $(dmesg 2>/dev/null | grep -i -m1 'microcode' || echo '(none)')"
if dmesg 2>/dev/null | grep -qiE 'microcode: updated early|early microcode'; then
    note "early (initrd) microcode load detected -> booting with dis_ucode_ldr will drop"
    note "back to the firmware revision; compare 'microcode' in /proc/cpuinfo before/after"
else
    note "no early microcode update in dmesg -> the running revision comes from the firmware (ROM)"
    note "in that case dis_ucode_ldr cannot help and the L1D flush on enclave entry stays active"
fi

###############################################################################
hdr "recommended SGX-Step kernel parameters"

REQUIRED_PARAMS=(
    iomem=relaxed
    no_timer_check
    clearcpuid=308,295,514
    pti=off
    isolcpus=1
    nmi_watchdog=0
    rcupdate.rcu_cpu_stall_suppress=1
    msr.allow_writes=on
    vdso=0
)

MISSING=()
for p in "${REQUIRED_PARAMS[@]}"; do
    if grep -qE "(^| )${p}( |$)" <<<"$CMDLINE"; then
        ok "$p"
    else
        bad "$p missing from /proc/cmdline"
        MISSING+=("$p")
    fi
done
if ((${#MISSING[@]})); then
    note "run setup/10-grub-cmdline.sh --apply and reboot"
fi

# config.h defaults to X2APIC=1, so nox2apic must NOT be present.
if grep -qE '(^| )nox2apic( |$)' <<<"$CMDLINE"; then
    bad "nox2apic is set, but libsgxstep/config.h uses X2APIC=1 (set X2APIC 0 if you really need it)"
else
    ok "nox2apic absent (consistent with X2APIC=1 in libsgxstep/config.h)"
fi
if grep -qw x2apic <<<"$CPUINFO"; then
    ok "x2apic supported by the CPU"
else
    warn "x2apic not reported by the CPU"
fi

###############################################################################
hdr "CPU features that SGX-Step requires to be disabled"

for feat in smep smap umip; do
    if grep -qw "$feat" <<<"$CPUINFO"; then
        bad "$feat still active -- add clearcpuid=308,295,514 and reboot"
    else
        ok "$feat disabled"
    fi
done

KPTI=$(dmesg 2>/dev/null | grep -i 'page tables isolation' | tail -1)
if [[ -n "$KPTI" ]]; then
    if grep -qi 'disabled' <<<"$KPTI"; then
        ok "KPTI disabled ($KPTI)"
    else
        bad "KPTI active -- add pti=off and reboot ($KPTI)"
    fi
else
    warn "no KPTI status line in dmesg"
fi

###############################################################################
hdr "kernel build configuration"

KVER=$(uname -r)
KCONF=/boot/config-$KVER
if [[ -r $KCONF ]]; then
    for opt in CONFIG_MODULES CONFIG_X86_SGX CONFIG_X86_LA57 CONFIG_STRICT_DEVMEM \
               CONFIG_DEVMEM CONFIG_KPROBES CONFIG_KPROBE_EVENTS CONFIG_X86_KERNEL_IBT \
               CONFIG_PGTABLE_LEVELS CONFIG_MITIGATION_PAGE_TABLE_ISOLATION; do
        val=$(grep -E "^${opt}=" "$KCONF" | tail -1)
        if [[ -n "$val" ]]; then
            note "$val"
        elif grep -qE "^# ${opt} is not set" "$KCONF"; then
            note "$opt: not set"
        else
            note "$opt: absent from config"
        fi
    done
    # Kernel >= 6.9 renamed the mitigation options: CONFIG_PAGE_TABLE_ISOLATION
    # became CONFIG_MITIGATION_PAGE_TABLE_ISOLATION. Accept either name.
    if grep -qE '^CONFIG_(MITIGATION_)?PAGE_TABLE_ISOLATION=y' "$KCONF"; then
        note "KPTI is compiled in (pti=off turns it off at boot)"
    fi
    if grep -qE '^CONFIG_X86_SGX=y' "$KCONF"; then
        ok "CONFIG_X86_SGX=y -- in-tree /dev/sgx_enclave driver expected"
    elif grep -qE '^CONFIG_X86_SGX=m' "$KCONF"; then
        ok "CONFIG_X86_SGX=m -- load the sgx_enclave module"
    else
        warn "CONFIG_X86_SGX not enabled -- an out-of-tree isgx driver is required"
    fi
    if grep -qE '^CONFIG_PGTABLE_LEVELS=5' "$KCONF"; then
        if grep -qw la57 <<<"$CPUINFO"; then
            warn "5-level page tables and LA57 present -- boot with no5lvl (libsgxstep walks 4 levels)"
        else
            note "kernel compiled with 5-level paging but this CPU has no LA57 -> 4 levels at run time"
            note "no5lvl is harmless (pid 4 levels are used anyway)"
        fi
    fi
    if ! grep -qE '^CONFIG_KPROBES=y' "$KCONF"; then
        bad "CONFIG_KPROBES missing -- the devmem_is_allowed bypass cannot work"
    fi
else
    warn "$KCONF not readable -- cannot check kernel options"
fi

###############################################################################
hdr "kernel headers / module build prerequisites"

if [[ -d /lib/modules/$KVER/build ]]; then
    ok "/lib/modules/$KVER/build present"
    note "-> $(readlink -f /lib/modules/$KVER/build)"
else
    bad "/lib/modules/$KVER/build missing -- apt install linux-headers-$KVER"
fi
for tool in make gcc ld git; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool: $("$tool" --version 2>/dev/null | head -1)"
    else
        bad "$tool not installed"
    fi
done

###############################################################################
hdr "SGX-Step driver state"

if lsmod | grep -qw sgx_step; then
    ok "sgx_step module loaded"
else
    bad "sgx_step module NOT loaded (this is the missing driver on .86)"
    note "build it: ./20-build-driver.sh   (needs the sgx-step source tree)"
fi
[[ -e /dev/sgx-step ]] && ok "/dev/sgx-step exists" || note "/dev/sgx-step absent"
for mod in msr isgx sgx_enclave; do
    if lsmod | grep -qw "$mod"; then ok "module $mod loaded"; else note "module $mod not loaded"; fi
done

###############################################################################
hdr "topology"

if [[ -r /sys/devices/system/cpu/smt/active ]]; then
    note "SMT active: $(cat /sys/devices/system/cpu/smt/active) (Foreshadow also leaks from a sibling HT core)"
fi
note "online CPUs: $(nproc)"
note "isolcpus on cmdline: $(grep -oE '(^| )isolcpus=[^ ]*' <<<"$CMDLINE" || echo 'none')"

###############################################################################
hdr "verdict"
printf '  passed: %d   failed: %d   warnings: %d\n' "$PASS" "$FAIL" "$WARN"
if ((FAIL > 0)); then
    echo "  -> BLOCKED: fix the [FAIL] items above before building the PoC."
    exit 1
fi
if ((WARN > 0)); then
    echo "  -> PARTIAL: no hard blocker, but read the [WARN] items."
    exit 0
fi
echo "  -> CLEAR: this host is ready for the SGX-Step / Foreshadow build."
