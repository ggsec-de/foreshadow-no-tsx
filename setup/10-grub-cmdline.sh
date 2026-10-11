#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
#
# Foreshadow / SGX-Step lab -- merge the required kernel boot parameters into
# /etc/default/grub (Debian/Kali style) and optionally drop a sysctl file.
#
# Nothing is written unless --apply is given; the script always prints the
# resulting GRUB_CMDLINE_LINUX_DEFAULT so the diff can be reviewed first.
#
# Usage:
#   sudo ./10-grub-cmdline.sh                 # dry run, show what would change
#   sudo ./10-grub-cmdline.sh --apply         # write + update-grub
#   sudo DIS_UCODE=0 ./10-grub-cmdline.sh --apply   # skip dis_ucode_ldr
#
# WARNING: these parameters deliberately disable KPTI, SMEP, SMAP, UMIP and
# microcode updates, and relax /dev/mem. Dedicated lab machine only.
#
set -uo pipefail

APPLY=0
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root" >&2
    exit 2
fi

GRUB_FILE=${GRUB_FILE:-/etc/default/grub}
SYSCTL_FILE=/etc/sysctl.d/99-sgx-step.conf

###############################################################################
# Parameters

# Exactly the set asserted by sgx-step/check_sys.sh against /proc/cmdline.
REQUIRED=(
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

OPTIONAL=()
# Required for the Foreshadow PoC: microcode flushes L1D on EENTER/EEXIT, after
# which no cache hits can be observed. DIS_UCODE=0 skips it.
if [[ ${DIS_UCODE:-1} == 1 ]]; then
    OPTIONAL+=(dis_ucode_ldr)
fi
# Execution-time stability.
OPTIONAL+=(intel_idle.max_cstate=1 processor.max_cstate=1)

KVER=$(uname -r)
if [[ -r /boot/config-$KVER ]] && grep -qE '^CONFIG_PGTABLE_LEVELS=5' /boot/config-$KVER; then
    OPTIONAL+=(no5lvl)
    echo "note: 5-level paging detected, adding no5lvl (libsgxstep walks 4 levels only)"
fi

# NOTE: nox2apic is intentionally NOT added. libsgxstep/config.h defaults to
# X2APIC=1 and recent CPUs with LEGACY_XAPIC_DISABLED only support x2APIC.

WANT=("${REQUIRED[@]}" "${OPTIONAL[@]}")

###############################################################################
# Current line

if [[ ! -r $GRUB_FILE ]]; then
    echo "error: $GRUB_FILE not readable" >&2
    exit 2
fi

CURRENT=$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE" | head -1)
if [[ -z "$CURRENT" ]]; then
    echo "error: GRUB_CMDLINE_LINUX_DEFAULT not found in $GRUB_FILE" >&2
    exit 2
fi

# Strip the variable name and the surrounding quotes.
CUR_VAL=$(sed -E 's/^GRUB_CMDLINE_LINUX_DEFAULT="?//; s/"?$//' <<<"$CURRENT")

# clearcpuid may already be present with a different bit list -- merge the bits.
CLEARCPUID_BITS=""
ADDED=()
for want in "${WANT[@]}"; do
    base=${want%%=*}
    if [[ $base == clearcpuid ]]; then
        continue
    fi
    if grep -qE "(^| )${base}(=| |$)" <<<"$CUR_VAL"; then
        continue
    fi
    ADDED+=("$want")
done

# Merge clearcpuid bits: existing 'clearcpuid=a,b' plus 308,295,514.
EXISTING_BITS=$(grep -oE '(^| )clearcpuid=[0-9,]+' <<<"$CUR_VAL" | tail -1 | cut -d= -f2)
for bit in 308 295 514; do
    if [[ ",${EXISTING_BITS}," != *",${bit},"* ]]; then
        CLEARCPUID_BITS="${CLEARCPUID_BITS:+${CLEARCPUID_BITS},}${bit}"
    fi
done

NEW_VAL="$CUR_VAL"
if [[ -n "$CLEARCPUID_BITS" ]]; then
    if [[ -n "$EXISTING_BITS" ]]; then
        MERGED_BITS="${EXISTING_BITS},${CLEARCPUID_BITS}"
        # Remove the old token, the merged one is appended below.
        NEW_VAL=$(sed -E "s/(^| )clearcpuid=[0-9,]+//" <<<"$NEW_VAL")
    else
        MERGED_BITS="$CLEARCPUID_BITS"
    fi
    ADDED+=("clearcpuid=$MERGED_BITS")
fi

for tok in "${ADDED[@]:-}"; do
    [[ -z $tok ]] && continue
    NEW_VAL="$NEW_VAL $tok"
done
NEW_VAL=$(tr -s ' ' <<<"$NEW_VAL" | sed -E 's/^ //; s/ $//')

###############################################################################
# Report

echo "== kernel parameters =="
echo "current : $CUR_VAL"
echo "target  : $NEW_VAL"
echo
if [[ "$CUR_VAL" == "$NEW_VAL" ]]; then
    echo "already up to date -- nothing to add"
else
    echo "changes:"
    for tok in "${ADDED[@]:-}"; do
        [[ -n $tok ]] && echo "  + $tok"
    done
fi

echo
echo "== missing required parameters check =="
RC=0
for p in "${REQUIRED[@]}"; do
    if grep -qE "(^| )${p}( |$)" <<<"$NEW_VAL"; then
        echo "  [ OK ]  $p"
    else
        echo "  [FAIL]  $p"
        RC=1
    fi
done

if grep -qE '(^| )nox2apic( |$)' <<<"$NEW_VAL"; then
    echo "  [WARN]  nox2apic present but config.h uses X2APIC=1"
fi

###############################################################################
# Apply

if [[ $APPLY -ne 1 ]]; then
    echo
    echo "dry run -- re-run with --apply to write $GRUB_FILE and run update-grub"
    exit $RC
fi

cp -a "$GRUB_FILE" "${GRUB_FILE}.bak.$(date +%Y%m%d%H%M%S)"
sed -i -E "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${NEW_VAL}\"|" "$GRUB_FILE"
echo "updated $GRUB_FILE"

# libsgxstep maps pages below mmap_min_addr for some apps.
if [[ ! -e $SYSCTL_FILE ]] || ! grep -q '^vm.mmap_min_addr' "$SYSCTL_FILE"; then
    echo 'vm.mmap_min_addr = 0' >>"$SYSCTL_FILE"
    echo "wrote $SYSCTL_FILE"
fi
sysctl -q --system || true

if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    grub-mkconfig -o /boot/grub/grub.cfg
else
    echo "warning: no update-grub / grub-mkconfig found -- regenerate the bootloader config manually" >&2
fi

echo
echo "reboot, then verify with:"
echo "  cat /proc/cmdline"
echo "  sudo ./00-diagnose.sh"
echo "  sudo <sgx-step>/check_sys.sh"
exit $RC
