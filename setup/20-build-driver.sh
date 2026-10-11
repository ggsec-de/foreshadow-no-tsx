#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
#
# Foreshadow / SGX-Step lab -- build and load /dev/sgx-step.
#
# This is the piece that was missing on .86: the SGX-Step loadable kernel module
# from kernel/sgxstep.c. Upstream was tested on Ubuntu 20.04/22.04 kernels; on
# Kali 6.19 the build may need a small port (see labs/foreshadow/README.md,
# "Porting notes").
#
# Usage:
#   SGXSTEP_DIR=$HOME/sgx-step sudo -E ./20-build-driver.sh          # build only
#   SGXSTEP_DIR=$HOME/sgx-step sudo -E ./20-build-driver.sh --load   # build + insmod
#
set -uo pipefail

LOAD=0
for arg in "$@"; do
    case "$arg" in
        --load) LOAD=1 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root (module build/load)" >&2
    exit 2
fi

###############################################################################
# Locate the sgx-step source tree

if [[ -z ${SGXSTEP_DIR:-} ]]; then
    for cand in "$HOME/sgx-step" /opt/sgx-step /usr/local/src/sgx-step; do
        if [[ -f $cand/kernel/sgxstep.c ]]; then
            SGXSTEP_DIR=$cand
            break
        fi
    done
fi

if [[ -z ${SGXSTEP_DIR:-} || ! -f $SGXSTEP_DIR/kernel/sgxstep.c ]]; then
    cat >&2 <<'EOF'
error: sgx-step source tree not found.
Clone it with submodules and pass the path explicitly:

  git clone --recursive https://github.com/jovanbulck/sgx-step.git ~/sgx-step
  SGXSTEP_DIR=~/sgx-step sudo -E ./20-build-driver.sh --load
EOF
    exit 2
fi

KVER=$(uname -r)
KERNEL_DIR=$SGXSTEP_DIR/kernel
LOG=$KERNEL_DIR/build-$KVER.log

echo "== sgx-step driver build =="
echo "  tree      : $SGXSTEP_DIR"
echo "  kernel    : $KVER"
echo "  log       : $LOG"
echo

###############################################################################
# Prerequisites

if [[ ! -d /lib/modules/$KVER/build ]]; then
    echo "error: /lib/modules/$KVER/build missing -- install the matching headers:" >&2
    echo "       sudo apt install linux-headers-$KVER" >&2
    exit 2
fi

if [[ -d $SGXSTEP_DIR/kernel/linux-sgx-driver && -z $(ls -A "$SGXSTEP_DIR/kernel/linux-sgx-driver" 2>/dev/null) ]]; then
    echo "note: kernel/linux-sgx-driver submodule is empty."
    echo "      Run: git -C '$SGXSTEP_DIR' submodule update --init --recursive"
    echo "      (only needed for the out-of-tree isgx driver, not for /dev/sgx-step)"
    echo
fi

###############################################################################
# Unload a previous instance so a re-build does not fail with -EBUSY

if lsmod | grep -qw sgx_step; then
    echo "note: sgx_step already loaded, unloading first"
    rmmod sgx_step || true
fi

###############################################################################
# Build

echo "== make =="
make -C "$KERNEL_DIR" clean >"$LOG" 2>&1
if make -C "$KERNEL_DIR" >>"$LOG" 2>&1; then
    echo "  [ OK ]  build succeeded, see $LOG"
else
    echo "  [FAIL]  build failed. Last 40 lines:" >&2
    tail -40 "$LOG" >&2
    cat <<'EOF' >&2

== likely causes on a 6.x kernel (patch minimally, keep the diff small) ==

1) struct apic / apic->read() / apic->write() in save_apic() / restore_apic()
   If the symbol or the hookup is gone, use the x2APIC MSR interface instead
   (equivalent with X2APIC=1 in libsgxstep/config.h):
     LVTT  -> MSR 0x832 (IA32_X2APIC_LVT_TIMER)
     TMICT -> MSR 0x838 (IA32_X2APIC_TMICT)
     TDCR  -> MSR 0x83E (IA32_X2APIC_TDCR)
   Keep the same "current CPU only" discipline as the original code.

2) pin_user_pages_fast(..., FOLL_LONGTERM | FOLL_WRITE, ...) in
   sgx_step_ioctl_setup_isr_map() -- pinning rules changed after 5.6.

3) 5-level paging (CONFIG_PGTABLE_LEVELS=5) -- boot with no5lvl, the PTE walk
   in sgx_step_get_pt_mapping() only handles 4 levels.

4) kretprobe on devmem_is_allowed no longer registers -> the module loads but
   /dev/mem keeps refusing the APIC page.

5) Generic API drift (header moves, vm_flags, symbol visibility): read the first
   real error in the log, not the last cascade of them.

Send the log back with the exact error to iterate on the patch.
EOF
    exit 1
fi

ls -l "$KERNEL_DIR"/sgx-step.ko 2>/dev/null || true

###############################################################################
# Load and verify

if [[ $LOAD -eq 0 ]]; then
    echo
    echo "build only -- re-run with --load to insmod the module"
    exit 0
fi

echo
echo "== load =="
# Make sure the SGX driver and the msr module are around (kernel/Makefile does
# the same via `make load`).
modprobe -a msr 2>/dev/null || true
if [[ -e /dev/sgx_enclave ]]; then
    : # in-tree SGX driver, nothing to load
elif [[ -e /dev/isgx ]]; then
    : # out-of-tree driver already loaded
else
    echo "  note: no /dev/sgx_enclave and no /dev/isgx yet."
    echo "        Needed for the real enclave (Phase 3); /dev/sgx-step works without it."
fi

if ! insmod "$KERNEL_DIR/sgx-step.ko"; then
    echo "  [FAIL]  insmod failed -- check 'dmesg | tail' for the unknown symbol" >&2
    exit 1
fi

echo
echo "== verify =="
dmesg | tail -n 15

RC=0
if [[ -e /dev/sgx-step ]]; then
    echo "  [ OK ]  /dev/sgx-step exists"
    ls -l /dev/sgx-step
else
    echo "  [FAIL]  /dev/sgx-step was not created"
    RC=1
fi

if dmesg | tail -n 30 | grep -q 'register_kprobe failed'; then
    echo "  [FAIL]  kretprobe on devmem_is_allowed failed to register"
    echo "          -> /dev/mem will refuse the APIC page and libsgxstep fails later"
    RC=1
else
    echo "  [ OK ]  no kprobe registration error in the last dmesg lines"
fi

if [[ ${L1TF_SETTLE:-0} == 1 ]]; then
    echo
    echo "note: to make sure IDT/APIC restoration works, unload and watch the timer:"
    echo "  rmmod sgx_step"
    echo "  watch -n0.1 \"cat /proc/interrupts | grep 'Local timer interrupts'\""
fi

exit $RC
