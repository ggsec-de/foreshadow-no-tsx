#!/usr/bin/env bash
#
# Foreshadow / SGX-Step lab -- build (and optionally run) the PoC.
#
# Milestones (see labs/foreshadow/README.md, section 5):
#   --selftest  M1: app/selftest/idt  -- IDT/APIC plumbing, no SGX SDK, no enclave
#   --sim       M4: app/foreshadow with SIM_ENCLAVE=1 -- L1TF without EENTER
#   --full      M5: app/foreshadow with SIM_ENCLAVE=0 -- the real attack
#
# Requires /dev/sgx-step to be loaded for anything that touches libsgxstep.
#
# Usage:
#   SGXSTEP_DIR=$HOME/sgx-step ./40-build-poc.sh --selftest
#   SGXSTEP_DIR=$HOME/sgx-step sudo -E ./40-build-poc.sh --selftest --run
#   SGXSTEP_DIR=$HOME/sgx-step sudo -E ./40-build-poc.sh --sim --run
#
set -uo pipefail

MODE=""
RUN=0
for arg in "$@"; do
    case "$arg" in
        --selftest) MODE=selftest ;;
        --sim) MODE=sim ;;
        --full) MODE=full ;;
        --run) RUN=1 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ -z $MODE ]]; then
    echo "error: pick a milestone: --selftest | --sim | --full" >&2
    exit 2
fi

if [[ -z ${SGXSTEP_DIR:-} ]]; then
    for cand in "$HOME/sgx-step" /opt/sgx-step /usr/local/src/sgx-step; do
        [[ -f $cand/app/foreshadow/main.c ]] && SGXSTEP_DIR=$cand && break
    done
fi

if [[ -z ${SGXSTEP_DIR:-} || ! -f $SGXSTEP_DIR/app/foreshadow/main.c ]]; then
    echo "error: sgx-step source tree not found (set SGXSTEP_DIR)" >&2
    exit 2
fi

if [[ ! -e /dev/sgx-step ]]; then
    echo "warning: /dev/sgx-step is not present -- build/load it first:" >&2
    echo "         SGXSTEP_DIR=$SGXSTEP_DIR sudo -E ./20-build-driver.sh --load" >&2
fi

###############################################################################
# Milestone M1: no enclave, no SGX SDK

if [[ $MODE == selftest ]]; then
    APP=$SGXSTEP_DIR/app/selftest/idt
    [[ -d $APP ]] || { echo "error: $APP not found" >&2; exit 2; }

    echo "== M1: app/selftest/idt (IDT/APIC plumbing) =="
    make -C "$APP" clean all || exit 1

    if [[ $RUN -eq 1 ]]; then
        if [[ $EUID -ne 0 ]]; then
            echo "error: --run needs root" >&2
            exit 2
        fi
        echo
        echo "firing interrupts in a loop -- exit with CTRL-C, then check that the"
        echo "local APIC timer still ticks on all cores:"
        echo "  watch -n0.1 \"cat /proc/interrupts | grep 'Local timer interrupts'\""
        make -C "$APP" run
    else
        echo "built. Run: sudo make -C $APP run"
    fi
    exit 0
fi

###############################################################################
# Milestones M4/M5: the Foreshadow PoC itself

APP=$SGXSTEP_DIR/app/foreshadow
[[ -f $APP/main.c ]] || { echo "error: $APP/main.c not found" >&2; exit 2; }

if [[ -z ${SGX_SDK:-} && ! -d /opt/intel/sgxsdk ]]; then
    cat >&2 <<'EOF'
error: the (patched) Intel SGX SDK is required to build app/foreshadow.
It links against the untrusted runtime and the generated enclave proxy:

  cd <sgx-step>/sdk/intel-sdk && ./install_SGX_SDK.sh
  source /opt/intel/sgxsdk/environment

On Kali, linux-sgx v2.29 may not build with the default modern GCC; keep a
gcc-12 toolchain around and build with CC=gcc-12 CXX=g++-12.
EOF
    exit 2
fi

case "$MODE" in
    sim)  SIM=1; LABEL="M4: SIM_ENCLAVE=1 (L1TF without EENTER)" ;;
    full) SIM=0; LABEL="M5: SIM_ENCLAVE=0 (real enclave attack)" ;;
esac

echo "== $LABEL =="
CUR=$(grep -E '^#define SIM_ENCLAVE[[:space:]]+[01]' "$APP/main.c" | awk '{print $3}')
echo "  main.c SIM_ENCLAVE: ${CUR:-unset} -> $SIM"

if [[ "$CUR" != "$SIM" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "  [WARN] changing the define needs write access to $APP/main.c (run as root)"
    elif [[ ${APPLY:-1} == 1 ]]; then
        cp -a "$APP/main.c" "$APP/main.c.bak.$(date +%Y%m%d%H%M%S)"
        sed -i -E "s/^#define SIM_ENCLAVE[[:space:]]+[01]/#define SIM_ENCLAVE         $SIM/" "$APP/main.c"
        echo "  patched $APP/main.c"
    fi
fi

if [[ $MODE == full ]]; then
    L1TF=$(cat /sys/devices/system/cpu/vulnerabilities/l1tf 2>/dev/null || echo unknown)
    echo "  l1tf status: $L1TF"
    if [[ $L1TF == Vulnerable ]]; then
        echo "  [ OK ]  no L1D flush mitigation -- the real attack can produce hits"
    else
        echo "  [WARN] mitigation active: expect 'cache hit/miss=0/...'."
        echo "         A microcode fix delivered by the BIOS cannot be undone with"
        echo "         dis_ucode_ldr; use --sim to demonstrate the primitive instead."
    fi
fi

echo
echo "== build =="
make -C "$APP" clean all || exit 1

if [[ $RUN -eq 1 ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "error: --run needs root" >&2
        exit 2
    fi
    echo
    echo "== run =="
    echo "success looks like: '[OK] Foreshadow correctly derived all 64 bytes!'"
    echo "keep the full output as evidence (CPU model, ucode, hit/miss ratio, #AEX)."
    make -C "$APP" run
else
    echo
    echo "built. Run: sudo make -C $APP run"
fi
