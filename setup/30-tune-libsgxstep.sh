#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
#
# Foreshadow / SGX-Step lab -- tune libsgxstep/config.h for this host.
#
# The defaults in the upstream config.h (4 cores, victim on CPU 1, X2APIC=1,
# timer interval 32) are fine for the Foreshadow PoC, but VICTIM_CPU/NUM_CORES
# must match the actual topology, and X2APIC must stay consistent with the
# kernel command line: X2APIC=1 <-> no 'nox2apic' boot parameter.
#
# The Foreshadow PoC does not depend on a calibrated timer interval (it is
# page-fault driven), unlike app/bench -- leave SGX_STEP_TIMER_INTERVAL alone
# unless you plan to single-step.
#
# Usage:
#   SGXSTEP_DIR=$HOME/sgx-step ./30-tune-libsgxstep.sh            # dry run
#   SGXSTEP_DIR=$HOME/sgx-step ./30-tune-libsgxstep.sh --apply
#
set -uo pipefail

APPLY=0
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=1 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ -z ${SGXSTEP_DIR:-} ]]; then
    for cand in "$HOME/sgx-step" /opt/sgx-step /usr/local/src/sgx-step; do
        [[ -f $cand/libsgxstep/config.h ]] && SGXSTEP_DIR=$cand && break
    done
fi

CONFIG=${SGXSTEP_DIR:-}/libsgxstep/config.h
if [[ ! -f $CONFIG ]]; then
    echo "error: libsgxstep/config.h not found (set SGXSTEP_DIR)" >&2
    exit 2
fi

NCPU=$(nproc)
VICTIM=${VICTIM_CPU:-1}
INTERVAL=${SGX_STEP_TIMER_INTERVAL:-32}

echo "== libsgxstep/config.h =="
echo "  file:  $CONFIG"
echo "  host:  $NCPU CPUs -> NUM_CORES=$NCPU, VICTIM_CPU=$VICTIM"

if ((VICTIM >= NCPU)); then
    echo "  [FAIL] VICTIM_CPU=$VICTIM but only $NCPU CPUs online -- adjust VICTIM_CPU" >&2
    exit 2
fi

if grep -qE '(^| )isolcpus=' /proc/cmdline; then
    echo "  note: $(grep -oE '(^| )isolcpus=[^ ]*' /proc/cmdline)"
else
    echo "  [WARN] no isolcpus on the command line -- the victim core will be preempted"
fi

# Build the sed program.
SED=(
    -E
    -e "s/^#define X2APIC[[:space:]]+[01]/#define X2APIC                     1/"
    -e "s/^#define VICTIM_CPU[[:space:]]+[0-9]+/#define VICTIM_CPU                  $VICTIM/"
    -e "s/^#define NUM_CORES[[:space:]]+[0-9]+/#define NUM_CORES                   $NCPU/"
)

echo
echo "== current values =="
grep -E '^#define (X2APIC|VICTIM_CPU|NUM_CORES|SPY_CPU|SGX_STEP_TIMER_INTERVAL|PSTATE_PCT|USER_IDT_ENABLE)' "$CONFIG" || true

if grep -qE '(^| )nox2apic( |$)' /proc/cmdline; then
    echo
    echo "  [WARN] 'nox2apic' is on the command line: sgx-step expects X2APIC=0 then."
    echo "         Either drop nox2apic (recommended, matches the README) or set X2APIC 0."
fi

if [[ $APPLY -eq 0 ]]; then
    echo
    echo "dry run -- re-run with --apply (a .bak copy is kept)"
    exit 0
fi

cp -a "$CONFIG" "$CONFIG.bak.$(date +%Y%m%d%H%M%S)"
sed -i "${SED[@]}" "$CONFIG"

echo
echo "== new values =="
grep -E '^#define (X2APIC|VICTIM_CPU|NUM_CORES|SPY_CPU|SGX_STEP_TIMER_INTERVAL)' "$CONFIG" || true

echo
echo "note: SGX_STEP_TIMER_INTERVAL is currently ${INTERVAL} (upstream default 32)."
echo "      Only relevant for single-stepping benchmarks (app/bench), not for app/foreshadow."
echo "      Reference intervals per CPU model: sgx-step README, 'Calibrating the single-stepping interval'."
