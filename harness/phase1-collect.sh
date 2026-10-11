#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
# Phase 1 interleaved collect. Only after phase1-oneshot.sh is not 0/12.
#   sudo bash /home/detox/CPU/labs/foreshadow/harness/phase1-collect.sh
# No RAW_LAT. Fresh outdir (do not reuse /tmp/ssawarm-votes-shift).
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "run: sudo bash $0" >&2
    exit 1
fi
DET=/home/detox
APP=$DET/sgx-step/app/foreshadow-ssa-warm
PY=$DET/CPU/labs/foreshadow/harness/warm_vote_stats.py
L=$DET/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu
P=$DET/sgxsdk/psw227/libs/protobuf23/usr/lib/x86_64-linux-gnu
SDK=$DET/sgxsdk/sdk227
OUT=/tmp/ssawarm-votes-dual
if ! grep -q 'DUAL_BASE=2' "$APP/main.c"; then
    echo "FAIL: $APP/main.c has no DUAL_BASE=2" >&2
    exit 1
fi
"$DET/CPU/labs/foreshadow/setup/90-start-lab.sh"
modprobe msr
wrmsr -p1 0x1a4 0xf
echo -n "0x1a4="; rdmsr -p1 0x1a4
unset ORACLE_LO_OFF RAW_LAT_DUMP RAW_LAT_OFF || true
export LD_PRELOAD=$DET/sgx-step/libsgxstep/fixalign.so
export LD_LIBRARY_PATH=$L:$P:$SDK/lib64
export TIMER_INTERVAL=5000
cd "$APP"
echo "collect n=30 votes=24 alt=DUAL_BASE=0,2 out=$OUT"
python3 "$PY" --collect ./app -n 30 --votes 24 \
    --alt-env DUAL_BASE=0,2 \
    --outdir "$OUT"
echo "COLLECT_OK  results in $OUT"
