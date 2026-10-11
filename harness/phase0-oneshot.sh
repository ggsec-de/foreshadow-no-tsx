#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
# One-shot baseline after a rebuild. No RAW_LAT, no ORACLE_LO_OFF.
#   sudo bash /home/detox/CPU/labs/foreshadow/harness/phase0-oneshot.sh
# Expect historical-ish: [TRANSIENT-WARM] 11/12 (or 12/12), ~80+/96 bytes.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "run: sudo bash $0" >&2
    exit 1
fi
DET=/home/detox
APP=$DET/sgx-step/app/foreshadow-ssa-warm
L=$DET/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu
P=$DET/sgxsdk/psw227/libs/protobuf23/usr/lib/x86_64-linux-gnu
SDK=$DET/sgxsdk/sdk227
"$DET/CPU/labs/foreshadow/setup/90-start-lab.sh"
modprobe msr
wrmsr -p1 0x1a4 0xf
echo -n "0x1a4="; rdmsr -p1 0x1a4
unset ORACLE_LO_OFF RAW_LAT_DUMP RAW_LAT_OFF || true
export LD_PRELOAD=$DET/sgx-step/libsgxstep/fixalign.so
export LD_LIBRARY_PATH=$L:$P:$SDK/lib64
export TIMER_INTERVAL=5000
export WARM_VOTES=24
cd "$APP"
./app | tee /tmp/ssawarm-oneshot.log | grep -E 'oracle_lo used|TRANSIENT-WARM|EDBGRD|r15 |r10 |rax |AEX='
echo "full log: /tmp/ssawarm-oneshot.log"
