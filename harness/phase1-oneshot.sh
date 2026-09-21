#!/bin/bash
# After a reboot: lab up, prefetchers off, one control shot and one dual-base shot.
#   sudo bash /home/detox/CPU/labs/foreshadow/harness/phase1-oneshot.sh
# Control should look like historical ~10-12/12. Dual is the new path.
# Do not start the 30-run collect until both lines are sane (not 0/12).
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
export WARM_VOTES=24
cd "$APP"
echo "=== DUAL_BASE unset (control) ==="
env -u DUAL_BASE ./app | tee /tmp/ssawarm-dual0.log | grep -E 'oracle_lo used|DUAL_BASE|TRANSIENT-WARM|EDBGRD|AEX='
echo "=== DUAL_BASE=2 (separate AEX, vote iff argmins agree) ==="
DUAL_BASE=2 ./app | tee /tmp/ssawarm-dual2.log | grep -E 'DUAL_BASE|TRANSIENT-WARM|EDBGRD|AEX=|pairs:'
chmod 644 /tmp/ssawarm-dual0.log /tmp/ssawarm-dual2.log || true
echo "ONESHOT_OK  logs /tmp/ssawarm-dual0.log /tmp/ssawarm-dual2.log"
