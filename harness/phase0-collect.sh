#!/bin/bash
# Phase 0 interleaved A/B collect. Run as root:
#   sudo bash /home/detox/CPU/labs/foreshadow/harness/phase0-collect.sh
# Do NOT use sudo -E; paths are hardcoded because sudo resets $HOME to /root.
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
OUT=/tmp/ssawarm-votes-shift

# unique-string gate on the LIVE binary's source
if ! grep -q ORACLE_LO_OFF "$APP/main.c"; then
    echo "FAIL: $APP/main.c has no ORACLE_LO_OFF -- run phase0-prep.sh first" >&2
    exit 1
fi
if ! python3 "$PY" --help | grep -q alt-env; then
    echo "FAIL: $PY has no --alt-env" >&2
    exit 1
fi

"$DET/CPU/labs/foreshadow/setup/90-start-lab.sh"
modprobe msr
wrmsr -p1 0x1a4 0xf
echo -n "IA32_MISC_ENABLE 0x1a4 = "; rdmsr -p1 0x1a4

export LD_PRELOAD=$DET/sgx-step/libsgxstep/fixalign.so
export LD_LIBRARY_PATH=$L:$P:$SDK/lib64
export TIMER_INTERVAL=5000
cd "$APP"
echo "collect: $APP/app  n=30 votes=24 alt=ORACLE_LO_OFF=0,0x400 out=$OUT (no RAW_LAT)"
# No --raw-lat: the first collect with RAW_LAT on every run collapsed lo-SNR
# to 0/12. One-shot without it recovered 10/12 93/96. Discriminator is
# per-run 12/12 + canary match rates, not the latency dump.
python3 "$PY" --collect ./app -n 30 --votes 24 \
    --alt-env ORACLE_LO_OFF=0,0x400 \
    --outdir "$OUT"
echo "COLLECT_OK  results in $OUT"
