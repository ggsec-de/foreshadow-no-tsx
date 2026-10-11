#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
# Phase 0 prep on .86: verify scp landed, install into live app, rebuild, selftest.
set -euo pipefail
H=$HOME/CPU/labs/foreshadow/harness
APP=$HOME/sgx-step/app/foreshadow-ssa-warm
SDK=$HOME/sgxsdk/sdk227

echo "=== unique-string gate ==="
c1=$(grep -c ORACLE_LO_OFF "$H/foreshadow-ssa-warm.c")
c2=$(grep -c ORACLE_LO_OFF "$H/selftest-decode.c")
c3=$(grep -c alt-env "$H/warm_vote_stats.py")
echo "ssa-warm ORACLE_LO_OFF=$c1  selftest ORACLE_LO_OFF=$c2  stats alt-env=$c3"
if [ "$c1" -lt 1 ] || [ "$c2" -lt 1 ] || [ "$c3" -lt 1 ]; then
    echo "FAIL: new sources not on disk" >&2
    exit 1
fi
python3 "$H/warm_vote_stats.py" --help | grep -e alt-env -e raw-lat

echo "=== install + rebuild (user, no sudo) ==="
cp "$H/foreshadow-ssa-warm.c" "$APP/main.c"
grep -n ORACLE_LO_OFF "$APP/main.c" | head
make -C "$APP" SGX_SDK="$SDK"

echo "=== offline selftest ==="
gcc -O2 -I"$HOME/sgx-step" "$H/selftest-decode.c" -o "$H/selftest-decode"
echo "--- ORACLE_LO_OFF unset ---"
"$H/selftest-decode" > /tmp/selftest-off0.log
echo "--- ORACLE_LO_OFF=0x400 ---"
ORACLE_LO_OFF=0x400 "$H/selftest-decode" > /tmp/selftest-off400.log

echo "=== banner + scores ==="
grep -E 'offline decoder|group |class 21' /tmp/selftest-off0.log /tmp/selftest-off400.log || true

echo "=== sudo -n probe (collect needs a password if this fails) ==="
if sudo -n true 2>/dev/null; then
    echo "sudo -n: available"
else
    echo "sudo -n: NOT available (collect must be started by you)"
fi
echo "PREP_OK"
