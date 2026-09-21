#!/bin/bash
set -euo pipefail
A0=/tmp/ssawarm-votes-shift/ORACLE_LO_OFF=0
A4=/tmp/ssawarm-votes-shift/ORACLE_LO_OFF=0x400
echo "=== headers arm0 run01 ==="
sed -n '1,16p' "$A0/run01.votes"
echo "=== E/D rax r10 r15 arm0 ==="
grep -E '^[ED] (0|7|80|87|120|127) ' "$A0/run01.votes"
echo "=== L 120 arm0 ==="
grep -E '^L 120 ' "$A0/run01.votes"
echo "=== L 80 arm0 ==="
grep -E '^L 80 ' "$A0/run01.votes"
echo "=== log arm0 run01 ==="
grep -E 'TRANSIENT-WARM|oracle_lo used|AEX=|\[EDBGRD\]|r15 |r10 |rax |CANARY|faults' "$A0/run01.log" | sed -n '1,50p'
echo "=== log arm400 run01 ==="
grep -E 'TRANSIENT-WARM|oracle_lo used|AEX=|\[EDBGRD\]|r15 |r10 |rax |CANARY|faults' "$A4/run01.log" | sed -n '1,50p'
echo "=== rawlat meta arm0 ==="
sed -n '1,12p' "$A0/run01.rawlat"
echo "=== rawlat R120-0 and R80-0 arm0 ==="
grep -E '^R 120 0 ' "$A0/run01.rawlat"
grep -E '^R 80 0 ' "$A0/run01.rawlat"
echo "=== old dumps ==="
ls /tmp/ssawarm-votes 2>/dev/null | sed -n '1,5p' || true
ls /tmp/ssawarm-votes/*.votes 2>/dev/null | sed -n '1,3p' || true
