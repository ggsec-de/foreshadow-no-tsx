#!/usr/bin/env bash
#
# Foreshadow / SGX-Step lab -- bound the retry loop in libsgxstep/transient.S.
#
# libsgxstep's transient_access() retries forever while the byte it reads is
# 0x00:
#
#   retry:
#       movb (%rsi), %al
#       shl %cl, %rax
#       jz retry            <-- unbounded
#
# The enclave-free harness re-presents the page in its SIGSEGV handler, so the
# faulting load succeeds on retry and returns the real byte; for a genuine 0x00
# secret byte the shifted value stays zero and the loop spins at 100% CPU
# forever. Bounding it keeps the behaviour identical for non-zero bytes and
# makes a 0x00 byte reach the caller as value 0 instead of hanging the process.
#
# Usage:
#   ./25-patch-libsgxstep.sh            # dry run
#   ./25-patch-libsgxstep.sh --apply
#
set -uo pipefail

APPLY=0
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=1 ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

SGXSTEP_DIR=${SGXSTEP_DIR:-$HOME/sgx-step}
SRC=$SGXSTEP_DIR/libsgxstep/transient.S
[[ -f $SRC ]] || { echo "error: $SRC not found (set SGXSTEP_DIR)" >&2; exit 2; }

if grep -q 'bound the retry loop' "$SRC"; then
    echo "already patched: $SRC"
    exit 0
fi

echo "== current retry block =="
grep -n -A 6 '^retry:' "$SRC"

if [[ $APPLY -eq 0 ]]; then
    echo
    echo "dry run -- re-run with --apply"
    exit 0
fi

python3 - "$SRC" <<'PYEOF'
import pathlib, sys

p = pathlib.Path(sys.argv[1])
s = p.read_text()

old = "retry:\n    movb (%rsi), %al\n    shl %cl, %rax\n    jz retry\n"
new = ("    mov $64, %r8                  # bound the retry loop for 0x00 values\n"
       "retry:\n"
       "    movb (%rsi), %al\n"
       "    shl %cl, %rax\n"
       "    jnz done\n"
       "    dec %r8\n"
       "    jnz retry\n"
       "done:\n")

if s.count(old) != 1:
    sys.exit("error: expected exactly one occurrence of the retry block, found %d"
             % s.count(old))

p.with_suffix(p.suffix + ".bak").write_text(s)
p.write_text(s.replace(old, new))
print("patched", p)
PYEOF

echo
echo "== result =="
sed -n '/transient_access:/,/retq/p' "$SRC"

echo
echo "note: libsgxstep must be rebuilt before the next run:"
echo "  cd $SGXSTEP_DIR/libsgxstep && make clean"
