#!/usr/bin/env bash
#
# Foreshadow / SGX-Step lab -- build the decisive leak test.
#
# Installs harness/leaktest.c as app/foreshadow-leak/ in the sgx-step tree (the
# app Makefiles build a single main.c, like app/selftest/*) and builds it.
# See labs/foreshadow/README.md section 12 for the experiment design and the
# control matrix, and for how to interpret the outcome.
#
# Usage:
#   SGXSTEP_DIR=$HOME/sgx-step SRC_LEAKTEST=$HOME/CPU/foreshadow/harness/leaktest.c \
#       ./45-build-leaktest.sh
#
set -uo pipefail

SGXSTEP_DIR=${SGXSTEP_DIR:-$HOME/sgx-step}
SRC_LEAKTEST=${SRC_LEAKTEST:-$HOME/CPU/foreshadow/harness/leaktest.c}

[[ -d $SGXSTEP_DIR/libsgxstep ]] || { echo "error: $SGXSTEP_DIR is not an sgx-step tree" >&2; exit 2; }
[[ -f $SRC_LEAKTEST ]] || { echo "error: $SRC_LEAKTEST not found (set SRC_LEAKTEST)" >&2; exit 2; }

APP=$SGXSTEP_DIR/app/foreshadow-leak
mkdir -p "$APP"

# Reuse the selftest Makefile that is known to build in this configuration
# (NO_SGX=1, libsgxstep only) and fix the relative path for the shallower depth.
cp "$SGXSTEP_DIR/app/selftest/idt/Makefile" "$APP/Makefile"
sed -i 's|\.\./\.\./\.\.|../..|g' "$APP/Makefile"
cp "$SRC_LEAKTEST" "$APP/main.c"

echo "== installed into $APP =="
grep -n 'LIBSGXSTEP_DIR\|SOURCES\|OUTPUT' "$APP/Makefile"

echo
echo "== build =="
cd "$APP"
make clean >/dev/null 2>&1
if make 2>&1 | tail -8; then :; fi
ls -l "$APP/app" || { echo "error: build failed" >&2; exit 1; }

cat <<'EOF'

== run matrix ==

  # the interesting case: handler never restores the page, PFN preserved
  sudo HANDLER=skip PFN=keep RELOAD=1 ./app

  # control: no physical address left in the PTE
  sudo HANDLER=skip PFN=zero RELOAD=1 ./app

  # control: secret line pushed out of L1D instead of reloaded
  sudo HANDLER=skip PFN=keep RELOAD=0 ./app

  # reference: old handler behaviour, architectural re-execution possible
  sudo HANDLER=restore PFN=zero RELOAD=1 ./app
EOF
