#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
#
# Bring the SGX lab back up after a reboot -- ONE command:
#
#   sudo ./90-start-lab.sh
#
# Run it with sudo as the desktop user. It loads both kernel modules, prepares
# the AESM runtime directory, then drops back to the desktop user to start
# aesm_service with the Launch Enclave and verify the whole chain. Idempotent:
# re-running changes nothing and just re-verifies.
#
# Why each step exists (every one cost a debugging session before this script):
#   * neither kernel module loads automatically, so /dev/isgx and /dev/sgx-step
#     are missing and the enclave loader fails with the misleading
#     "Failed to open Intel SGX device";
#   * /var/run/aesmd lives on tmpfs and is gone after every reboot, so
#     aesm_service exits with "Fail to start service";
#   * aesm_service is started by hand with the Launch Enclave preloaded -- the
#     only way to launch an enclave on a CPU without flexible launch control;
#   * sudo resets $HOME to /root, so all paths are derived from the invoking
#     user's home (via SUDO_USER), never from $HOME. Passing the wrong home is
#     what made an earlier version look for the modules under /root/sgx-step.
set -u

fail() { echo "error: $*" >&2; exit 1; }

# ---- resolve the desktop user and their home independently of $HOME/sudo ----
TARGET_USER="${SUDO_USER:-$(id -un)}"
[ "$TARGET_USER" != "root" ] || fail "run this with sudo AS THE DESKTOP USER (got SUDO_USER=root)"
USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[ -n "$USER_HOME" ] || fail "cannot resolve home directory for $TARGET_USER"

SGXSTEP_DIR="${SGXSTEP_DIR:-$USER_HOME/sgx-step}"
AESM_DIR="${AESM_DIR:-$USER_HOME/sgxsdk/psw227/extract/opt/intel/sgx-aesm-service/aesm}"
PROTOBUF_DIR="${PROTOBUF_DIR:-$USER_HOME/sgxsdk/psw227/libs/protobuf23/usr/lib/x86_64-linux-gnu}"
PSW_LIB_DIR="${PSW_LIB_DIR:-$USER_HOME/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu}"
SDK_DIR="${SDK_DIR:-$USER_HOME/sgxsdk/sdk227}"
FIXALIGN_SO="${FIXALIGN_SO:-$SGXSTEP_DIR/libsgxstep/fixalign.so}"

ISGX_KO="$SGXSTEP_DIR/kernel/linux-sgx-driver/isgx.ko"
STEP_KO="$SGXSTEP_DIR/kernel/sgx-step.ko"

# ================= privileged half (must be root) =================
if [ "$(id -u)" = "0" ]; then
	modprobe msr 2>/dev/null || true

	if ! lsmod | grep -q '^isgx '; then
		[ -f "$ISGX_KO" ] || fail "$ISGX_KO missing (build it first)"
		insmod "$ISGX_KO" || fail "insmod isgx.ko"
		echo "loaded isgx"
	else
		echo "isgx already loaded"
	fi

	if ! lsmod | grep -q '^sgx_step '; then
		[ -f "$STEP_KO" ] || fail "$STEP_KO missing (build it first)"
		insmod "$STEP_KO" || fail "insmod sgx-step.ko"
		echo "loaded sgx_step"
	else
		echo "sgx_step already loaded"
	fi

	mkdir -p /var/run/aesmd /var/opt/aesmd/data
	# aesmd runs as the desktop user here, so it must own both paths
	chown -R "$TARGET_USER" /var/run/aesmd /var/opt/aesmd
	echo "runtime directories ready"

	# ---- drop privileges and run the unprivileged half as the desktop user ----
	echo "--- starting AESM as $TARGET_USER ---"
	exec runuser -u "$TARGET_USER" -- "$0" "$@"
fi

# ================= unprivileged half (desktop user) =================
[ -c /dev/isgx ]        || fail "/dev/isgx missing: run 'sudo $0' first"
[ -c /dev/sgx-step ]    || fail "/dev/sgx-step missing: run 'sudo $0' first"
[ -d /var/run/aesmd ]   || fail "/var/run/aesmd missing: run 'sudo $0' first"
[ -x "$AESM_DIR/aesm_service" ] || fail "$AESM_DIR/aesm_service missing"
[ -f "$FIXALIGN_SO" ]   || fail "$FIXALIGN_SO missing (build: gcc -shared -fPIC -O2 fixalign.c -o fixalign.so)"

if pgrep -x aesm_service > /dev/null; then
	echo "aesmd already running (pid $(pgrep -x aesm_service | head -1))"
else
	echo "starting aesmd with the Launch Enclave and the alignment shim"
	# setsid + </dev/null fully detaches aesmd from this (possibly SSH) session,
	# so it survives the script and the terminal that started it.
	(
		cd "$AESM_DIR" || exit 1
		LD_PRELOAD="$FIXALIGN_SO" \
		LD_LIBRARY_PATH=".:$PROTOBUF_DIR" \
		setsid ./aesm_service --no-daemon --no-syslog \
			< /dev/null > /tmp/aesmd.log 2>&1 &
	)
	for _ in $(seq 60); do
		[ -S /var/run/aesmd/aesm.socket ] && break
		sleep 0.25
	done
fi

[ -S /var/run/aesmd/aesm.socket ] || {
	echo "---- aesmd log ----"
	tail -20 /tmp/aesmd.log 2>/dev/null
	fail "aesmd did not create its socket"
}

echo "aesmd ok (socket $(ls -l /var/run/aesmd/aesm.socket | awk '{print $1}'))"
echo "lab is up: /dev/isgx, /dev/sgx-step and aesmd are all ready"
echo
echo "run the memory-secret PoC with:"
echo "  cd $SGXSTEP_DIR/app/foreshadow && sudo timeout 1800 env \\"
echo "      FORESHADOW_ZERO_RETRIES=48 \\"
echo "      LD_PRELOAD=$FIXALIGN_SO \\"
echo "      LD_LIBRARY_PATH=$PSW_LIB_DIR:$PROTOBUF_DIR:$SDK_DIR/lib64 \\"
echo "      ./app > /tmp/foreshadow-run.log 2>&1; grep -e hit/miss -e rounds -e misses /tmp/foreshadow-run.log | tail -3"
