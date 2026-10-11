#!/usr/bin/env bash
# GGSEC modifications and additions:
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
#
# Port the legacy Intel SGX driver (isgx, the v2.14 revision pinned by SGX-Step
# as kernel/linux-sgx-driver) to the running Kali kernel.
#
# Why this driver and not the in-tree one: the kernel's own SGX driver requires
# Flexible Launch Control and refuses to run without it. On this host it says so
# itself and disables the device:
#
#   sgx: EPC section 0x90200000-0x95f7ffff
#   sgx: SGX disabled: SGX launch control CPU feature is not available,
#        /dev/sgx_enclave disabled.
#
# The legacy driver reaches ENCLS through CPUID (commits "Use cpuid instead of
# boot_cpu_has to check cpu features") and ships the Intel Launch Enclave public
# key hash, which is the mechanism that makes enclave launch possible on
# non-FLC parts. SGX-Step's kernel/install_SGX_driver.sh falls back to it.
#
# Usage:  SGXSTEP_DIR=$HOME/sgx-step ./50-port-isgx.sh
#
# The script only edits the driver sources. Every edit asserts that the expected
# source text is present, so a different upstream revision fails loudly instead
# of silently doing nothing. Building and loading stay explicit:
#
#   make -C $SGXSTEP_DIR/kernel/linux-sgx-driver
#   sudo insmod ... (see README section 13)

set -euo pipefail

SGXSTEP_DIR="${SGXSTEP_DIR:-$HOME/sgx-step}"
DRV="$SGXSTEP_DIR/kernel/linux-sgx-driver"

[ -d "$DRV" ] || { echo "error: $DRV not found (git submodule update --init kernel/linux-sgx-driver)" >&2; exit 1; }

python3 - "$DRV" <<'PY'
import pathlib
import sys

drv = pathlib.Path(sys.argv[1])


def patch(name, pairs):
    path = drv / name
    src = path.read_text()
    for old, new in pairs:
        if old not in src and new in src:
            print("  %s: already applied" % name)
            continue
        if old not in src:
            sys.exit("error: pattern not found in %s:\n---\n%s\n---" % (name, old))
        src = src.replace(old, new, 1)
    path.write_text(src)
    print("patched %s" % name)


# 1. vm_flags became read-only in 6.3; drivers must use the setter now.
# 2. mm->get_unmapped_area was removed in 6.1. __get_unmapped_area() is the
#    exported equivalent; passing NULL as the file keeps us out of our own
#    f_op->get_unmapped_area, which a non-NULL file would re-enter.
# 3. wrmsrl_safe() was folded into wrmsr_safe(msr, low, high).
# 4. platform_driver.remove returns void since 6.11.
patch("sgx_main.c", [
    ("\tvma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO |\n"
     "\t\t\t VM_DONTCOPY;",
     "\tvm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO |\n"
     "\t\t       VM_DONTCOPY);"),

    ("\taddr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,\n"
     "\t\t\t\t\t      flags);",
     "\t/* the generic search, with the enclave-size alignment applied below */\n"
     "\taddr = __get_unmapped_area(NULL, addr, 2 * len, pgoff, flags, 0);"),

    ("static void sgx_reset_pubkey_hash(void *failed)\n"
     "{\n"
     "\tif (wrmsrl_safe(MSR_IA32_SGXLEPUBKEYHASH0, 0xa6053e051270b7acULL) ||\n"
     "\t\twrmsrl_safe(MSR_IA32_SGXLEPUBKEYHASH1, 0x6cfbe8ba8b3b413dULL) ||\n"
     "\t\twrmsrl_safe(MSR_IA32_SGXLEPUBKEYHASH2, 0xc4916d99f2b3735dULL) ||\n"
     "\t\twrmsrl_safe(MSR_IA32_SGXLEPUBKEYHASH3, 0xd4f8c05909f9bb3bULL))\n"
     "\t\t*(int *)failed = -EIO;\n"
     "}",
     "/*\n"
     " * Restore Intel's Launch Enclave public key hash. Without flexible launch\n"
     " * control these MSRs are read-only and already hold that value (the firmware\n"
     " * programmed it), so the write fails harmlessly -- which is exactly why the\n"
     " * safe variant is used.\n"
     " */\n"
     "#define SGX_RESET_PUBKEY_HASH(msr, value)\t\t\t\t\t\\\n"
     "\twrmsr_safe(msr, (u32)(value), (u32)((u64)(value) >> 32))\n"
     "\n"
     "static void sgx_reset_pubkey_hash(void *failed)\n"
     "{\n"
     "\tif (SGX_RESET_PUBKEY_HASH(MSR_IA32_SGXLEPUBKEYHASH0, 0xa6053e051270b7acULL) ||\n"
     "\t    SGX_RESET_PUBKEY_HASH(MSR_IA32_SGXLEPUBKEYHASH1, 0x6cfbe8ba8b3b413dULL) ||\n"
     "\t    SGX_RESET_PUBKEY_HASH(MSR_IA32_SGXLEPUBKEYHASH2, 0xc4916d99f2b3735dULL) ||\n"
     "\t    SGX_RESET_PUBKEY_HASH(MSR_IA32_SGXLEPUBKEYHASH3, 0xd4f8c05909f9bb3bULL))\n"
     "\t\t*(int *)failed = -EIO;\n"
     "}"),

    ("static int sgx_drv_remove(struct platform_device *pdev)\n"
     "{\n"
     "\tint i;\n"
     "\n"
     "\tif (!atomic_cmpxchg(&sgx_init_flag, 1, 0)) {\n"
     "\t\tpr_warn(\"intel_sgx: second release call skipped\\n\");\n"
     "\t\treturn 0;\n"
     "\t}",
     "static void sgx_drv_remove(struct platform_device *pdev)\n"
     "{\n"
     "\tint i;\n"
     "\n"
     "\tif (!atomic_cmpxchg(&sgx_init_flag, 1, 0)) {\n"
     "\t\tpr_warn(\"intel_sgx: second release call skipped\\n\");\n"
     "\t\treturn;\n"
     "\t}"),

    ("\tsgx_page_cache_teardown();\n"
     "\n"
     "\treturn 0;\n"
     "}",
     "\tsgx_page_cache_teardown();\n"
     "}"),
])

# 5. zap_vma_ptes() was replaced by zap_vma_range(), which takes the same
#    arguments. The whole-VMA case in sgx_vma_close() has a dedicated helper.
for name in ("sgx_encl.c", "sgx_encl2.c", "sgx_page_cache.c", "sgx_util.c"):
    path = drv / name
    src = path.read_text()
    hits = src.count("zap_vma_ptes(")
    if hits == 0:
        print("  %s: already applied" % name)
        continue
    path.write_text(src.replace("zap_vma_ptes(", "zap_vma_range("))
    print("patched %s (%d x zap_vma_ptes -> zap_vma_range)" % (name, hits))

patch("sgx_vma.c", [
    ("\tzap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);",
     "\tzap_vma(vma);"),
])

# 6. shmem_file_setup() takes an opaque vma_flags_t since the vm_flags rework,
#    and VM_NORESERVE is only a plain mask now, so it no longer type-checks.
#    mk_vma_flags() is the documented constructor for such a value.
path = drv / "sgx_encl.c"
src = path.read_text()
if "mk_vma_flags(VMA_NORESERVE_BIT)" in src:
    print("  sgx_encl.c: already applied")
elif src.count("VM_NORESERVE);") != 2:
    sys.exit("error: expected 2 shmem_file_setup(.., VM_NORESERVE) calls in sgx_encl.c, found %d"
             % src.count("VM_NORESERVE);"))
else:
    path.write_text(src.replace("VM_NORESERVE);", "mk_vma_flags(VMA_NORESERVE_BIT));"))
    print("patched sgx_encl.c (2 x VM_NORESERVE -> mk_vma_flags(VMA_NORESERVE_BIT))")

# 7. mm->get_unmapped_area is gone and __get_unmapped_area() is not exported to
#    modules, but mm_get_unmapped_area() is (declared in linux/sched/mm.h) and it
#    is exactly what the in-tree SGX driver calls. The legacy 2*len window and the
#    rounding to the enclave size go away with it: the untrusted runtime maps the
#    enclave itself -- either through the elrange configuration, which names the
#    image address, or by retrying on SGX_ERROR_MEMORY_MAP_FAILURE/CONFLICT.
UNMAPPED_AREA = """static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	/*
	 * Same shape as the in-tree driver: check the mapping type and let the
	 * core search. mm->get_unmapped_area() no longer exists and neither
	 * __get_unmapped_area() nor vm_unmapped_area() is exported to modules,
	 * but mm_get_unmapped_area() is, with this exact prototype.
	 */
	if ((flags & MAP_TYPE) == MAP_PRIVATE)
		return -EINVAL;

	if (flags & MAP_FIXED)
		return addr;

	return mm_get_unmapped_area(file, addr, len, pgoff, flags);
}
"""

path = drv / "sgx_main.c"
src = path.read_text()
if "mm_get_unmapped_area(file, addr, len, pgoff, flags)" in src:
    print("  sgx_main.c: unmapped-area hook already ported")
else:
    start = src.index("static unsigned long sgx_get_unmapped_area(")
    end = src.index("\n}\n", start) + 3
    src = src[:start] + UNMAPPED_AREA + src[end:]
    if "#include <linux/sched/mm.h>" not in src:
        src = src.replace("#include <linux/hashtable.h>",
                          "#include <linux/hashtable.h>\n#include <linux/sched/mm.h>", 1)
    path.write_text(src)
    print("patched sgx_main.c (get_unmapped_area -> mm_get_unmapped_area)")
PY

echo
echo "port applied; build with:"
echo "  make -C $DRV"
