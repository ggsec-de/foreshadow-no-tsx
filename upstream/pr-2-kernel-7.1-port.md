# `kernel`: build and load `/dev/sgx-step` on Linux 7.1.x

Two small changes are needed for the out-of-tree module on `7.1.5+kali-amd64`
(GCC 15.2). Both are backwards compatible.

## 1. Missing transitive include for `vmap()` / `vunmap()`

     sgxstep.c:199:9: error: implicit declaration of function 'vunmap'; did you mean 'kunmap'?
     sgxstep.c:338:26: error: implicit declaration of function 'vmap'; did you mean 'kmap'?
     sgxstep.c:338:24: error: assignment to 'void *' from 'int' makes pointer from integer without a cast

7.1.x no longer pulls `<linux/vmalloc.h>` in through the other headers the module
includes, so the prototypes are missing. Fix:

     #include <linux/slab.h>
    +#include <linux/vmalloc.h>

## 2. objtool rejects the magic init/exit names

     sgx-step.o: error: objtool: init_module(): Magic init_module() function name is
                 deprecated, use module_init(fn) instead
     make[4]: *** [scripts/Makefile.build:512: sgx-step.o] Error 255

`init_module()`/`cleanup_module()` are no longer accepted for modules. Fix,
keeping the bodies untouched:

    -int init_module(void)
    +static int __init sgxstep_init(void)

    -void cleanup_module(void)
    +static void __exit sgxstep_exit(void)

    +module_init(sgxstep_init);
    +module_exit(sgxstep_exit);

Note when reviewing: when objtool fails, `make` removes the intermediate object,
so the following `insmod` reports `No such file or directory` -- the same
failure, not a second one.

## Testing

Environment: Intel Core i3-6100, Kali Linux, kernel `7.1.5+kali-amd64`, GCC
15.2.0, boot parameters from the top-level README (`pti=off`,
`clearcpuid=308,295,514`, `isolcpus=1`, `no_timer_check`, `iomem=relaxed`,
`msr.allow_writes=on`, `vdso=0`).

With both changes the module builds cleanly and ships as expected:

      CC [M]  sgxstep.o
      LD [M]  sgx-step.o
      LD [M]  sgx-step.ko
      BTF [M] sgx-step.ko

and `make load` gives

     [sgx-step] listening on /dev/sgx-step
     [sgx-step] original IDT: 0xfffffe0000000000 with size 4096
     [sgx-step] original APIC_LVTT=0x400ec/TDCR=0x0)
     [sgx-step] mapped 2 pinned user ISR memory pages to kernel virtual address 0x...
     [sgx-step] restored IDT: 0xfffffe0000000000 with size 4096
     [sgx-step] restoring APIC timer tsc-deadline operation

`app/selftest/idt` then completes a full run on this kernel:

     [idt.c] installed asm IRQ handler at 10:0x...
     [main.c] returned from software IRQ: my_cpl=3; irq_cpl=0; ...
     [apic.c] APIC timer one-shot mode with division 2 (lvtt=2d/tdcr=0)
     [apic.c] APIC timer tsc-deadline mode (lvtt=4002d/tdcr=0)
     [main.c] all is well; irq_count=60; exiting..

ring-3 and ring-0 interrupt gates, both APIC modes, and a clean restore (the
`Local timer interrupts` counters of all four CPUs keep increasing after the
process exits). The `#warning 5-level page tables currently not supported` is
expected on a kernel built with `CONFIG_PGTABLE_LEVELS=5` and harmless on a CPU
without LA57.

Patch attached: `0001-sgxstep-kernel-7.1.5-port.patch` (one hunk per change).
