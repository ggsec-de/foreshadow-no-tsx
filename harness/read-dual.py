#!/usr/bin/env python3
import os, sys
keys = ("oracle_lo used", "DUAL_BASE", "TRANSIENT-WARM", "[EDBGRD]",
        "AEX=", "agree=", "  rax ", "  rcx ", "  rdx ", "  rbx ",
        "  r8 ", "  r9 ", "  r10 ", "  r11 ", "  r12 ", "  r13 ",
        "  r14 ", "  r15 ", "RIP ", "URSP ", "0x1a4")
for p in sys.argv[1:]:
    st = os.stat(p)
    print("====", p, "mode", oct(st.st_mode & 0o777), "bytes", st.st_size)
    with open(p) as f:
        for line in f:
            if any(k in line for k in keys):
                sys.stdout.write(line)
    print()
