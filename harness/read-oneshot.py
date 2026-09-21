#!/usr/bin/env python3
import os, sys
p = "/tmp/ssawarm-oneshot.log"
print("ls", oct(os.stat(p).st_mode), os.stat(p).st_uid, os.stat(p).st_size)
keys = ("oracle_lo used", "TRANSIENT-WARM", "[EDBGRD]", "  rax ", "  rcx ",
        "  rdx ", "  rbx ", "  r8 ", "  r9 ", "  r10 ", "  r11 ", "  r12 ",
        "  r13 ", "  r14 ", "  r15 ", "RIP ", "URSP ", "AEX=")
with open(p) as f:
    for line in f:
        if any(k in line for k in keys):
            sys.stdout.write(line)
