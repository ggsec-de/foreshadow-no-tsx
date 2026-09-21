#!/bin/bash
objdump -d /home/detox/sgx-step/app/foreshadow-ssa-warm/app | awk '
/imul/ { p=1; n=0 }
p { print; n++; if (n>12) { print "----"; p=0 } }
' | head -n 80
