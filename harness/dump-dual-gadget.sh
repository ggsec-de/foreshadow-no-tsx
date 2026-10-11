#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
objdump -d /home/detox/sgx-step/app/foreshadow-ssa-warm/app | awk '
/imul/ { p=1; n=0 }
p { print; n++; if (n>12) { print "----"; p=0 } }
' | head -n 80
