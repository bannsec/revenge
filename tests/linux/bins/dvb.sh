#!/bin/sh

# Helper for making dvb

gcc -fno-stack-protector -no-pie -m64 -g -o dvb_x86_64_nocanary_nopie_elf dvb.c -Wl,--no-as-needed -ldl
gcc -fno-stack-protector --pie -m64 -g -o dvb_x86_64_nocanary_pie_elf dvb.c -Wl,--no-as-needed -ldl

gcc -fno-stack-protector -no-pie -m32 -g -o dvb_i386_nocanary_nopie_elf dvb.c -Wl,--no-as-needed -ldl
gcc -fno-stack-protector --pie -m32 -g -o dvb_i386_nocanary_pie_elf dvb.c -Wl,--no-as-needed -ldl
