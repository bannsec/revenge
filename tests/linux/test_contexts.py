
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
from revenge.tracer import contexts
import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

def test_contexts_amd64():

    basic_one = revenge.Process(os.path.join(bin_location, 'basic_one'), resume=False, verbose=False, load_symbols='basic_one')
    t = list(basic_one.threads)[0]
    assert type(t.context) is contexts.X64Context

    x64 = contexts.X64Context(None,
            rax=0x1234567887654321,
            rbx=0x1234567887654321,
            rcx=0x1234567887654321,
            rdx=0x1234567887654321,
            rsi=0x1234567887654321,
            rdi=0x1234567887654321,
            rip=0x1234567887654321,
            rsp=0x1234567887654321,
            rbp=0x1234567887654321,
            r8=0x1234567887654321,
            r9=0x1234567887654321,
            r10=0x1234567887654321,
            r11=0x1234567887654321,
            r12=0x1234567887654321,
            r13=0x1234567887654321,
            r14=0x1234567887654321,
            r15=0x1234567887654321)

    assert x64.rax == 0x1234567887654321
    assert x64.eax == 0x87654321
    assert x64.ax == 0x4321
    assert x64.al == 0x21
    assert x64.ah == 0x43

    assert x64.rbx == 0x1234567887654321
    assert x64.ebx == 0x87654321
    assert x64.bx == 0x4321
    assert x64.bl == 0x21
    assert x64.bh == 0x43

    assert x64.rcx == 0x1234567887654321
    assert x64.ecx == 0x87654321
    assert x64.cx == 0x4321
    assert x64.cl == 0x21
    assert x64.ch == 0x43

    assert x64.rdx == 0x1234567887654321
    assert x64.edx == 0x87654321
    assert x64.dx == 0x4321
    assert x64.dl == 0x21
    assert x64.dh == 0x43

    assert x64.r8 == 0x1234567887654321
    assert x64.r8d == 0x87654321
    assert x64.r8w == 0x4321
    assert x64.r8b == 0x21
    
    assert x64.r9 == 0x1234567887654321
    assert x64.r9d == 0x87654321
    assert x64.r9w == 0x4321
    assert x64.r9b == 0x21

    assert x64.r10 == 0x1234567887654321
    assert x64.r10d == 0x87654321
    assert x64.r10w == 0x4321
    assert x64.r10b == 0x21

    assert x64.r11 == 0x1234567887654321
    assert x64.r11d == 0x87654321
    assert x64.r11w == 0x4321
    assert x64.r11b == 0x21

    assert x64.r12 == 0x1234567887654321
    assert x64.r12d == 0x87654321
    assert x64.r12w == 0x4321
    assert x64.r12b == 0x21

    assert x64.r13 == 0x1234567887654321
    assert x64.r13d == 0x87654321
    assert x64.r13w == 0x4321
    assert x64.r13b == 0x21

    assert x64.r14 == 0x1234567887654321
    assert x64.r14d == 0x87654321
    assert x64.r14w == 0x4321
    assert x64.r14b == 0x21

    assert x64.r15 == 0x1234567887654321
    assert x64.r15d == 0x87654321
    assert x64.r15w == 0x4321
    assert x64.r15b == 0x21

    assert x64.rbp == 0x1234567887654321
    assert x64.ebp == 0x87654321
    assert x64.bp == 0x4321
    assert x64.bpl == 0x21

    assert x64.rsp == 0x1234567887654321
    assert x64.esp == 0x87654321
    assert x64.sp == 0x4321
    assert x64.spl == 0x21

    assert x64.rsi == 0x1234567887654321
    assert x64.esi == 0x87654321
    assert x64.si == 0x4321
    assert x64.sil == 0x21

    assert x64.rdi == 0x1234567887654321
    assert x64.edi == 0x87654321
    assert x64.di == 0x4321
    assert x64.dil == 0x21

    assert x64.rip == 0x1234567887654321

    str(x64)

    basic_one.quit()

def test_contexts_x86():

    basic_one = revenge.Process(os.path.join(bin_location, 'basic_one_ia32'), resume=False, verbose=False, load_symbols='basic_one_ia32')
    t = list(basic_one.threads)[0]
    assert type(t.context) is contexts.X86Context

    x86 = contexts.X86Context(None,
            eax=0x87654321,
            ebx=0x87654321,
            ecx=0x87654321,
            edx=0x87654321,
            esi=0x87654321,
            edi=0x87654321,
            eip=0x87654321,
            esp=0x87654321,
            ebp=0x87654321)

    assert x86.eax == 0x87654321
    assert x86.ax == 0x4321
    assert x86.al == 0x21
    assert x86.ah == 0x43

    assert x86.ebx == 0x87654321
    assert x86.bx == 0x4321
    assert x86.bl == 0x21
    assert x86.bh == 0x43

    assert x86.ecx == 0x87654321
    assert x86.cx == 0x4321
    assert x86.cl == 0x21
    assert x86.ch == 0x43

    assert x86.edx == 0x87654321
    assert x86.dx == 0x4321
    assert x86.dl == 0x21
    assert x86.dh == 0x43

    assert x86.ebp == 0x87654321
    assert x86.bp == 0x4321
    assert x86.bpl == 0x21

    assert x86.esp == 0x87654321
    assert x86.sp == 0x4321
    assert x86.spl == 0x21

    assert x86.esi == 0x87654321
    assert x86.si == 0x4321
    assert x86.sil == 0x21

    assert x86.edi == 0x87654321
    assert x86.di == 0x4321
    assert x86.dil == 0x21

    assert x86.eip == 0x87654321

    str(x86)

    basic_one.quit()
