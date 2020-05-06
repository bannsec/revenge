
import logging
import os
from revenge.cpu import contexts
import revenge
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

cpu_snapshot_x64 = {'rip': {'thing': '0x7fc954d349c0', 'next': {'type': 'instruction', 'thing': {'groups': ['branch_relative', 'jump'], 'regsWritten': [], 'regsRead': [], 'operands': [{'type': 'imm', 'value': '140502694078472', 'size': 8}], 'opStr': '0x7fc9552ba808', 'mnemonic': 'jmp', 'size': 5, 'next': '0x7fc954d349c5', 'address': '0x7fc954d349c0'}, 'telescope': True, 'next': None, 'mem_range': None}, 'mem_range': {'base': '0x7fc954d34000', 'size': 4096, 'protection': 'rwx', 'file': {'path': '/lib/x86_64-linux-gnu/libc-2.27.so', 'offset': 524288, 'size': 0}}, 'telescope': True, 'type': 'int'}, 'r15': {'thing': '0x7fc9475f52a0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'r14': {'thing': '0x7fc94c6fbd38', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'r13': {'thing': '0x1', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'r12': {'thing': '0x0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'r11': {'thing': '0x7fc954d349c0', 'next': {'type': 'instruction', 'thing': {'groups': ['branch_relative', 'jump'], 'regsWritten': [], 'regsRead': [], 'operands': [{'type': 'imm', 'value': '140502694078472', 'size': 8}], 'opStr': '0x7fc9552ba808', 'mnemonic': 'jmp', 'size': 5, 'next': '0x7fc954d349c5', 'address': '0x7fc954d349c0'}, 'telescope': True, 'next': None, 'mem_range': None}, 'mem_range': {'base': '0x7fc954d34000', 'size': 4096, 'protection': 'rwx', 'file': {'path': '/lib/x86_64-linux-gnu/libc-2.27.so', 'offset': 524288, 'size': 0}}, 'telescope': True, 'type': 'int'}, 'r10': {'thing': '0x0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'r9': {'thing': '0x205f', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'r8': {'thing': '0x3', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'rdi': {'thing': '0x7fc94770f110', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'rsi': {'thing': '0x2711', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'rbp': {'thing': '0x7fc947ffe300', 'next': {'thing': '0x7', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0x7fc947800000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'rsp': {'thing': '0x7fc947ffe2f8', 'next': {'thing': '0x7fc94e92798d', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0x7fc947800000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'rbx': {'thing': '0x7fc947ffe240', 'next': {'thing': '0x7fc94770f110', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0x7fc947800000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'rdx': {'thing': '0x7fc947ffe2a8', 'next': {'thing': '0x7fc94770f110', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0x7fc947800000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'rcx': {'thing': '0x7fc94e9e1891', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'rax': {'thing': '0x0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'sp': {'thing': '0x7fc947ffe2f8', 'next': {'thing': '0x7fc94e92798d', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0x7fc947800000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'pc': {'thing': '0x7fc954d349c0', 'next': {'type': 'instruction', 'thing': {'groups': ['branch_relative', 'jump'], 'regsWritten': [], 'regsRead': [], 'operands': [{'type': 'imm', 'value': '140502694078472', 'size': 8}], 'opStr': '0x7fc9552ba808', 'mnemonic': 'jmp', 'size': 5, 'next': '0x7fc954d349c5', 'address': '0x7fc954d349c0'}, 'telescope': True, 'next': None, 'mem_range': None}, 'mem_range': {'base': '0x7fc954d34000', 'size': 4096, 'protection': 'rwx', 'file': {'path': '/lib/x86_64-linux-gnu/libc-2.27.so', 'offset': 524288, 'size': 0}}, 'telescope': True, 'type': 'int'}}

cpu_snapshot_x86 = {'eip': {'thing': '0xf7da6b40', 'next': {'type': 'instruction', 'thing': {'groups': ['branch_relative', 'jump'], 'regsWritten': [], 'regsRead': [], 'operands': [{'type': 'imm', 'value': -137132028, 'size': 4}], 'opStr': '0xf7d38804', 'mnemonic': 'jmp', 'size': 5, 'next': '0xf7da6b45', 'address': '0xf7da6b40'}, 'telescope': True, 'next': None, 'mem_range': None}, 'mem_range': {'base': '0xf7da6000', 'size': 4096, 'protection': 'rwx', 'file': {'path': '/lib/i386-linux-gnu/libc-2.27.so', 'offset': 421888, 'size': 0}}, 'telescope': True, 'type': 'int'}, 'edi': {'thing': '0xe', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'esi': {'thing': '0xf42fe9c0', 'next': {'thing': '0xf2f199e0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'ebp': {'thing': '0xf42fe930', 'next': {'thing': '0xf42fe9a8', 'next': {'thing': '0xf42fec18', 'next': {'thing': '0xf42fec48', 'next': {'thing': '0xf42fece8', 'next': {'thing': '0xf42feda8', 'next': {'thing': '0xf42fee88', 'next': {'thing': '0xf42fef18', 'next': {'thing': '0xf42fef48', 'next': {'thing': '0xf42ff058', 'next': {'thing': '0xf42ff098', 'next': {'thing': '0xf42ff0b8', 'next': {'thing': '0xf42ff1b8', 'next': {'thing': '0xf42ff1d8', 'next': {'thing': '0xf42ff1f8', 'next': {'thing': '0xf42ff218', 'next': {'thing': '0xf42ff278', 'next': {'thing': '0xf42ff2d8', 'next': {'thing': '0xf42ff308', 'next': {'thing': '0xf42ff328', 'next': {'thing': '0xf42ff358', 'next': {'thing': '0xf42ff428', 'next': {'thing': '0x0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'esp': {'thing': '0xf42fe91c', 'next': {'thing': '0xf5f70008', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'ebx': {'thing': '0x0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'edx': {'thing': '0xf42fe958', 'next': {'thing': '0xf42fe998', 'next': {'thing': '0xf5f6fa66', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'ecx': {'thing': '0x0', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'eax': {'thing': '0xf7387e70', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'sp': {'thing': '0xf42fe91c', 'next': {'thing': '0xf5f70008', 'next': None, 'mem_range': None, 'telescope': True, 'type': 'int'}, 'mem_range': {'base': '0xf3b00000', 'size': 8388608, 'protection': 'rw-'}, 'telescope': True, 'type': 'int'}, 'pc': {'thing': '0xf7da6b40', 'next': {'type': 'instruction', 'thing': {'groups': ['branch_relative', 'jump'], 'regsWritten': [], 'regsRead': [], 'operands': [{'type': 'imm', 'value': -137132028, 'size': 4}], 'opStr': '0xf7d38804', 'mnemonic': 'jmp', 'size': 5, 'next': '0xf7da6b45', 'address': '0xf7da6b40'}, 'telescope': True, 'next': None, 'mem_range': None}, 'mem_range': {'base': '0xf7da6000', 'size': 4096, 'protection': 'rwx', 'file': {'path': '/lib/i386-linux-gnu/libc-2.27.so', 'offset': 421888, 'size': 0}}, 'telescope': True, 'type': 'int'}}


def test_contexts_amd64():

    basic_one = revenge.Process(os.path.join(bin_location, 'basic_one'),
                                resume=False, verbose=False, load_symbols='basic_one')
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
    assert hash(x64) == hash(x64)

    str(x64)

    #
    # Test Telescoping context
    #

    ctx = revenge.cpu.CPUContext(basic_one, **cpu_snapshot_x64)
    ctx_str = str(ctx)
    assert "0x7fc954d349c0 -> " in ctx_str
    assert "0x7fc9552ba808" in ctx_str
    assert "0x7fc947ffe300 -> 0x7" in ctx_str
    assert isinstance(ctx.pc, types.Telescope)
    assert isinstance(ctx.sp, types.Telescope)
    assert isinstance(ctx.rax, types.Telescope)
    assert isinstance(ctx.rbx, types.Telescope)
    assert isinstance(ctx.rcx, types.Telescope)
    assert isinstance(ctx.rdx, types.Telescope)
    assert isinstance(ctx.rsi, types.Telescope)
    assert isinstance(ctx.rdi, types.Telescope)
    assert isinstance(ctx.rsp, types.Telescope)
    assert isinstance(ctx.rbp, types.Telescope)
    assert isinstance(ctx.r8, types.Telescope)
    assert isinstance(ctx.r9, types.Telescope)
    assert isinstance(ctx.r10, types.Telescope)
    assert isinstance(ctx.r11, types.Telescope)
    assert isinstance(ctx.r12, types.Telescope)
    assert isinstance(ctx.r13, types.Telescope)
    assert isinstance(ctx.r14, types.Telescope)
    assert isinstance(ctx.r15, types.Telescope)

    assert hash(ctx) == hash(ctx)
    assert hash(ctx) != hash(x64)

    basic_one.quit()


def test_contexts_x86():

    basic_one = revenge.Process(os.path.join(bin_location, 'basic_one_ia32'),
                                resume=False, verbose=False, load_symbols='basic_one_ia32')
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

    assert hash(x86) == hash(x86)

    #
    # Test Telescoping context
    #

    ctx = revenge.cpu.CPUContext(basic_one, **cpu_snapshot_x86)
    ctx_str = str(ctx)
    assert "0xf7d38804" in ctx_str
    assert "0xf42fe91c -> 0xf5f70008" in ctx_str
    assert isinstance(ctx.eax, types.Telescope)
    assert isinstance(ctx.ebx, types.Telescope)
    assert isinstance(ctx.ecx, types.Telescope)
    assert isinstance(ctx.edx, types.Telescope)
    assert isinstance(ctx.edi, types.Telescope)
    assert isinstance(ctx.esi, types.Telescope)
    assert isinstance(ctx.esp, types.Telescope)
    assert isinstance(ctx.ebp, types.Telescope)

    assert hash(ctx) == hash(ctx)
    assert hash(ctx) != hash(x86)

    basic_one.quit()
