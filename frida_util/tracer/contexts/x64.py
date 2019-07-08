import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored
from prettytable import PrettyTable

from ... import types, common

x64_regs = {
    'sp'  : 'self.rsp',
    'bp'  : 'self.rbp',
    'ip'  : 'self.rip',
    'rax' : 'self.rax',
    'eax' : 'self.rax & 0xffffffff',
    'ax'  : 'self.rax & 0xffff',
    'al'  : 'self.rax & 0xff',
    'ah'  : '(self.rax>>8) & 0xff',
    'rbx' : 'self.rbx',
    'ebx' : 'self.rbx & 0xffffffff',
    'bx'  : 'self.rbx & 0xffff',
    'bl'  : 'self.rbx & 0xff',
    'bh'  : '(self.rbx>>8) & 0xff',
    'rcx' : 'self.rcx',
    'ecx' : 'self.rcx & 0xffffffff',
    'cx'  : 'self.rcx & 0xffff',
    'cl'  : 'self.rcx & 0xff',
    'ch'  : '(self.rcx>>8) & 0xff',
    'rdx' : 'self.rdx',
    'edx' : 'self.rdx & 0xffffffff',
    'dx'  : 'self.rdx & 0xffff',
    'dl'  : 'self.rdx & 0xff',
    'dh'  : '(self.rdx>>8) & 0xff',
    'r8'  : 'self.r8',
    'r8d' : 'self.r8 & 0xffffffff',
    'r8w' : 'self.r8 & 0xffff',
    'r8b' : 'self.r8 & 0xff',
    'r9'  : 'self.r9',
    'r9d' : 'self.r9 & 0xffffffff',
    'r9w' : 'self.r9 & 0xffff',
    'r9b' : 'self.r9 & 0xff',
    'r10' : 'self.r10',
    'r10d': 'self.r10 & 0xffffffff',
    'r10w': 'self.r10 & 0xffff',
    'r10b': 'self.r10 & 0xff',
    'r11' : 'self.r11',
    'r11d': 'self.r11 & 0xffffffff',
    'r11w': 'self.r11 & 0xffff',
    'r11b': 'self.r11 & 0xff',
    'r12' : 'self.r12',
    'r12d': 'self.r12 & 0xffffffff',
    'r12w': 'self.r12 & 0xffff',
    'r12b': 'self.r12 & 0xff',
    'r13' : 'self.r13',
    'r13d': 'self.r13 & 0xffffffff',
    'r13w': 'self.r13 & 0xffff',
    'r13b': 'self.r13 & 0xff',
    'r14' : 'self.r14',
    'r14d': 'self.r14 & 0xffffffff',
    'r14w': 'self.r14 & 0xffff',
    'r14b': 'self.r14 & 0xff',
    'r15' : 'self.r15',
    'r15d': 'self.r15 & 0xffffffff',
    'r15w': 'self.r15 & 0xffff',
    'r15b': 'self.r15 & 0xff',
    'rsi' : 'self.rsi',
    'esi' : 'self.rsi & 0xffffffff',
    'si'  : 'self.rsi & 0xffff',
    'sil' : 'self.rsi & 0xff',
    'rdi' : 'self.rdi',
    'edi' : 'self.rdi & 0xffffffff',
    'di'  : 'self.rdi & 0xffff',
    'dil' : 'self.rdi & 0xff',
    'rbp' : 'self.rbp',
    'ebp' : 'self.rbp & 0xffffffff',
    'bp'  : 'self.rbp & 0xffff',
    'bpl' : 'self.rbp & 0xff',
    'rsp' : 'self.rsp',
    'esp' : 'self.rsp & 0xffffffff',
    'sp'  : 'self.rsp & 0xffff',
    'spl' : 'self.rsp & 0xff',
    'rip' : 'self.rip',
}

class X64Context(object):

    def __init__(self, process, **registers):
        """Represents a x86_64 CPU context.

        Example:
            X64Context(process, rax=12, rbx=13, <etc>)
        """

        self._process = process

        # Generically set any registers we're given
        for key, val in registers.items():
            setattr(self, key, common.auto_int(val))

    def __getattr__(self, attr):
        return eval(x64_regs[attr])

    def __str__(self):
        table = PrettyTable(["Register", "Value"])
        main_regs = ['rip', 'rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

        for reg in main_regs:
            table.add_row([reg, hex(getattr(self, reg))])

        return str(table)
