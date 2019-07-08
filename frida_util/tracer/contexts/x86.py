import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored
from prettytable import PrettyTable

from ... import types, common

x64_regs = {
    'sp'  : 'self.esp',
    'bp'  : 'self.ebp',
    'ip'  : 'self.eip',
    'eax' : 'self.eax',
    'ax'  : 'self.eax & 0xffff',
    'al'  : 'self.eax & 0xff',
    'ah'  : '(self.eax>>8) & 0xff',
    'ebx' : 'self.ebx',
    'bx'  : 'self.ebx & 0xffff',
    'bl'  : 'self.ebx & 0xff',
    'bh'  : '(self.ebx>>8) & 0xff',
    'ecx' : 'self.ecx',
    'cx'  : 'self.ecx & 0xffff',
    'cl'  : 'self.ecx & 0xff',
    'ch'  : '(self.ecx>>8) & 0xff',
    'edx' : 'self.edx',
    'dx'  : 'self.edx & 0xffff',
    'dl'  : 'self.edx & 0xff',
    'dh'  : '(self.edx>>8) & 0xff',
    'esi' : 'self.esi',
    'si'  : 'self.esi & 0xffff',
    'sil' : 'self.esi & 0xff',
    'edi' : 'self.edi',
    'di'  : 'self.edi & 0xffff',
    'dil' : 'self.edi & 0xff',
    'ebp' : 'self.ebp',
    'bp'  : 'self.ebp & 0xffff',
    'bpl' : 'self.ebp & 0xff',
    'esp' : 'self.esp',
    'sp'  : 'self.esp & 0xffff',
    'spl' : 'self.esp & 0xff',
    'eip' : 'self.eip',
}

class X86Context(object):

    def __init__(self, process, **registers):
        """Represents a x86 CPU context.

        Example:
            X86Context(process, eax=12, ebx=13, <etc>)
        """

        self._process = process

        # Generically set any registers we're given
        for key, val in registers.items():
            setattr(self, key, common.auto_int(val))

    def __getattr__(self, attr):
        return eval(x64_regs[attr])

    def __str__(self):
        table = PrettyTable(["Register", "Value"])
        main_regs = ['eip', 'esp', 'ebp', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']

        table.align = 'l'

        for reg in main_regs:
            table.add_row([reg, hex(getattr(self, reg))])

        return str(table)
