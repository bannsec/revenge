import logging
logger = logging.getLogger(__name__)

from . import CPUContextBase

class X86Context(CPUContextBase):

    REGS = ['eip', 'esp', 'ebp', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
    REGS_ALL = {
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

    __slots__ = REGS

