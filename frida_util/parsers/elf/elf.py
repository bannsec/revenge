
import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored

from ... import types, common

elf_types = {
    0x0: 'NONE',
    0x1: 'REL',
    0x2: 'EXEC',
    0x3: 'DYN',
    0x4: 'CORE',
    0xfe00: 'LOOS',
    0xfeff: 'HIOS',
    0xff00: 'LOPROC',
    0xffff: 'HIPROC',
}

class ELF(object):

    def __init__(self, process, module):
        """Parses the ELF in memory.

        Args:
            process (Process): frida-util Process object
            module (Module): Module object to start parsing at
        """

        self._process = process
        self.module = module
        self.bits = None

        assert self._process.memory[self.module.base:self.module.base+4].bytes == b'\x7fELF', "This does not appear to be an ELF file..."

    @property
    def program_headers(self):
        """Program headers object."""
        return ProgramHeaders(self._process, self)

    @property
    def section_headers(self):
        """Section headers object."""
        return SectionHeaders(self._process, self)

    @property
    def bits(self):
        """int: How many bits is this ELF?"""

        if self.__bits is None:
            self.__bits = 32 if self._process.memory[self.module.base+0x4].int8 == 1 else 64

        return self.__bits

    @bits.setter
    def bits(self, bits):
        self.__bits = bits

    @property
    def entry(self):
        """int: ELF entrypoint. Rebased"""
        ret = self._process.memory[self.module.base+0x18].pointer

        if self.type_str == 'DYN':
            ret = types.Pointer(ret + self.module.base)

        return ret

    @property
    def phoff(self):
        """int: Program header offset."""
        if self.bits == 32:
            ret = self._process.memory[self.module.base+0x1C].pointer
        else:
            ret = self._process.memory[self.module.base+0x20].pointer
            
        return types.Pointer(ret + self.module.base)

    @property
    def phnum(self):
        """int: Number of program headers."""
        if self.bits == 32:
            return self._process.memory[self.module.base+0x2C].uint16
        else:
            return self._process.memory[self.module.base+0x38].uint16

    @property
    def phentsize(self):
        """int: Size of program headers."""
        if self.bits == 32:
            return self._process.memory[self.module.base+0x2A].uint16
        else:
            return self._process.memory[self.module.base+0x36].uint16

    @property
    def flags(self):
        """int: Flags"""
        if self.bits == 32:
            return self._process.memory[self.module.base+0x24].uint32
        else:
            return self._process.memory[self.module.base+0x30].uint32

    @property
    def ehsize(self):
        """int: Size of this header."""
        if self.bits == 32:
            return self._process.memory[self.module.base+0x28].uint16
        else:
            return self._process.memory[self.module.base+0x34].uint16

    @property
    def shentsize(self):
        """int: Size of a section header entry"""
        if self.bits == 32:
            return self._process.memory[self.module.base+0x2e].uint16
        else:
            return self._process.memory[self.module.base+0x3a].uint16

    @property
    def shnum(self):
        """int: Number of section header entries."""
        if self.bits == 32:
            return self._process.memory[self.module.base+0x30].uint16
        else:
            return self._process.memory[self.module.base+0x3c].uint16

    @property
    def shstrndx(self):
        """int: Section header index that contains the section names."""
        if self.bits == 32:
            return self._process.memory[self.module.base+0x32].uint16
        else:
            return self._process.memory[self.module.base+0x3e].uint16

    @property
    def shoff(self):
        """int: Section Header offset"""
        if self.bits == 32:
            ret = self._process.memory[self.module.base+0x20].pointer
        else:
            ret = self._process.memory[self.module.base+0x28].pointer

        return types.Pointer(ret + self.module.base)

    @property
    def type(self):
        """int: Type of this binary."""

        try:
            return self.__type
        except AttributeError:
            self.__type = self._process.memory[self.module.base+0x10].uint16
            return self.__type

    @property
    def type_str(self):
        """str: Type of this binary."""
        return elf_types[self.type]
        

from .program_headers import ProgramHeaders
from .section_headers import SectionHeaders
