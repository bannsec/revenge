
import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored

from ... import types, common

segment_types = {
    0: 'PT_NULL',
    1: 'PT_LOAD',
    2: 'PT_DYNAMIC',
    3: 'PT_INTERP',
    4: 'PT_NOTE',
    5: 'PT_SHLIB',
    6: 'PT_PHDR',
}

class ProgramHeader(object):

    def __init__(self, process, elf, address):
        self._process = process
        self._elf = elf
        self.address = address

    def __repr__(self):
        attrs = ['ProgramHeader', self.type_str]
        return '<{}>'.format(' '.join(attrs))

    @property
    def type(self):
        """int: What type of header is this."""
        return self._process.memory[self.address].uint32

    @property
    def type_str(self):
        """str: What type of header is this."""
        try:
            return segment_types[self.type]
        except KeyError:
            return "Unknown"

    @property
    def flags(self):
        """int: Flags for this header."""
        if self._elf.bits == 32:
            return self._process.memory[self.address+0x18].uint32
        else:
            return self._process.memory[self.address+0x4].uint32

    @property
    def vaddr(self):
        """int: Virtual address of the segment in memory."""
        if self._elf.bits == 32:
            return types.Pointer(self._elf.module.base + self._process.memory[self.address+0x8].pointer)
        else:
            return types.Pointer(self._elf.module.base + self._process.memory[self.address+0x10].pointer)

    @property
    def filesz(self):
        """int: Size in bytes of the segment in the file image."""
        if self._elf.bits == 32:
            return self._process.memory[self.address+0x10].uint32
        else:
            return self._process.memory[self.address+0x20].uint64

    @property
    def memsz(self):
        """int: Size in bytes of the segment in memory."""
        if self._elf.bits == 32:
            return self._process.memory[self.address+0x14].uint32
        else:
            return self._process.memory[self.address+0x28].uint64
