
import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored

from ... import types, common

section_types = {
    0x0: 'SHT_NULL',
    0x1: 'SHT_PROGBITS',
    0x2: 'SHT_SYMTAB',
    0x3: 'SHT_STRTAB',
    0x4: 'SHT_RELA',
    0x5: 'SHT_HASH',
    0x6: 'SHT_DYNAMIC',
    0x7: 'SHT_NOTE',
    0x8: 'SHT_NOBITS',
    0x9: 'SHT_REL',
    0xa: 'SHT_SHLIB',
    0xb: 'SHT_DYNSYM',
    0xe: 'SHT_INIT_ARRAY',
    0xf: 'SHT_FINI_ARRAY',
    0x10: 'SHT_PREINIT_ARRAY',
    0x11: 'SHT_GROUP',
    0x12: 'SHT_SYMTAB_SHNDX',
    0x13: 'SHT_NUM',
}

class SectionHeader(object):

    def __init__(self, process, elf, address):
        self._process = process
        self._elf = elf
        self.address = address

    def __repr__(self):
        attrs = ['SectionHeader', self.type_str]
        return '<{}>'.format(' '.join(attrs))

    @property
    def name(self):
        """int: Index into shstrtab for the name of this section."""
        return self._process.memory[self.address].uint32

    @property
    def type(self):
        """int: Type of this section."""
        return self._process.memory[self.address+4].uint32

    @property
    def type_str(self):
        """str: Type of this section as str."""
        try:
            return section_types[self.type]
        except KeyError:
            return "Unknown"
