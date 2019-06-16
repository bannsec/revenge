
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import io
from elftools.elf.elffile import ELFFile
from termcolor import cprint, colored

from .. import common, types

class Module(object):

    def __init__(self, process, name, base, size, path):
        self._process = process
        self.name = name
        self.base = base
        self.size = size

        self.path = path # Must go last

    def _load_symbols(self):
        """Reads in the file for this module and attempts to extract the symbols."""

        # For now, only loading main binary symbols
        if self.name == self._process.file_name:
        
            if self._process.file_type == 'ELF':
                self._load_symbols_elf()

            # TODO: Windows
            # TODO: Mac

        # If we didn't resolve anything, make sure we noted we tried
        if self.name not in self._process.modules._symbol_to_address:
            self._process.modules._symbol_to_address[self.name] = {}

    def _load_symbols_elf(self):
        # TODO: Assuming that this process will work on any system running ELF...
        print("Loading symbols for {} ... ".format(self.name), end='', flush=True)

        fopen = self._process.memory[':fopen']
        fseek = self._process.memory[':fseek']
        ftell = self._process.memory[':ftell']
        fread = self._process.memory[':fread']
        fclose = self._process.memory[':fclose']
        malloc = self._process.memory[':malloc']
        free = self._process.memory[':free']

        fp = fopen(self.path, 'r')

        # If we couldn't open it, fail gracefully
        if fp == 0:
            logger.debug("Couldn't load symbols for file: " + self.path)
            cprint("[ Couldn't open ]", "yellow")
            return

        fseek(fp, 0, 2)
        size = ftell(fp)
        fseek(fp, 0, 0)
        
        malloc_ptr = malloc(size)
        mem = self._process.memory[malloc_ptr:malloc_ptr+size]
        fread(malloc_ptr, size, 1, fp)

        elf_io = io.BytesIO(mem.bytes)
        free(malloc_ptr)
        fclose(fp)

        e = ELFFile(elf_io)
        symtab = e.get_section_by_name('.symtab')

        # Sometimes the binary won't have a symbol table
        if symtab is not None:

            # Clear out old symbols if needed
            self._process.modules._symbol_to_address[self.name] = {}
            
            # Pull out symbols
            for sym in symtab.iter_symbols():
                if sym.name == '':
                    continue

                address = sym['st_value']

                if self.elf.type_str == 'DYN':
                    address = address + self.base

                self._process.modules._symbol_to_address[self.name][sym.name] = types.Pointer(address)
                self._process.modules._address_to_symbol[address] = sym.name

        else:
            logger.debug("No symtab found for {}".format(self.path))

        cprint("[ DONE ]", "green")

    def __repr__(self):
        attrs = ['Module', self.name, '@', hex(self.base)]
        return "<{}>".format(' '.join(attrs))

    def __eq__(self, other):
        return self.name == other.name and self.base == other.base and self.path == other.path and self.size == other.size

    @property
    def name(self):
        """str: Module name."""
        return self.__name

    @name.setter
    def name(self, name):
        if type(name) is not str:
            error = "Name must be string, not {}".format(type(name))
            logger.error(error)
            raise Exception(error)

        self.__name = name

    @property
    def base(self):
        """int: Base address this module is loaded at."""
        return self.__base

    @base.setter
    def base(self, base):

        base = common.auto_int(base)

        if type(base) is int:
            base = types.Pointer(base)

        self.__base = base

    @property
    def path(self):
        """str: Module path."""
        return self.__path

    @path.setter
    def path(self, path):
        if type(path) is not str:
            error = "Path must be string, not {}".format(type(path))
            logger.error(error)
            raise Exception(error)

        self.__path = path

        # Load up the symbols for this file if we haven't already
        if self.name not in self._process.modules._symbol_to_address:
            self._load_symbols()
        
    @property
    def size(self):
        """int: Size of this module."""
        return self.__size

    @size.setter
    def size(self, size):
        self.__size = common.auto_int(size)

    @property
    def elf(self):
        """Returns ELF object, if applicable, otherwise None."""
        if self._process.file_type == 'ELF':
            return ELF(self._process, self)

    @property
    def symbols(self):
        """dict: symbol name -> address for this binary."""
        return self._process.modules._symbol_to_address[self.name]

from ..parsers import ELF
