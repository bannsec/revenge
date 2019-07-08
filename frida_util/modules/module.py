
import logging
logger = logging.getLogger(__name__)

from elftools.elf.elffile import ELFFile
from termcolor import cprint, colored
import itertools
import hashlib
import os
import io
import json
from fnmatch import fnmatch
import pefile

from .. import common, types, config

symbol_cache_path = os.path.join(config.app_dirs.user_cache_dir, 'symbol_cache')
os.makedirs(symbol_cache_path, exist_ok=True)

class Module(object):

    def __init__(self, process, name, base, size, path):
        self._process = process
        self.name = name
        self.base = base
        self.size = size

        self.path = path # Must go last

    def _read_symbols_cache_dict(self, f):
        """f == file like object

        Returns either None (if no cache exists) or dict of cache."""

        if f is None:
            return None

        assert isinstance(f, io.IOBase), 'Unhandled symbol cache load type of {}'.format(type(f))

        f.seek(0, 0)
        h = hashlib.sha256(f.read()).hexdigest()
        f.seek(0, 0)

        this_cache_file = os.path.join(symbol_cache_path, h)

        # Cache miss
        if not os.path.isfile(this_cache_file):
            return None

        # Cache hit
        with open(this_cache_file, "r") as f:
            return json.loads(f.read())

    def _load_symbols_cache(self, cache):
        """Loads symbols previously discovered.

        Args:
            cache (dict): Dictionary cache to load up.
        """

        for sym, address in cache.items():
            if self._process.file_type is "PE" or \
                    (self.elf is not None and self.elf.type_str == 'DYN'):
                address = address + self.base

            self._process.modules._symbol_to_address[self.name][sym] = types.Pointer(address)
            self._process.modules._address_to_symbol[address] = sym


    def _save_symbols_cache(self, file_io, cache):
        """Saves symbols into cache to be used later.

        Args:
            file_io (file like): The base file in full.
            cache (dict): The symbols we discovered.
        """

        file_io.seek(0, 0)
        h = hashlib.sha256(file_io.read()).hexdigest()
        file_io.seek(0, 0)

        this_cache_file = os.path.join(symbol_cache_path, h)
        with open(this_cache_file, "w") as f:
            f.write(json.dumps(cache))
        

    def _load_symbols(self):
        """Reads in the file for this module and attempts to extract the symbols."""

        # Either we're loading everything or what we're looking at right now __should__ be loaded
        if self._process._load_symbols is None or any(True for x in self._process._load_symbols if fnmatch(self.name, x)):

            # Clear out old symbols if needed
            self._process.modules._symbol_to_address[self.name] = {}

            file_io = common.load_file(self._process, self.path)
            cache = self._read_symbols_cache_dict(file_io)

            if cache is not None:
                return self._load_symbols_cache(cache)
        
            if self._process.file_type == 'ELF':
                self._load_symbols_elf(file_io)
            
            elif self._process.file_type == "PE":
                self._load_symbols_pe(file_io)

            # TODO: Windows
            # TODO: Mac

        # If we didn't resolve anything, make sure we noted we tried
        if self.name not in self._process.modules._symbol_to_address:
            self._process.modules._symbol_to_address[self.name] = {}

    def _load_symbols_pe(self, pe_io):
        # TODO: Assuming that this process will work on any system running ELF...
        print("Loading symbols for {} ... ".format(self.name), end='', flush=True)

        pe = pefile.PE(data=pe_io.read())
        cache = {}

        # Some PEs don't export anything.
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name in [b'', None]:
                    continue

                name = sym.name.decode()

                rel_address = sym.address
                address = rel_address + self.base

                self._process.modules._symbol_to_address[self.name][name] = types.Pointer(address)
                self._process.modules._address_to_symbol[address] = name
                cache[name] = rel_address

        self._save_symbols_cache(pe_io, cache)
        cprint("[ DONE ]", "green")

    def _load_symbols_elf(self, elf_io):
        # TODO: Assuming that this process will work on any system running ELF...
        print("Loading symbols for {} ... ".format(self.name), end='', flush=True)

        if elf_io is None:
            cprint("[ Failed to load ]", "yellow")
            return

        e = ELFFile(elf_io)

        #
        # Load up any symbols from the file
        #

        symtab = e.get_section_by_name('.symtab')
        dynsym = e.get_section_by_name('.dynsym')

        symbols = []
        cache = {}

        # Sometimes the binary won't have a symbol table
        if symtab is not None:
            symbols.append(symtab.iter_symbols())

        if dynsym is not None:
            symbols.append(dynsym.iter_symbols())

        # Pull out symbols
        for sym in itertools.chain(*symbols):
            if sym.name == '':
                continue

            address = sym['st_value']
            rel_address = address

            if self.elf.type_str == 'DYN':
                address = address + self.base

            self._process.modules._symbol_to_address[self.name][sym.name] = types.Pointer(address)
            self._process.modules._address_to_symbol[address] = sym.name
            cache[sym.name] = rel_address

        self._save_symbols_cache(elf_io, cache)

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

        if self._process.file_type != 'ELF':
            return

        try:
            return self.__elf
        except AttributeError:
            self.__elf = ELF(self._process, self)
            return self.__elf

    @property
    def symbols(self):
        """dict: symbol name -> address for this binary."""
        return self._process.modules._symbol_to_address[self.name]

from ..parsers import ELF
