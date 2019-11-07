
import logging
logger = logging.getLogger(__name__)

import os
import collections
from prettytable import PrettyTable
import datetime
from fnmatch import fnmatch
import time

from .. import common, types

class Modules(object):

    def __init__(self, process):
        self._process = process

        # key == module name, value == dict of symbol->address
        self._symbol_to_address = {}

        # key == address, value == symbol
        self._address_to_symbol = {}

        self.__last_update = datetime.datetime(1970,1,1)

    def lookup_symbol(self, symbol):
        """Generically resolve a symbol.
        
        Examples:
            resolve_symbol(":strlen") -> returns address of strlen resolved globally.
            resolve_symbol("strlen") -> equivalent to above
            resolve_symbol("strlen+0xf") -> strlen offset by 0xf
            resolve_symbol("a.out:main") -> returns address of main resolved to a.out.
            resolve_symbol(0x12345) -> returns symbol at that address.
        
        """

        # Resolve address to symbol
        if isinstance(symbol, int):
            try:
                return self._address_to_symbol[symbol]
            except KeyError:
                return None

        module, offset, symbol = common.parse_location_string(symbol)

        # First try to resolve with local symbol table
        try:
            return self._symbol_to_address[module][symbol]
        except KeyError:
            pass
        
        # Fall back to asking Frida to resolve it

        replace_vars = {
                "FUNCTION_SYMBOL_HERE": symbol,
                "FUNCTION_MODULE_HERE": module,
                "FUNCTION_OFFSET_HERE": offset,
                }

        location_resolved = self._process.run_script_generic("resolve_location_address.js", replace=replace_vars, unload=True)[0]

        if location_resolved == []:
            raise RevengeSymbolLookupFailure("Cannot resolve symbol.")

        return types.Pointer(common.auto_int(location_resolved[0]))

    def load_library(self, library):
        """Dynamically load a library into the program.

        Args:
            library (str): The full path to the library on the process machine

        Returns:
            revenge.modules.Module: RetuRns the new loaded module or None on error.

        Examples:
            .. code-block:: python3

                selinux = process.modules.load_library("/lib/x86_64-linux-gnu/libselinux.so.1")

        This will eventually be implemented across all platforms. For now,
        it only works on linux platforms.
        """

        def load_linux(self, library):

            dlopen = self._process.memory[':dlopen']
            dlopen.argument_types = types.Pointer, types.Int32
            
            if dlopen is None:
                logger.error("Unable to locate dlopen. Cannot dynamically load.")
                return

            # Assuming non-lazy load and exporting symbols for now.
            out = dlopen(library, 0x102)

            # dlopen is reporting an error
            if out == 0:
                return False

            self._flush_cache()
            return self[os.path.basename(library)]


        if not isinstance(library, str):
            error = "library argument must be of type str."
            logger.error(error)
            raise RevengeInvalidArgumentType(error)


        if self._process.device_platform == "linux":
            return load_linux(self, library)

        else:
            logger.error("Not yet supported platform for load_library: {}".format(self._process.device_platform))

    def _flush_cache(self):
        """Make sure the next time we're hit is a full one."""
        self.__last_update = datetime.datetime(1970,1,1)

    def __iter__(self):
        return self.modules.__iter__()

    def __len__(self):
        return len(self.modules)

    def __repr__(self):
        attrs = ['Modules', str(len(self))]
        return "<{}>".format(' '.join(attrs))

    def __str__(self):
        table = PrettyTable(['name', 'base', 'size', 'path'])

        for module in self:
            table.add_row([module.name, hex(module.base), hex(module.size), module.path])

        table.align['path'] = 'l'
        
        return str(table)

    def __getitem__(self, item):

        # Resolve module by it's name
        if isinstance(item, str):
            return next(mod for mod in self if fnmatch(mod.name, item))

        if isinstance(item, types.Telescope):
            item = int(item)

        # Resolve module by the address
        if isinstance(item, int):
            for mod in self:
                if item >= mod.base and item <= mod.base + mod.size:
                    return mod
            return None

        raise NotImplementedError

    @property
    def modules(self):
        """list: Return list of modules."""

        # Time to update the cache
        if datetime.datetime.now() - self.__last_update > datetime.timedelta(seconds=0.5):
            mods = self._process.run_script_generic("""send(Process.enumerateModulesSync());""", raw=True, unload=True)[0][0]
            self.__modules = [Module(self._process, name=mod['name'], base=mod['base'], size=mod['size'], path=mod['path']) for mod in mods]
            self.__last_update = datetime.datetime.now()

        return self.__modules

from .module import Module
from ..exceptions import *
