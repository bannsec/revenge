
import logging

from prettytable import PrettyTable
from ... import common
from .. import Plugin

class Dwarf(Plugin):
    _MODULE_PLUGIN_REGISTERED = False

    def __init__(self, process, module=None):
        """Lookup Dwarf debugging information from the file.
        
        Examples:
            .. code-block:: python

                dwarf = process.modules['*libc'].dwarf

                # Show all known function names and their address and size
                print(dwarf.functions)

                # Print the first instruction block in main
                print(dwarf.functions['main'].instruction_block)
        """
        self._process = process
        self._module = module

        # Register this in modules
        if not Dwarf._MODULE_PLUGIN_REGISTERED:
            self._process.modules._register_plugin(Dwarf._modules_plugin, "dwarf")
            Dwarf._MODULE_PLUGIN_REGISTERED = True

        if self._dwarffile is not None:
            self.__init_functions()

    def __init_functions(self):

        for CU in self._dwarffile.iter_CUs():
            for DIE in CU.iter_DIEs():
                try:
                    if DIE.tag == 'DW_TAG_subprogram':
                        lowpc = DIE.attributes['DW_AT_low_pc'].value

                        # DWARF v4 in section 2.17 describes how to interpret the
                        # DW_AT_high_pc attribute based on the class of its form.
                        # For class 'address' it's taken as an absolute address
                        # (similarly to DW_AT_low_pc); for class 'constant', it's
                        # an offset from DW_AT_low_pc.
                        highpc_attr = DIE.attributes['DW_AT_high_pc']
                        highpc_attr_class = describe_form_class(highpc_attr.form)
                        if highpc_attr_class == 'address':
                            highpc = highpc_attr.value
                        elif highpc_attr_class == 'constant':
                            highpc = lowpc + highpc_attr.value
                        else:
                            print('Error: invalid DW_AT_high_pc class:',
                                  highpc_attr_class)
                            continue

                        self.functions[DIE.attributes['DW_AT_name'].value] = self._process.memory[self._module.base + lowpc - self.base_address : self._module.base + highpc - self.base_address]
                except KeyError:
                    continue

    @common.validate_argument_types(address=int)
    def lookup_function(self, address):
        """Lookup corresponding function that contains this address.

        Args:
            address (int): Address inside function

        Returns:
            bytes: The name of the function or None if lookup fails.
        """
        return self.functions[address]

    @common.validate_argument_types(address=int)
    def lookup_file_line(self, address):
        """Given the address, try to resolve what the source file name and
        line are

        Args:
            address (int): Address to lookup file line info

        Returns:
            tuple: (filename,line) or None, None if it wasn't found.

        Example:
            .. code-block:: python

                mybin = process.module['mybin']
                filename, line = mybin.dwarf.lookup_file_line(mybin.dwarf.functions[b'main'].address)
        """

        if not self.has_debug_info:
            return

        # Adjust for current base
        address -= self._module.base - self.base_address

        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in self._dwarffile.iter_CUs():
            # First, look at line programs to find the file/line for the address
            lineprog = self._dwarffile.line_program_for_CU(CU)
            prevstate = None
            for entry in lineprog.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = lineprog['file_entry'][prevstate.file - 1].name
                    line = prevstate.line
                    return filename, line

                # This if test was originally above the range check... However
                # it seemed to cause lookup to miss the edge case of the final
                # line in the function. Not sure what other effects moving it
                # down here will have...
                if entry.state.end_sequence:
                    # if the line number sequence ends, clear prevstate.
                    prevstate = None
                    continue
                prevstate = entry.state
        return (None, None)

    @classmethod
    def _modules_plugin(klass, module):
        self = klass(module._process, module)

        # ELF parsing error
        if self._elffile is None:
            return

        # No point in having Dwarf object with no dwarf...
        if not self._elffile.has_dwarf_info():
            return

        return self

    @property
    def _elffile(self):
        try:
            return self.__elffile
        except AttributeError:
            if self._module is None:
                self.__elffile = None
            else:
                try:
                    self.__elffile = ELFFile(common.load_file(self._process, self._module.path))
                except elftools.common.exceptions.ELFError:
                    self.__elffile = None

        return self.__elffile

    @property
    def _dwarffile(self):
        try:
            return self.__dwarffile
        except AttributeError:
            if self._elffile is None:
                self.__dwarffile = None
            else:
                if not self._elffile.has_dwarf_info():
                    self.__dwarffile = None
                else:
                    self.__dwarffile = self._elffile.get_dwarf_info()

        return self.__dwarffile

    @property
    def has_debug_info(self):
        """bool: Does this module actually have debugging info?"""
        try:
            return self.__has_debug_info
        except AttributeError:
            if self._dwarffile is not None:
                self.__has_debug_info = self._dwarffile.has_debug_info
            else:
                self.__has_debug_info = False

        return self.__has_debug_info

    @property
    def _is_valid(self):
        # Not bothering to load this under process
        return False

    @property
    def base_address(self):
        """int: What is the binary's defined base address."""
        return next(x.header["p_vaddr"] for x in self._elffile.iter_segments() if x.header['p_type'] == "PT_LOAD" and x.header["p_offset"] == 0)

    @property
    def functions(self):
        """dict: Dictionary of function_name -> MemoryBytes."""
        try:
            return self.__functions
        except AttributeError:
            self.__functions = Functions(self._process)

        return self.__functions

    ####################
    # Decompiler stuff #
    ####################

    @property
    def decompiler(self):
        """'Decompiler' using dwarf."""
        try:
            return self.__decompiler
        except AttributeError:
            self.__decompiler = DwarfDecompiler(self._process, self)
        return self.__decompiler

    def decompile_address(self, address):
        return self.decompiler.decompile_address(address)

    def decompile_function(self, address):
        return self.decompiler.decompile_function(address)

    def add_source_path(self, path):
        return self.decompiler.add_source_path(path)

from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
import elftools.common.exceptions

import os

from .dwarf_decompiler import DwarfDecompiler, DecompilerBase
from ...functions import Functions

# Doc fixup
Dwarf.__doc__ = Dwarf.__init__.__doc__
#Dwarf._modules_plugin.__doc__ = Dwarf.__init__.__doc__
Dwarf.decompile_address.__doc__ = DecompilerBase.decompile_address.__doc__
Dwarf.add_source_path.__doc__ = DwarfDecompiler.add_source_path.__doc__
