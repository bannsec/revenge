
import logging
from .. import Plugin
from revenge.exceptions import *
from revenge import common

class Decompiler(Plugin):

    def __init__(self, process):
        """Use this to decompile things.

        Examples:
            .. code-block:: python3

                # Attempt to get corresponding source code from address 0x12345
                process.decompiler[0x12345]
        """
        self._process = process

    def _select_decompiler(self):
        # Need to postpone selecting decompiler until all plugins are loaded...
        decomp = self._process.radare2.decompiler

        if decomp is not None:
            self.imp = decomp

        else:
            self.imp = None
            LOGGER.warning("No decompiler discovered. Consider installing radare2 with ghidra (r2pm install r2ghidra-dec)")

    @property
    def imp(self):
        try:
            return self.__imp
        except AttributeError:
            pass

        # Time to check what decompilers we have access to
        self._select_decompiler()

        return self.__imp

    @imp.setter
    def imp(self, imp):
        if imp is not None and not issubclass(type(imp), DecompilerBase):
            raise RevengeInvalidArgumentType("imp must be a subclass of DecompilerBase.")

        self.__imp = imp

    @property
    def _is_valid(self):
        return True

    ###############
    # imp methods #
    ###############

    @common.require_imp()
    def __getitem__(self, item):
        return self.imp.__getitem__(item)

    @common.require_imp()
    def lookup_address(self, address):
        return self.imp.lookup_address(address)

    @common.require_imp()
    def decompile_function(self, address):
        return self.imp.decompile_function(address)

from revenge.plugins.radare2.decompilers import GhidraDecompiler
from revenge.plugins.decompiler.base import DecompilerBase

# Docs fixup
Decompiler.lookup_address.__doc__ = DecompilerBase.lookup_address.__doc__
Decompiler.decompile_function.__doc__ = DecompilerBase.decompile_function.__doc__

LOGGER = logging.getLogger(__name__)
