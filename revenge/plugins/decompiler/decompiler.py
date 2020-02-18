
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

        This is really just a light wrapper to lookup and call the correct
        decompiler.
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
        """revenge.plugins.decompiler.DecompilerBase: The underlying implementation.

        This will be guessed automatically based on what decompilers are
        discovered. You can also instantiate your own and assign it directly
        to imp.
        """
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
    def decompile_address(self, address):
        return self.imp.decompile_address(address)

    @common.require_imp()
    def decompile_function(self, address):
        return self.imp.decompile_function(address)

from revenge.plugins.decompiler.base import DecompilerBase

# Docs fixup
Decompiler.__init__.__doc__ = DecompilerBase.__init__.__doc__
Decompiler.__doc__ = Decompiler.__init__.__doc__
Decompiler.decompile_address.__doc__ = DecompilerBase.decompile_address.__doc__
Decompiler.decompile_function.__doc__ = DecompilerBase.decompile_function.__doc__

LOGGER = logging.getLogger(__name__)
