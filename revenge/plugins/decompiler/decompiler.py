
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

        # priority: decompiler
        self._decompilers = {}

    @common.validate_argument_types(priority=int)
    def _register_decompiler(self, decompiler, priority):
        """Registers a decompiler to this plugin's stack.

        Args:
            decompiler (revenge.plugins.decompiler.DecompilerBase): The
                decompiler to register
            priority (int): What priority should this decompiler be used?
                0 is lowest 100 is highest

        Note:
            Only register your decompiler if it is valid in the CURRENT INSTANCE
            of revenge. I.e.: Check for needed dependencies prior to registering.

        Registering a decompiler will place it in the list of available
        decompilers.
        """

        if not issubclass(type(decompiler), DecompilerBase):
            raise RevengeInvalidArgumentType("decompiler must be a subclass of DecompilerBase.")

        if priority in self._decompilers:
            raise RevengeDecompilerAlreadyRegisteredError("Cannot register {}. Priority is already in use by: {}".format(decompiler, self._decompilers[priority]))

        self._decompilers[priority] = decompiler


    def _select_decompiler(self):
        # Need to postpone selecting decompiler until all plugins are loaded...

        for priority in sorted(self._decompilers.keys(), reverse=True):
            self.imp = self._decompilers[priority]
            break

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
