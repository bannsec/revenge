
import logging

from prettytable import PrettyTable
from ... import common
from .. import Plugin

class Handles(Plugin):

    def __init__(self, process):
        """Manage process handles.
        
        Examples:
            .. code-block:: python

                # Grab a specific handle
                handle = process.handles[4]

                # Print out details about handles
                print(process.handles)
        """
        self._process = process

    def values(self):
        return self._handles.values()

    def __len__(self):
        return len(self._handles)

    def __repr__(self):
        return "<Handles " + str(len(self)) + ">"

    def __iter__(self):
        return self._handles.__iter__()

    def __str__(self):
        table = PrettyTable(["handle", "name"])
        table.align = 'l'
        table.border = False
        for handle in self.values():
            table.add_row([hex(handle.handle), handle.name or ""])
        return str(table)

    def __getitem__(self, item):

        if isinstance(item, int):
            return self._handles[item]

        else:
            err = "Unhandled handles item of type " + type(item)
            LOGGER.error(err)
            raise RevengeInvalidArgumentType(err)

    @property
    def _handles(self):
        """dict: {ID: Handle}"""
        if self._process.device.platform == "linux":
            return linux.enumerate_handles(self._process)

        else:
            LOGGER.warning("Handles not yet implemented on platform " + self._process.device.platform + ".")
            return {}

    @property
    def _is_valid(self):
        return True

from . import linux
from ...exceptions import *

Handles.__doc__ = Handles.__init__.__doc__
LOGGER = logging.getLogger(__name__)
