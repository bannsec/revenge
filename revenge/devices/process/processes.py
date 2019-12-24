import logging
logger = logging.getLogger(__name__)

class Processes:

    def __init__(self, processes=None):
        """List of process objects.

        Args:
            processes (list, optional): List of processes.

        Examples:
            .. code-block:: python3

                # List the process objects
                list(procs)
        """

        self._processes = processes

    def __len__(self):
        return len(self._processes)

    def __repr__(self):
        return "<Processes " + str(len(self)) + ">"

    def __iter__(self):
        return self._processes.__iter__()

    @property
    def _processes(self):
        return self.__processes

    @_processes.setter
    def _processes(self, processes):
        if processes is None:
            processes = []

        if isinstance(processes, tuple):
            processes = list(processes)

        if not isinstance(processes, list):
            processes = [processes]

        if not all(isinstance(x, Process) for x in processes):
            raise RevengeInvalidArgumentType("Found non-Process object in processes.")

        self.__processes = processes

Processes.__doc__ = Processes.__init__.__doc__

from ...exceptions import *
from .process import Process
