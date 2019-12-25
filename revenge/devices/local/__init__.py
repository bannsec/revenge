import logging
logger = logging.getLogger(__name__)

from .. import BaseDevice

class LocalDevice(BaseDevice):
    """Connect to whatever this is locally running on.
    
    Args:
        engine (str, optional): What engine to use? Defualt: frida
    """
    def __init__(self, engine=None):
        self._engine = engine or 'frida'

    def Process(self, *args, **kwargs):
        return Engine._from_string(self._engine, device=self).Process(*args, **kwargs)

    def resume(self, pid):
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            raise RevengeInvalidArgumentType("Couldn't find pid to resume.")

        p.resume()

    def suspend(self, pid):
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            raise RevengeInvalidArgumentType("Couldn't find pid to suspend.")

        p.suspend()

    @property
    def platform(self):
        return platform.system().lower()

    @property
    def processes(self):
        procs = []

        for proc in psutil.process_iter():
            procs.append( Process(
                name=proc.name(),
                pid=proc.pid,
                ppid=proc.ppid(),
                ) )

        return Processes(procs)

import frida
import platform
import psutil

from ..process import Process, Processes
from ...engines import Engine
from ...process import Process as ProcessBase

LocalDevice.Process.__doc__ = ProcessBase.__init__.__doc__
