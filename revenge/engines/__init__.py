
import logging
logger = logging.getLogger(__name__)

from ..common import implement_in_engine
import importlib
import pkgutil
import importlib
import functools

class Engine(object):
    """Base for Revenge Engines."""

    def __init__(self, klass, device, *args, **kwargs):

        self.device = device

        Process = importlib.import_module('.process', package=klass.__module__).Process
        self.Process = functools.partial(Process, engine=self)
        functools.update_wrapper(self.Process, BaseProcess)

        self._memory = importlib.import_module('.memory', package=klass.__module__)
        self.memory = self._memory.Memory(self)
        
        #
        # Dynamically populate the plugins from our base mix-in
        #

        self.plugins = importlib.import_module('.plugins', package=klass.__module__)
        for importer, modname, ispkg in pkgutil.iter_modules(self.plugins.__path__):
            if ispkg:
                setattr(self.plugins, modname, importlib.import_module(".plugins." + modname, package=klass.__module__))

    @staticmethod
    def _from_string(engine, *args, **kwargs):
        """Instantitate an engine based on the string name for it.

        Args:
            engine (str): What engine? I.e.: 'frida' or 'unicorn'

        Returns:
            Instantiated Engine object for that engine.
        """

        mod = importlib.import_module('..engines.{engine}'.format(engine=engine), package=__name__)
        return mod.Engine(*args, **kwargs)

    @implement_in_engine()
    def start_session(self):
        """This call is responsible for getting the engine up and running."""
        pass

    def _at_exit(self):
        """Cleanup stuff."""
        return

    @implement_in_engine()
    def resume(self, pid):
        """Resume execution."""
        pass

    @property
    def device(self):
        """revenge.devices.BaseDevice: What device is this process associated with?"""
        return self.__device

    @device.setter
    def device(self, device):
        assert isinstance(device, devices.BaseDevice), "Device must be an instantiation of one of the devices defined in revenge.devices."
        self.__device = device

from ..process import Process as BaseProcess
from .. import devices
