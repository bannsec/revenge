
import logging
logger = logging.getLogger(__name__)

from .. import common
import importlib
import pkgutil
import importlib
import functools

class Engine(object):
    """Base for Revenge Engines."""

    def __init__(self, klass):

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
    def _from_string(engine):
        """Instantitate an engine based on the string name for it.

        Args:
            engine (str): What engine? I.e.: 'frida' or 'unicorn'

        Returns:
            Instantiated Engine object for that engine.
        """

        mod = importlib.import_module('..engines.{engine}'.format(engine=engine), package=__name__)
        return mod.Engine()

    @common.implement_in_engine()
    def start_session(self):
        """This call is responsible for getting the engine up and running."""
        pass

    def _at_exit(self):
        """Cleanup stuff."""
        return

from ..process import Process as BaseProcess
