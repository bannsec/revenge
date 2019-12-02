
import logging
logger = logging.getLogger(__name__)

from .. import common
import importlib
import pkgutil

class Engine(object):
    """Base for Revenge Engines."""

    def __init__(self, process, klass):
        self._process = process
        self.memory = importlib.import_module('.memory', package=klass.__module__)
        
        #
        # Dynamically populate the plugins from our base mix-in
        #

        self.plugins = importlib.import_module('.plugins', package=klass.__module__)
        for importer, modname, ispkg in pkgutil.iter_modules(self.plugins.__path__):
            if ispkg:
                setattr(self.plugins, modname, importlib.import_module(".plugins." + modname, package=klass.__module__))

    @common.implement_in_engine()
    def start_session(self):
        """This call is responsible for getting the engine up and running."""
        pass

    def _at_exit(self):
        """Cleanup stuff."""
        return
