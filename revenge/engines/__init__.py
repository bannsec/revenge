
import logging
logger = logging.getLogger(__name__)

from .. import common
import importlib

class Engine(object):
    """Base for Revenge Engines."""

    def __init__(self, process, klass):
        self._process = process
        self.java = importlib.import_module('.java', package=klass.__module__)
        self.memory = importlib.import_module('.memory', package=klass.__module__)

    @common.implement_in_engine()
    def start_session(self):
        """This call is responsible for getting the engine up and running."""
        pass

    def _at_exit(self):
        """Cleanup stuff."""
        return
