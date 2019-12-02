
import logging
logger = logging.getLogger(__name__)

from .. import common

class Engine(object):
    """Base for Revenge Engines."""

    def __init__(self, process):
        self._process = process

    @common.implement_in_engine()
    def start_session(self):
        """This call is responsible for getting the engine up and running."""
        pass

    def _at_exit(self):
        """Cleanup stuff."""
        return
