
import logging
LOGGER = logging.getLogger(__name__)

from .. import common

class Plugin(object):
    """Base mix-in for plugins."""

    @property
    @common.implement_in_engine()
    def _is_valid(self):
        """Is the plugin valid for this configuration/should it be loaded?"""
        pass
