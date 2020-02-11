
import logging
LOGGER = logging.getLogger(__name__)

import collections
from revenge.plugins.handles import Handles as HandlesBase

class Handles(HandlesBase):

    def __init__(self, *args, **kwargs):
        """Manage handles."""
        super().__init__(*args, **kwargs)
