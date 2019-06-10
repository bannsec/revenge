

import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

from .. import common, types

class MemoryFind(object):

    def __init__(self, util, thing):
        self._util = util
        self.thing = thing

    @property
    def thing(self):
        """What we're looking for."""
        return self.__thing

    @thing.setter
    def thing(self, thing):
        pass
