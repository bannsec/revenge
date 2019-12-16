import logging
logger = logging.getLogger(__name__)

from .... import common, types
from ....memory import MemoryMap

class PseudoMemoryMap(MemoryMap):
    pass

from . import MemoryRange
