import logging
logger = logging.getLogger(__name__)

from ....memory import MemoryRange

class PseudoMemoryRange(MemoryRange):
    pass

from .... import common, types, exceptions
