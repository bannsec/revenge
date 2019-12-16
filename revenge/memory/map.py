import logging
logger = logging.getLogger(__name__)

from .. import common, types

class MemoryMap(object):
    """Small wrapper to simply memory map lookups."""

    def __init__(self, engine):
        self._engine = engine
        self._process = self._engine._process

    def __iter__(self):
        return self._ranges.__iter__()

    def __len__(self):
        return self._ranges.__len__()

    def __repr__(self):
        attrs = ['MemoryMap', str(len(self)), 'mapped ranges']
        return "<{}>".format(' '.join(attrs))

    def __str__(self):
        return str(self._engine.memory)

    def __getitem__(self, item):

        if isinstance(item, int):
            for range in self:
                if item >= range.base and item <= range.base + range.size:
                    return range
            return None

        else:
            logger.error("Unsupported item type of {}".format(type(item)))

from . import MemoryRange
