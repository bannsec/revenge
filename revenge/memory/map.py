import logging
logger = logging.getLogger(__name__)

from .. import common, types

class MemoryMap(object):
    """Small wrapper to simply memory map lookups."""

    def __init__(self, process):
        self._process = process

        ranges = self._process.run_script_generic("""send(Process.enumerateRangesSync(''));""", raw=True, unload=True)[0][0]
        self._ranges = [MemoryRange(self._process, **range) for range in ranges]

    def __iter__(self):
        return self._ranges.__iter__()

    def __len__(self):
        return self._ranges.__len__()

    def __repr__(self):
        attrs = ['MemoryMap', str(len(self)), 'mapped ranges']
        return "<{}>".format(' '.join(attrs))

    def __str__(self):
        return str(self._process.memory)

    def __getitem__(self, item):

        if isinstance(item, int):
            for range in self:
                if item >= range.base and item <= range.base + range.size:
                    return range
            return None

        else:
            logger.error("Unsupported item type of {}".format(type(item)))

from . import MemoryRange
