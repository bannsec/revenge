import logging
logger = logging.getLogger(__name__)

from .... import common, types
from ....memory import MemoryMap

class FridaMemoryMap(MemoryMap):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        ranges = self._process.engine.run_script_generic("""send(Process.enumerateRangesSync(''));""", raw=True, unload=True)[0][0]
        self._ranges = [MemoryRange(self._process, **range) for range in ranges]

from . import MemoryRange
