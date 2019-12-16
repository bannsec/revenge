import logging
logger = logging.getLogger(__name__)

import json
import time

from ....memory import MemoryFind

class FridaMemoryFind(MemoryFind):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Loaded script to unload once we're done
        self._script = None

        self._start()

    def _start(self):

        replace = {
                "SCAN_PATTERN_HERE": self.search_string,
                "SEARCH_SPACE_HERE": json.dumps(self._ranges_js),
                }

        self._engine.run_script_generic("find_in_memory.js", replace=replace, unload=False, on_message=self._on_message)
        self._script = self._engine._scripts.pop(0)

    def _on_message(self, m,d):
        """Catch messages from our search."""
        payload = m['payload']

        if type(payload) is list:
            for addr in payload:
                self.found.add(types.Pointer(common.auto_int(addr['address'])))
        
        elif type(payload) is str and payload == 'DONE':
            self.completed = True

        else:
            logger.error("Unexpected message: {} {}".format(m,d))

    def __del__(self):
        # TODO: Probably don't do this... Register at_exit handler
        # Be sure to unload our script
        if self._script is not None:
            self._script[0].unload()
            self._script = None

    @property
    def completed(self):
        return self.__completed

    @completed.setter
    def completed(self, completed):
        assert type(completed) is bool
        self.__completed = completed

        # Clean up our search script when we're done.
        if completed and self._script is not None:
            self._script[0].unload()
            self._script = None

    @property
    def _ranges_js(self):
        """Returns the ranges as a list for insertion into js."""
        l = []
        for range in self.ranges:
            d = {'base': range.base.js, 'size': range.size}
            l.append(d)

        return l

from .... import common, types
from . import MemoryRange
