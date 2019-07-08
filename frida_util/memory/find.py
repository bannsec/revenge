
import logging
logger = logging.getLogger(__name__)

import json

from .. import common, types
import time

class MemoryFind(object):

    def __init__(self, process, thing, ranges=None):
        """Find something in memory.

        Args:
            process: Base process instantiation
            thing: Some instantiated type to search for from types module
            ranges(list, optional): List of MemoryRange objects to limit the search
                to. By default, search everything.
        """
        self._process = process
        self.thing = thing
        self.ranges = ranges

        # Loaded script to unload once we're done
        self._script = None

        # Not completed yet
        self.completed = False

        # Memory locations we discovered
        self.found = set()

        self._start()

    def sleep_until_completed(self):
        """This call sleeps and only returns once the search is completed."""

        while not self.completed:
            time.sleep(0.1)

    def _start(self):
        """Starts the search."""

        replace = {
                "SCAN_PATTERN_HERE": self.search_string,
                "SEARCH_SPACE_HERE": json.dumps(self._ranges_js),
                }

        self._process.run_script_generic("find_in_memory.js", replace=replace, unload=False, on_message=self._on_message)
        self._script = self._process._scripts.pop(0)

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
        # Be sure to unload our script
        if self._script is not None:
            self._script[0].unload()
            self._script = None

    def __repr__(self):
        attr = ["MemoryFind"]
        attr += ["found", str(len(self.found))]
        
        if self.completed:
            attr.append("completed")
        else:
            attr.append("running")

        return "<{}>".format(' '.join(attr))

    def __iter__(self):
        if not self.completed:
            logger.warning("Search is not completed. Your results may not be full.")

        return (x for x in self.found)

    def __len__(self):
        return len(self.found)

    @property
    def completed(self):
        """bool: Is this search completed?"""
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
    def search_string(self):
        """The search string for this thing."""
        return self._process.memory._type_to_search_string(self.thing)

    @property
    def thing(self):
        """What we're looking for."""
        return self.__thing

    @thing.setter
    def thing(self, thing):
        
        if not isinstance(thing, types.all_types):
            error = "Invalid search thing of type {}".format(type(thing))
            logger.error(error)
            raise Exception(error)

        self.__thing = thing

    @property
    def _ranges_js(self):
        """Returns the ranges as a list for insertion into js."""
        l = []
        for range in self.ranges:
            d = {'base': range.base.js, 'size': range.size}
            l.append(d)

        return l

    @property
    def ranges(self):
        return self.__ranges

    @ranges.setter
    def ranges(self, ranges):
        
        if ranges is None:
            # It appears the first time maps gets run, something in the Frida actually changes... Not sure what.
            # Running this here to prime the pump as it were.. Maybe some day figure out wtf is going on.
            # REMINDER: This bug didn't always hit. So pytest may say it's fine when it isn't.
            self._process.memory.maps
            self._process.memory.maps

            ranges = list(self._process.memory.maps)

        if type(ranges) is MemoryRange:
            self.__ranges = [ranges]

        if type(ranges) not in (list, tuple):
            error = "Invalid range type of {}".format(type(ranges))
            logger.error(error)
            raise Exception(error)

        self.__ranges = ranges

from . import MemoryRange
