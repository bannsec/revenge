
import logging
logger = logging.getLogger(__name__)

import json

from .. import common, types
import time

class MemoryFind(object):

    def __init__(self, engine, thing, ranges=None):
        """Find something in memory.

        Args:
            engine: Base engine instantiation
            thing: Some instantiated type to search for from types module
            ranges(list, optional): List of MemoryRange objects to limit the search
                to. By default, search everything.
        """
        self._engine = engine
        self._process = self._engine._process
        self.thing = thing
        self.ranges = ranges

        # Not completed yet
        self.completed = False

        # Memory locations we discovered
        self.found = set()

    def sleep_until_completed(self):
        """This call sleeps and only returns once the search is completed."""

        while not self.completed:
            time.sleep(0.1)

    @common.implement_in_engine()
    def _start(self):
        """Starts the search."""
        pass

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
