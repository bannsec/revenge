from .. import Colorer
import logging

logger = logging.getLogger(__name__)
import colorama
colorama.init()

class Technique(object):
    """This is a base mix-in class. To implement a technique, you need to extend this class."""
    TYPES = ("stalk", "replace")
    # This must be defined and must be one of TYPES
    TYPE = None

    def __init__(self, process):
        self._process = process

    def apply(self, threads=None):
        """Applies this technique, optionally to the given threads."""
        raise NotImplementedError("Apply MUST be implemented by the Technique.")

    def remove(self):
        """Removes this technique."""
        raise NotImplementedError("Remove MUST be implemented by the Technique.")

    def _technique_code_range(self, range):
        """Called to inform Technique of known source (non-target binary) range.

        Args:
            range (revenge.memory.memory_range.MemoryRange): Object describing
                the range we expect to be ours.

        This is not required to be implemented. However, for stalking it may
        be beneficial to know when we have wandered into un-interesting (read:
        non-target) code.

        This can be called multiple times, with other MemoryRange objects.
        """
        return        


class Techniques(object):
    def __init__(self, process):
        self._process = process
        # What threads are actively being stalked?
        # TID: trace
        self._active_stalks = {}
        self._techniques = []
        self._enumerate_techniques()


    def _enumerate_techniques(self):

        for (_, name, _) in pkgutil.iter_modules([Path(__file__).parent]):
            imported_module = import_module('.' + name, package=__name__)

            for i in dir(imported_module):
                attribute = getattr(imported_module, i)

                # Strict subclass
                if inspect.isclass(attribute) and issubclass(attribute, Technique) and attribute.__name__ != "Technique":
                    self.append(attribute)
                    setattr(self, attribute.__name__, partial(attribute, self._process))
                    getattr(self, attribute.__name__).__doc__ = attribute.__doc__

    def append(self, item):
        self._techniques.append(item)

    def __repr__(self):
        return "<Techniques {} loaded>".format(len(self))

    def __len__(self):
        return len(self._techniques)
    
    def __iter__(self):
        return self._techniques.__iter__()

    @property
    def _techniques(self):
        """list: The actual list of techniques."""
        return self.__techniques

    @_techniques.setter
    def _techniques(self, tech):
        self.__techniques = tech


import os
from ..exceptions import *
from importlib import import_module
from pathlib import Path
import pkgutil
import inspect
from functools import partial

here = os.path.dirname(os.path.realpath(__file__))

