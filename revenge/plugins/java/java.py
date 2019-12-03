
import logging
logger = logging.getLogger(__name__)

import collections
from ... import common
from .. import Plugin

class Java(Plugin):

    def __init__(self, process):
        """Handles performing Java related activities."""
        self._process = process
        
        # Key = Full path to method that was implemented, Value = str that we implemented with.
        self._implementations = {}

        # Key: class name, vlaue = list of handles to active objects in memory
        self._active_handles = collections.defaultdict(lambda: list())

        # Key: Full class name, value = list of dict of reflected info
        self._cache_reflected_methods = collections.defaultdict(lambda: list())
        self._cache_reflected_fields = collections.defaultdict(lambda: list())

    @property
    @common.implement_in_engine()
    def _is_valid(self):
        """bool: Is this plugin valid for this environment? Used to enable/disable plugins at load time."""
        pass
    
    @common.implement_in_engine()
    def find_active_instance(self, klass, invalidate_cache=False):
        """Look through memory and finds an active instance of the given klass.

        Args:
            klass (str, JavaClass): The class we want to find already in memory.
            invalidate_cache (bool, optional): Throw away any current cache.
                This should normally not be needed.

        Returns:
            Returns JavaClass instance with approrpiate handle server. This
            means you can use the object without instantiating it yourself.

        Example:
            .. code-block:: python3

                MainActivity = p.java.find_active_class("ooo.defcon2019.quals.veryandroidoso.MainActivity")
                MainActivity.parse("test")
        """
        pass

    @property
    def classes(self):
        """JavaClasses: Returns java classes object."""
        return self._JavaClasses(self._process)
