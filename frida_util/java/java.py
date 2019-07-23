
import logging
logger = logging.getLogger(__name__)

import collections

class Java:

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
    
    def run_script_generic(self, script_name, raw=False, main_thread=False, *args, **kwargs):
        """Run the given Java related Frida calls. Simply wraps them in the perform call...

        Java Specific:
        Args:
            main_thread (bool, optional): Run this on the main Java thread.

        Calls the Process.run_script_generic as below:
        """

        context = kwargs.get("context", None)

        if not raw:
            script = self._process.load_js(script_name)
        else:
            # NOTE: This is meant to transparently convert the java_class and
            # others into the corresponding code. Do not remove str call!
            script = str(script_name)

        # If we're outside a context, do the full setup
        if context is None:
            action = "Java.perform( function () {"
            action_end = "});"

            if main_thread:
                script = "Java.scheduleOnMainThread( function () { " + script + "});"

            # Wrap up the java call
            script = "Java.perform( function () {" + script + "});"

        #kwargs['timeout'] = None

        return self._process.run_script_generic(script, raw=True, *args, **kwargs)

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
            MainActivity = p.java.find_active_class("ooo.defcon2019.quals.veryandroidoso.MainActivity")
            MainActivity.parse("test")
        """

        if isinstance(klass, JavaClass):
            klass_name = klass._name
            
        elif isinstance(klass, str):
            klass_name = klass

        else:
            logger.error("Invalid klass type of {}".format(type(klass)))
            return


        if invalidate_cache:
            self._active_handles[klass_name] = []

        # Attempt to enumerate active handles if we don't know of any.
        if self._active_handles[klass_name] == []:
            self._active_handles[klass_name] = self.run_script_generic("var my_list = []; Java.choose('{}', {{onMatch: function (i) {{my_list.push(i); send(i);}}, onComplete: function () {{send('DONE');}}}})".format(klass_name), raw=True, unload=False,onComplete='DONE')[0]

        # If we can't find any instances
        # TODO: Clean-up script if we don't find anything..
        if self._active_handles[klass_name] == []:
            logger.warn("Couldn't find any active instances of {}!".format(klass_name))
            return

        # Build new instance
        handle = common.auto_int(self._active_handles[klass_name][0]['$handle'])
        klass = JavaClass(self._process, klass_name, handle=handle)
        return klass

    @property
    def classes(self):
        """JavaClasses: Returns java classes object."""
        return JavaClasses(self._process)

    @property
    def BatchContext(self):
        """Returns a BatchContext class for this jvm.

        Example:
            with process.java.BatchContext() as context:
                <stuff>

        BatchContext doc:
        """
        return lambda **kwargs: BatchContext(self._process,
                run_script_generic=self.run_script_generic, 
                handler_pre = "Java.perform(function () {",
                handler_post = "});",
                **kwargs)

from .classes import JavaClasses
from .java_class import JavaClass
from ..process import Process
from ..contexts.batch import BatchContext
from .. import common

# Fixup docs
Java.run_script_generic.__doc__ += Process.run_script_generic.__doc__
Java.BatchContext.__doc__ += BatchContext.__init__.__doc__
