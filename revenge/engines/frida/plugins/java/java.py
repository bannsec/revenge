
import logging
LOGGER = logging.getLogger(__name__)

import collections
from .....plugins.java import Java

class FridaJava(Java):

    def __init__(self, *args, **kwargs):
        """Handles performing Java related activities."""
        super().__init__(*args, **kwargs)

        self._JavaClasses = JavaClasses
    
    def run_script_generic(self, script_name, raw=False, main_thread=False, *args, **kwargs):
        """Run the given Java related Frida calls. Simply wraps them in the perform call...

        Java Specific:
        Args:
            main_thread (bool, optional): Run this on the main Java thread.

        Calls the Process.engine.run_script_generic as below:
        """

        context = kwargs.get("context", None)

        if not raw:
            script = self._process.engine.load_js(script_name)
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

        return self._process.engine.run_script_generic(script, raw=True, *args, **kwargs)

    def find_active_instance(self, klass, invalidate_cache=False):

        if isinstance(klass, JavaClass):
            klass_name = klass._name
            
        elif isinstance(klass, str):
            klass_name = klass

        else:
            LOGGER.error("Invalid klass type of {}".format(type(klass)))
            return

        if invalidate_cache:
            self._active_handles[klass_name] = []

        # Attempt to enumerate active handles if we don't know of any.
        if self._active_handles[klass_name] == []:
            self._active_handles[klass_name] = self.run_script_generic("var my_list = []; Java.choose('{}', {{onMatch: function (i) {{my_list.push(i); send(i.$h);}}, onComplete: function () {{send('DONE');}}}})".format(klass_name), raw=True, unload=False,onComplete='DONE')[0]

        # If we can't find any instances
        # TODO: Clean-up script if we don't find anything..
        if self._active_handles[klass_name] == []:
            LOGGER.warn("Couldn't find any active instances of {}!".format(klass_name))
            return

        # Build new instance
        handle = common.auto_int(self._active_handles[klass_name][0])
        klass = JavaClass(self._process, klass_name, handle=handle)
        return klass

    @property
    def _is_valid(self):
        try:
            return self.__is_valid
        except AttributeError:
            self.__is_valid = self._process.engine.run_script_generic(r"""send(Java.available)""", raw=True, unload=True)[0][0]
            return self.__is_valid

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

from .classes import FridaJavaClasses as JavaClasses
from .java_class import FridaJavaClass as JavaClass
from .....engines.frida import FridaEngine
from .....contexts.batch import BatchContext
from ..... import common

# Fixup docs
FridaJava.run_script_generic.__doc__ += FridaEngine.run_script_generic.__doc__
FridaJava.BatchContext.__doc__ += BatchContext.__init__.__doc__
