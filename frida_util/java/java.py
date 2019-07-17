
import logging
logger = logging.getLogger(__name__)

class Java:

    def __init__(self, process):
        """Handles performing Java related activities."""
        self._process = process
        
        # Key = Full path to method that was implemented, Value = str that we implemented with.
        self._implementations = {}
    
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
from ..process import Process
from ..contexts.batch import BatchContext

# Fixup docs
Java.run_script_generic.__doc__ += Process.run_script_generic.__doc__
Java.BatchContext.__doc__ += BatchContext.__init__.__doc__
