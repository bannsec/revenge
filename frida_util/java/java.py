
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

        if not raw:
            script = self._process.load_js(script_name)
        else:
            # NOTE: This is meant to transparently convert the java_class and
            # others into the corresponding code. Do not remove str call!
            script = str(script_name)

        if main_thread:
            action = "Java.scheduleOnMainThread"
        else:
            action = "Java.perform"

        # Wrap up the java call
        script = action + "(function() {" + script + "});"
        
        return self._process.run_script_generic(script, raw=True, *args, **kwargs)

    @property
    def classes(self):
        """JavaClasses: Returns java classes object."""
        return JavaClasses(self._process)

from .classes import JavaClasses
from ..process import Process

# Fixup docs
Java.run_script_generic.__doc__ += Process.run_script_generic.__doc__
