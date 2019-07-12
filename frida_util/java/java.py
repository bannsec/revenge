
import logging
logger = logging.getLogger(__name__)

class Java:

    def __init__(self, process):
        """Handles performing Java related activities."""
        self._process = process
    
    def run_script_generic(self, script_name, raw=False, *args, **kwargs):
        """Run the given Java related Frida calls. Simply wraps them in the perform call...

        Calls the Process.run_script_generic as below:
        """

        if not raw:
            script = self._process.load_js(script_name)
        else:
            script = script_name

        # Wrap up the java call
        script = "Java.perform(" + script + ");"
        
        return self._process.run_script_generic(script, raw=True, *args, **kwargs)

    @property
    def android_version(self):
        """str: Returns android version (if applicable)."""
        try:
            return self.__android_version
        except AttributeError:
            self.__android_version = self.run_script_generic("send(Java.androidVersion)", raw=True, unload=True)[0][0]
            return self.__android_version

from ..process import Process

# Fixup docs
Java.run_script_generic.__doc__ += Process.run_script_generic.__doc__
