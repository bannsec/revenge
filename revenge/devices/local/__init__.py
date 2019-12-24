
from .. import BaseDevice

class LocalDevice(BaseDevice):
    """Connect to whatever this is locally running on.
    
    Args:
        engine (str, optional): What engine to use? Defualt: frida
    """
    def __init__(self, engine=None):
        self._engine = engine
        self.device = frida.get_local_device()

    @property
    def platform(self):
        return platform.system().lower()

import frida
import platform
