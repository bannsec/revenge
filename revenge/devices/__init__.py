
import logging
logger = logging.getLogger(__name__)

import frida
import subprocess
import shlex
import os

# Standardize for Frida conventions
uname_standard = {
    "x86_64": "x86_64",
    "i686": "x86",
    "armv7l": "arm",
    "armv6l": "arm",
    "i386": "x86_64",
    "arm64": "arm64"
}

class BaseDevice:
    pass

class LocalDevice(BaseDevice):
    """Connect to whatever this is locally running on.
    
    Args:
        engine (str, optional): What engine to use? Defualt: frida
    """
    def __init__(self):
        self.device = frida.get_local_device()

from ..engines import Engine
from .android import AndroidDevice
