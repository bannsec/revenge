"""__init__.py"""

import logging
import sys
from .engines import Engine
from .process import Process as ProcessBase
from . import devices
from revenge.native_error import NativeError

LOGGER = logging.getLogger(__name__)

if sys.version_info[0] < 3:
    LOGGER.error('This script is supposed to be run with python3.')

# Transparently choose Frida engine
def Process(*args, **kwargs): return devices.LocalDevice().Process(*args, **kwargs)
Process.__doc__ = ProcessBase.__doc__
