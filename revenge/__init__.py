"""__init__.py"""

import logging
import sys
from . import symbols
from .native_error import NativeError
from .engines import Engine
from .process import Process as ProcessBase

LOGGER = logging.getLogger(__name__)

if sys.version_info[0] < 3:
    LOGGER.error('This script is supposed to be run with python3.')

# Transparently choose Frida engine
# DON'T REUSE ENGINE!
def Process(*args, **kwargs): return Engine._from_string('frida').Process(*args, **kwargs)
Process.__doc__ = ProcessBase.__doc__
