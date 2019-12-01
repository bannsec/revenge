"""__init__.py"""

import logging
import sys
from .process import Process
from . import symbols
from .native_error import NativeError

LOGGER = logging.getLogger(__name__)

if sys.version_info[0] < 3:
    LOGGER.error('This script is supposed to be run with python3.')
