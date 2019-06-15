import logging

logger = logging.getLogger(__name__)

import sys

if sys.version_info[0] < 3:
    logger.error('This script is supposed to be run with python3.')

from .process import Process
