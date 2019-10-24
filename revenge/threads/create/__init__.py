
import logging
logger = logging.getLogger(__name__)

def create_thread(process, callback):

    # What type of things do we have to work with?
    try:
        process.memory['pthread_create']
        return create_pthread(process, callback)
    except RevengeSymbolLookupFailure:
        pass

    logger.error("Currently unsupported platform {}".format(process.device_platform))

from .pthread import create_pthread
from ...exceptions import *
