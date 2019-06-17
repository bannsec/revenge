
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

from termcolor import cprint, colored

from prettytable import PrettyTable

from .. import types, common

class AssemblyInstruction(object):
    """Represents an assembly instruction."""

    def __init__(self, process):

        self._process = process
