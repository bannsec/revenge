
import logging
logger = logging.getLogger(__name__)

from prettytable import PrettyTable
import binascii
import operator
import struct
import inspect
from termcolor import cprint, colored

from ....memory import Memory

class PseudoMemory(Memory):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._MemoryBytes = MemoryBytes
        self._MemoryFind = MemoryFind
        self._MemoryMap = MemoryMap

from .... import common, types, symbols
from . import MemoryBytes, MemoryMap, MemoryFind
from ....exceptions import *
