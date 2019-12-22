
import logging
logger = logging.getLogger(__name__)

from prettytable import PrettyTable
import binascii
import operator
import struct
import inspect
from termcolor import cprint, colored

from ....memory import Memory

class UnicornMemory(Memory):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._MemoryBytes = MemoryBytes
        self._MemoryFind = MemoryFind
        self._MemoryMap = MemoryMap

        self._memory_raw = {}

from .... import common, types, symbols
from . import MemoryBytes, MemoryMap, MemoryFind
from ....exceptions import *
