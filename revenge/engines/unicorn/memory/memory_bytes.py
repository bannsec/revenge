
import logging
logger = logging.getLogger(__name__)

import json
import time

from ....memory import MemoryBytes

class UnicornMemoryBytes(MemoryBytes):

    @property
    def int8(self):
        try:
            return self._engine.memory._memory_raw[self.address]
        except KeyError:
            return RevengeMemoryReadError("Memory at address {} not initialized.".format(hex(self.address)))

    @int8.setter
    def int8(self, val):
        self._engine.memory._memory_raw[self.address] = val

    @property
    def uint8(self):
        try:
            return self._engine.memory._memory_raw[self.address]
        except KeyError:
            return RevengeMemoryReadError("Memory at address {} not initialized.".format(hex(self.address)))

    @uint8.setter
    def uint8(self, val):
        self._engine.memory._memory_raw[self.address] = val

    """
    @property
    def int16(self):
        pass

    @int16.setter
    def int16(self, val):
        pass

    @property
    def uint16(self):
        pass

    @uint16.setter
    def uint16(self, val):
        pass

    @property
    def int32(self):
        pass

    @int32.setter
    def int32(self, val):
        pass

    @property
    def uint32(self):
        pass

    @uint32.setter
    def uint32(self, val):
        pass

    @property
    def int64(self):
        pass

    @int64.setter
    def int64(self, val):
        pass
    
    @property
    def uint64(self):
        pass

    @uint64.setter
    def uint64(self, val):
        pass

    @property
    def string_ansi(self):
        pass

    @string_ansi.setter
    def string_ansi(self, val):
        pass

    @property
    def string_utf8(self):
        pass

    @string_utf8.setter
    def string_utf8(self, val):
        pass

    @property
    def string_utf16(self):
        pass

    @string_utf16.setter
    def string_utf16(self, val):
        pass

    @property
    def double(self):
        pass

    @double.setter
    def double(self, val):
        pass

    @property
    def float(self):
        pass

    @float.setter
    def float(self, val):
        pass
    
    @property
    def pointer(self):
        pass

    @pointer.setter
    def pointer(self, val):
        pass
    """

    @property
    def replace(self):
        pass

    @replace.setter
    def replace(self, replace):
        pass

from .... import common, types
from ....exceptions import *
from ....cpu.assembly import AssemblyInstruction, AssemblyBlock
from ....native_exception import NativeException
