
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import time
from . import common

class MemoryBytes(object):
    """Meta-class used for resolving bytes into something else."""

    def __init__(self, util, address):
        self._util = util
        self.address = address

    def __repr__(self):
        return "<MemoryBytes {}>".format(hex(self.address))

    @property
    def int8(self):
        """Signed 8-bit int"""
        return self._util.run_script_generic("""send(ptr("{}").readS8())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @int8.setter
    def int8(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeS8({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def uint8(self):
        """Unsigned 8-bit int"""
        return self._util.run_script_generic("""send(ptr("{}").readU8())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @uint8.setter
    def uint8(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeU8({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def int16(self):
        """Signed 16-bit int"""
        return self._util.run_script_generic("""send(ptr("{}").readS16())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @int16.setter
    def int16(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeS16({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def uint16(self):
        """Unsigned 16-bit int"""
        return self._util.run_script_generic("""send(ptr("{}").readU16())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @uint16.setter
    def uint16(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeU16({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def int32(self):
        """Signed 32-bit int"""
        return self._util.run_script_generic("""send(ptr("{}").readS32())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @int32.setter
    def int32(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeS32({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def uint32(self):
        """Unsigned 32-bit int"""
        return self._util.run_script_generic("""send(ptr("{}").readU32())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @uint32.setter
    def uint32(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeU32({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def int64(self):
        """Signed 64-bit int"""
        return common.auto_int(self._util.run_script_generic("""send(ptr("{}").readS64())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @int64.setter
    def int64(self, val):
        self._util.run_script_generic("""ptr("{}").writeS64(int64('{}'))""".format(hex(self.address), val), raw=True, unload=True)
    
    @property
    def uint64(self):
        """Unsigned 64-bit int"""
        return common.auto_int(self._util.run_script_generic("""send(ptr("{}").readU64())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @uint64.setter
    def uint64(self, val):
        self._util.run_script_generic("""ptr("{}").writeU64(uint64('{}'))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def string_ansi(self):
        """Read as ANSI string"""
        return self._util.run_script_generic("""send(ptr("{}").readAnsiString())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @string_ansi.setter
    def string_ansi(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeAnsiString(\"{}\"))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def string_utf8(self):
        """Read as utf-8 string"""
        return self._util.run_script_generic("""send(ptr("{}").readUtf8String())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @string_utf8.setter
    def string_utf8(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeUtf8String(\"{}\"))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def string_utf16(self):
        """Read as utf-16 string"""
        return self._util.run_script_generic("""send(ptr("{}").readUtf16String())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @string_utf16.setter
    def string_utf16(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeUtf16String(\"{}\"))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def double(self):
        """Read as double val"""
        return self._util.run_script_generic("""send(ptr("{}").readDouble())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @double.setter
    def double(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeDouble({}))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def float(self):
        """Read as float val"""
        return self._util.run_script_generic("""send(ptr("{}").readFloat())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @float.setter
    def float(self, val):
        self._util.run_script_generic("""send(ptr("{}").writeFloat({}))""".format(hex(self.address), val), raw=True, unload=True)
    
    @property
    def pointer(self):
        """Read as pointer val"""
        return common.auto_int(self._util.run_script_generic("""send(ptr("{}").readPointer())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @pointer.setter
    def pointer(self, val):
        common.auto_int(self._util.run_script_generic("""send(ptr("{}").writePointer(ptr("{}")))""".format(hex(self.address), hex(val)), raw=True, unload=True)[0][0])

    @property
    def breakpoint(self):
        """bool: Does this address have an active breakpoint?"""
        return self.address in self._util.memory._active_breakpoints

    @breakpoint.setter
    def breakpoint(self, val):
        """bool: Set this as a breakpoint or remove the breakpoint."""
        
        assert type(val) is bool, "breakpoint set must be boolean."

        # Remove breakpoint
        if val is False:
            # We're already not a breakpoint
            if not self.breakpoint:
                return

            # Remove breakpoint
            self._util.run_script_generic("""ptr("{}").writeS8(1);""".format(hex(self._util.memory._active_breakpoints[self.address])), raw=True, unload=True)
            self._util.memory._active_breakpoints.pop(self.address)

        # Add breakpoint
        else:
            # Breakpoint already exists
            if self.breakpoint:
                return

            unbreak = int(self._util.run_script_generic('generic_suspend_until_true.js', replace={"FUNCTION_HERE": hex(self.address)})[0][0],16)
            #print('Unsuspend pointer: ' + hex(unbreak))
            self._util.memory._active_breakpoints[self.address] = unbreak


class Memory(object):
    """Class to simplify getting and writing things to memory. Behaves like a list.
    
    Example:
        - memory[0x12345].int8 -> Reads a signed 8-bit int from address
        - memory[0x12345:0x12666] -> Returns byte array from memory
    """

    def __init__(self, util):
        self._util = util

        # Keep track of where we've inserted breakpoints
        # key == address of breakpoint, value == memory location to un-breakpoint it
        self._active_breakpoints = {}

    def __getitem__(self, item):

        if type(item) == str:
            # Assume it's something we need to resolve
            item = self._util._resolve_location_string(item)

        if type(item) == int:
            return MemoryBytes(self._util, item)

        elif type(item) == slice:

            if item.start is None or item.stop is None or item.step is not None:
                logger.error("Memory slices must have start and stop and not contain a step option.")
                return

            return self._util.run_script_generic("""send('array', ptr("{}").readByteArray({}))""".format(hex(item.start), hex(item.stop-item.start)), raw=True, unload=True)[1][0]


        logger.error("Unhandled memory type of {}".format(type(item)))
