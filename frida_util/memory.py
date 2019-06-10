
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import time
from . import common

from prettytable import PrettyTable
import json

class MemoryBytes(object):
    """Meta-class used for resolving bytes into something else."""

    def __init__(self, util, address, address_stop=None):
        """Abstracting what memory location is.

        Args:
            util: Util object
            address (int): Starting address of the memory location.
            address_stop (int, optional): Optional stopping memory location.
        """
        self._util = util
        self.address = address
        self.address_stop = address_stop

    def free(self):
        """bool: Free this memory location. This is only valid if this memory location has been allocated by us."""

        # Make sure we allocated it
        if self.address not in self._util.memory._allocated_memory:
            logger.error("Can't free this memory as we didn't allocate it.")
            return False

        # Free it implicitly by freeing our script
        script = self._util.memory._allocated_memory.pop(self.address)
        script[0].unload()
        return True

    def __repr__(self):
        attrs = ['MemoryBytes', hex(self.address)]

        if self.size is not None:
            attrs.append(str(self.size) + ' bytes')

        return "<{}>".format(' '.join(attrs))

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


    @property
    def bytes(self):
        """bytes: Return this as raw bytes."""
        if self.address_stop is None:
            length = 1 # Default to 1 byte
        else:
            length = self.address_stop - self.address

        return self._util.run_script_generic("""send('array', ptr("{}").readByteArray({}))""".format(hex(self.address), hex(length)), raw=True, unload=True)[1][0]

    @bytes.setter
    def bytes(self, b):
        if type(b) is str:
            logger.warning("Implicitly converting str to bytes.")
            b = b.encode('latin-1')

        if type(b) is not bytes:
            logger.error("Must use type 'bytes' when writing as bytes.")
            return

        # If we know our size, check that we're not overwriting
        if self.size is not None and len(b) > self.size:
            logger.warning("Writing more bytes than it appears is allocated.")

        self._util.run_script_generic("""ptr("{}").writeByteArray({});""".format(
            hex(self.address),
            json.dumps(list(b)),
            ), raw=True, unload=True)

    @property
    def size(self):
        """int: Size of this MemoryBytes. Only valid if it was generated as a slice, alloc or something else that has known size."""
        if self.address_stop is None:
            return None

        return self.address_stop - self.address


class MemoryRange(object):

    def __init__(self, util, base, size, protection, file=None):
        self._util = util
        self.base = base
        self.size = size
        self.protection = protection
        self._file = file

    def __repr__(self):
        value = ["MemoryRange", hex(self.base), '-', hex(self.base+self.size), self.protection]
        return '<' + ' '.join(value) + '>'


    @property
    def file(self):
        """str: File backing this memory range, or None."""
        if self._file is None:
            return None

        return self._file['path']

    @property
    def file_offset(self):
        """str: Offset into backing file or None."""
        if self._file is None:
            return None

        return self._file['offset']

    @property
    def readable(self):
        """bool: Is this range readable?"""
        return self.protection[0] == 'r'

    @property
    def writable(self):
        """bool: Is this range writable?"""
        return self.protection[1] == 'w'

    @property
    def executable(self):
        """bool: Is this range executable?"""
        return self.protection[2] == 'x'

    @property
    def protection(self):
        """str: Protection for this range."""
        return self.__protection

    @protection.setter
    def protection(self, protection):
        assert type(protection) is str
        assert len(protection) == 3
        self.__protection = protection.lower()

    @property
    def size(self):
        """int: Size for this range."""
        return self.__size

    @size.setter
    def size(self, size):
        self.__size = common.auto_int(size)

    @property
    def base(self):
        """int: Base address for this range."""
        return self.__base

    @base.setter
    def base(self, base):
        self.__base = common.auto_int(base)



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

        # Keep track of what we've allocated.
        # key == address of allocation, value = script where we allocated it.
        # NOTE: It's important to keep the script alive until we're done with the alloc or javascript might gc it.
        self._allocated_memory = {}

    def alloc(self, size):
        """Allocate size bytes of memory and get a MemoryBytes object back to use it.
    
        Args:
            size (int): How many bytes to allocate.
        """
        
        assert type(size) is int

        pointer = common.auto_int(self._util.run_script_generic("""var p = Memory.alloc(uint64('{}')); send(p);""".format(hex(size)), raw=True, unload=False)[0][0])
        script = self._util._scripts.pop(0) # We want to hold on to it here

        self._allocated_memory[pointer] = script
        return MemoryBytes(self._util, pointer, pointer+size)

    def alloc_string(self, s, encoding='latin-1'):
        """Short-hand to run alloc of appropriate size, then write in the string.
        
        Args:
            s (bytes, str): String to allocate
            encoding (str, optional): How to encode the string if passed in as type str.
        """
        
        if type(s) is str:
            s = s.encode(encoding)
            if encoding == 'utf-16':
                s = s[2:] # Remove BOM

        if type(s) is not bytes:
            logger.error("Invalid string type of {}".format(type(s)))
            return None
        
        # Null terminate
        s = s + b'\x00'

        mem = self.alloc(len(s))
        mem.bytes = s
        return mem

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

            return MemoryBytes(self._util, item.start, item.stop)

        logger.error("Unhandled memory type of {}".format(type(item)))

    @property
    def maps(self):
        """Return a list of memory ranges that are currently allocated."""
        ranges = self._util.run_script_generic("""send(Process.enumerateRangesSync(''));""", raw=True, unload=True)[0][0]
        return [MemoryRange(self._util, **range) for range in ranges]

    def __str__(self):
        
        table = PrettyTable(['range', 'prot', 'file'])
        table.header = False
        table.align = 'l'
        table.border = False

        for range in self.maps:
            table.add_row([
                hex(range.base)[2:] + '-' + hex(range.base+range.size)[2:],
                range.protection,
                range.file or '',
                ])

        return str(table)
