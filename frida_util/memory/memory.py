
import logging
logger = logging.getLogger(__name__)

from prettytable import PrettyTable
import binascii
import struct

from .. import common
from .. import types


class Memory(object):
    """Class to simplify getting and writing things to memory. Behaves like a list.
    
    Example:
        - memory[0x12345].int8 -> Reads a signed 8-bit int from address
        - memory[0x12345:0x12666] -> Returns byte array from memory
    """

    def __init__(self, process):
        self._process = process

        # Keep track of where we've inserted breakpoints
        # key == address of breakpoint, value == memory location to un-breakpoint it
        self._active_breakpoints = {}

        # Keep track of what we've allocated.
        # key == address of allocation, value = script where we allocated it.
        # NOTE: It's important to keep the script alive until we're done with the alloc or javascript might gc it.
        self._allocated_memory = {}

        # key == address of replaced function, value = tuple: what it's being replaced with, script so we can unload later
        self._active_replacements = {}


    def alloc(self, size):
        """Allocate size bytes of memory and get a MemoryBytes object back to use it.
    
        Args:
            size (int): How many bytes to allocate.
        """
        
        assert type(size) is int

        pointer = common.auto_int(self._process.run_script_generic("""var p = Memory.alloc(uint64('{}')); send(p);""".format(hex(size)), raw=True, unload=False)[0][0])
        script = self._process._scripts.pop(0) # We want to hold on to it here

        self._allocated_memory[pointer] = script
        return MemoryBytes(self._process, pointer, pointer+size)

    def alloc_string(self, s, encoding='latin-1'):
        """Short-hand to run alloc of appropriate size, then write in the string.
        
        Args:
            s (bytes, str): String to allocate
            encoding (str, optional): How to encode the string if passed in as type str.
        """

        # TODO: Smart guess encoding, linux is usually utf-8, Windows has function call to determine utf-8 vs 16. Mac...?

        if type(s) in [types.StringUTF8, types.StringUTF16]:
            if s.type == 'utf8':
                encoding = 'utf-8'
            elif s.type == 'utf16':
                encoding = 'utf-16'
            else:
                logger.error('How did i get here??')
                return

            s = str(s)
        
        if type(s) is str:
            s = s.encode(encoding)
            if encoding == 'utf-16':
                s = s[2:] # Remove BOM
                s += b'\x00' # Extra null at end of utf-16
        

        if type(s) is not bytes:
            logger.error("Invalid string type of {}".format(type(s)))
            return None
        
        # Null terminate
        s += b'\x00'

        mem = self.alloc(len(s))
        mem.bytes = s
        return mem

    def find(self, *args, **kwargs):
        """Search for thing in memory. Must be one of the defined types."""
        return MemoryFind(self._process, *args, **kwargs)

    def _type_to_search_string(self, thing):
        """Converts the given object into something relevant that can be fed into a memory search query."""

        if not isinstance(thing, types.all_types):
            logger.error("Please use valid type.")
            return None

        endian_str = "<" if self._process.endianness == 'little' else '>'

        if isinstance(thing, types.StringUTF8):
            # Normal string
            return binascii.hexlify(thing.encode('utf-8')).decode()

        elif isinstance(thing, types.StringUTF16):
            # Wide Char String (Windows/UTF16)
            return binascii.hexlify(thing.encode('utf-16')[2:]).decode()

        elif isinstance(thing, types.UInt8):
            return binascii.hexlify(struct.pack(endian_str + "B", thing)).decode()

        elif isinstance(thing, types.Int8):
            return binascii.hexlify(struct.pack(endian_str + "b", thing)).decode()

        elif isinstance(thing, types.UInt16):
            return binascii.hexlify(struct.pack(endian_str + "H", thing)).decode()

        elif isinstance(thing, types.Int16):
            return binascii.hexlify(struct.pack(endian_str + "h", thing)).decode()

        elif isinstance(thing, types.UInt32):
            return binascii.hexlify(struct.pack(endian_str + "I", thing)).decode()

        elif isinstance(thing, types.Int32):
            return binascii.hexlify(struct.pack(endian_str + "i", thing)).decode()

        elif isinstance(thing, types.UInt64):
            return binascii.hexlify(struct.pack(endian_str + "Q", thing)).decode()

        elif isinstance(thing, types.Int64):
            return binascii.hexlify(struct.pack(endian_str + "q", thing)).decode()
        
        else:
            logger.error("Unexpected type to convert of {}".format(type(thing)))
            return None
        

    def __getitem__(self, item):

        if type(item) == str:
            # Assume it's something we need to resolve
            item = self._process._resolve_location_string(item)

        if isinstance(item, int):
            return MemoryBytes(self._process, item)

        elif type(item) == slice:

            if item.start is None or item.stop is None or item.step is not None:
                logger.error("Memory slices must have start and stop and not contain a step option.")
                return

            return MemoryBytes(self._process, item.start, item.stop)

        logger.error("Unhandled memory type of {}".format(type(item)))

    @property
    def maps(self):
        """Return a list of memory ranges that are currently allocated."""
        return MemoryMap(self._process)

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

from . import MemoryBytes
from . import MemoryRange
from . import MemoryFind
from . import MemoryMap

Memory.find.__doc__ = MemoryFind.__init__.__doc__
