
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

from prettytable import PrettyTable
from .. import common


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

        # TODO: Smart guess encoding, linux is usually utf-8, Windows has function call to determine utf-8 vs 16. Mac...?
        
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

from . import MemoryBytes
from . import MemoryRange
