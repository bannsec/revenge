
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

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
        return self._util.run_script_generic("""send(ptr({}).readS8())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def uint8(self):
        """Unsigned 8-bit int"""
        return self._util.run_script_generic("""send(ptr({}).readU8())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def int16(self):
        """Signed 16-bit int"""
        return self._util.run_script_generic("""send(ptr({}).readS16())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def uint16(self):
        """Unsigned 16-bit int"""
        return self._util.run_script_generic("""send(ptr({}).readU16())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def int32(self):
        """Signed 32-bit int"""
        return self._util.run_script_generic("""send(ptr({}).readS32())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def uint32(self):
        """Unsigned 32-bit int"""
        return self._util.run_script_generic("""send(ptr({}).readU32())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def int64(self):
        """Signed 64-bit int"""
        return common.auto_int(self._util.run_script_generic("""send(ptr({}).readS64())""".format(hex(self.address)), raw=True)[0][0])
    
    @property
    def uint64(self):
        """Unsigned 64-bit int"""
        return common.auto_int(self._util.run_script_generic("""send(ptr({}).readU64())""".format(hex(self.address)), raw=True)[0][0])

    @property
    def string_ansi(self):
        """Read as ANSI string"""
        return self._util.run_script_generic("""send(ptr({}).readAnsiString())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def string_utf8(self):
        """Read as utf-8 string"""
        return self._util.run_script_generic("""send(ptr({}).readUtf8String())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def string_utf16(self):
        """Read as utf-16 string"""
        return self._util.run_script_generic("""send(ptr({}).readUtf16String())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def double(self):
        """Read as double val"""
        return self._util.run_script_generic("""send(ptr({}).readDouble())""".format(hex(self.address)), raw=True)[0][0]

    @property
    def float(self):
        """Read as float val"""
        return self._util.run_script_generic("""send(ptr({}).readFloat())""".format(hex(self.address)), raw=True)[0][0]
    
    @property
    def pointer(self):
        """Read as pointer val"""
        return common.auto_int(self._util.run_script_generic("""send(ptr({}).readPointer())""".format(hex(self.address)), raw=True)[0][0])

class Memory(object):
    """Class to simplify getting and writing things to memory. Behaves like a list.
    
    Example:
        - memory[0x12345].int8 -> Reads a signed 8-bit int from address
        - memory[0x12345:0x12666] -> Returns byte array from memory
    """

    def __init__(self, util):
        self._util = util

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

            return self._util.run_script_generic("""send('array', ptr({}).readByteArray({}))""".format(hex(item.start), hex(item.stop-item.start)), raw=True)[1][0]


        logger.error("Unhandled memory type of {}".format(type(item)))
