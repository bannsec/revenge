
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

# Keeping str types as properties in case they change what they call things later

class Basic:
    @property
    def js(self):
        """String that can be fed into js."""
        return str(self)

class Int8(int, Basic):
    @property
    def type(self):
        return "int8"

class UInt8(int, Basic):
    @property
    def type(self):
        return "uint8"

class Int16(int, Basic):
    @property
    def type(self):
        return "int16"

class UInt16(int, Basic):
    @property
    def type(self):
        return "uint16"

class Int32(int, Basic):
    @property
    def type(self):
        return "int32"

class UInt32(int, Basic):
    @property
    def type(self):
        return "uint32"

class Int64(int, Basic):
    @property
    def js(self):
        return "int64('{}')".format(hex(self))

    @property
    def type(self):
        return "int64"

class UInt64(int, Basic):
    @property
    def js(self):
        return "uint64('{}')".format(hex(self))

    @property
    def type(self):
        return "uint64"

class Char(Int8):
    @property
    def type(self):
        return "char"

class UChar(UInt8):
    @property
    def type(self):
        return "uchar"

class Short(Int16):
    @property
    def type(self):
        return "short"

class UShort(UInt16):
    @property
    def type(self):
        return "ushort"

class Int(Int32):
    @property
    def type(self):
        return "int"

class UInt(UInt32):
    @property
    def type(self):
        return "uint"

class Long(Int64):
    @property
    def type(self):
        return "long"

class ULong(UInt64):
    @property
    def type(self):
        return "ulong"

class Float(float):
    @property
    def type(self):
        return "float"

    @property
    def js(self):
        return str(self)

class Double(Float):
    @property
    def type(self):
        return "double"

class Pointer(UInt64):
    @property
    def js(self):
        return "ptr('{}')".format(hex(self))

    @property
    def type(self):
        return "pointer"

all_types = (Pointer, Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64, Char, UChar, Short, UShort, Int, UInt, Long, ULong, Float, Double)
