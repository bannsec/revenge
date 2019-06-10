
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
    type = "int8"

class UInt8(int, Basic):
    type = "uint8"

class Int16(int, Basic):
    type = "int16"

class UInt16(int, Basic):
    type = "uint16"

class Int32(int, Basic):
    type = "int32"

class UInt32(int, Basic):
    type = "uint32"

class Int64(int, Basic):
    type = "int64"

    @property
    def js(self):
        return "int64('{}')".format(hex(self))

class UInt64(int, Basic):
    type = "uint64"

    @property
    def js(self):
        return "uint64('{}')".format(hex(self))

class Char(Int8):
    type = "char"

class UChar(UInt8):
    type = "uchar"

class Short(Int16):
    type = "short"

class UShort(UInt16):
    type = "ushort"

class Int(Int32):
    type = "int"

class UInt(UInt32):
    type = "uint"

class Long(Int64):
    type = "long"

class ULong(UInt64):
    type = "ulong"

class Float(float):
    type = "float"

    @property
    def js(self):
        return str(self)

class Double(Float):
    type = "double"

class Pointer(UInt64):
    type = "pointer"

    @property
    def js(self):
        return "ptr('{}')".format(hex(self))

#
# These don't directly have a return type value, they will just be pointers..
# 

class StringUTF8(str):
    type = 'utf8'

    @property
    def js(self):
        logger.error("Shouldn't be asking for js on this object...")
        return str(self)

class StringUTF16(str):
    type = 'utf16'

    @property
    def js(self):
        logger.error("Shouldn't be asking for js on this object...")
        return str(self)


all_types = (Pointer, Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64, Char, UChar, Short, UShort, Int, UInt, Long, ULong, Float, Double, StringUTF8, StringUTF16)
