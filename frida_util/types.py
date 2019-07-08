
import logging
logger = logging.getLogger(__name__)

# Keeping str types as properties in case they change what they call things later

class Basic: 
    def __add__(self, other):
        if type(self) is type(other) or type(other) is int:
            return self.__class__(int.__add__(self, other))
        else:
            logger.warning("Adding incompatible types {} and {}. Un-casting back to int.".format(type(self), type(other)))
            return int(self) + int(other)

    def __sub__(self, other):
        if type(self) is type(other) or type(other) is int:
            return self.__class__(int.__sub__(self, other))
        else:
            logger.warning("Subtracting incompatible types {} and {}. Un-casting back to int.".format(type(self), type(other)))
            return int(self) - int(other)

    @property
    def js(self):
        """String that can be fed into js."""
        return str(self)

class FloatBasic: 
    def __add__(self, other):
        if type(self) is type(other) or type(other) is int:
            return self.__class__(float.__add__(self, other))
        else:
            logger.warning("Adding incompatible types {} and {}. Un-casting back to float.".format(type(self), type(other)))
            return float(self) + float(other)

    def __sub__(self, other):
        if type(self) is type(other) or type(other) is int:
            return self.__class__(float.__sub__(self, other))
        else:
            logger.warning("Subtracting incompatible types {} and {}. Un-casting back to float.".format(type(self), type(other)))
            return float(self) - float(other)

class Int8(Basic, int):
    type = "int8"

class UInt8(Basic, int):
    type = "uint8"

class Int16(Basic, int):
    type = "int16"

class UInt16(Basic, int):
    type = "uint16"

class Int32(Basic, int):
    type = "int32"

class UInt32(Basic, int):
    type = "uint32"

class Int64(Basic, int):
    type = "int64"

    @property
    def js(self):
        return "int64('{}')".format(hex(self))

class UInt64(Basic, int):
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

class Float(FloatBasic, float):
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
