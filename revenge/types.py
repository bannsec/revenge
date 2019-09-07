
import logging
logger = logging.getLogger(__name__)

import collections
from .exceptions import *

def require_process(func):
    def func_wrap(self, *args, **kwargs):
        if self._process is None:
            raise RevengeProcessRequiredError("Calling {} requires ._process be set first.".format(func.__name__))
        return func(self, *args, **kwargs)
    return func_wrap


# Keeping str types as properties in case they change what they call things later
class BasicBasic(object):
    @property
    def _process(self):
        """Process property is only required for certain actions."""
        
        try:
            return self.__process
        except AttributeError:
            return None

    @_process.setter
    def _process(self, process):
        if not isinstance(process, Process):
            logger.error("_process must be an instance of Process. Got type {}".format(type(process)))
            return

        self.__process = process

    @property
    def memory(self):
        """Instantiate this type to an active memory location for getting
        and setting.

        Examples:
            .. code-block:: python3

                struct = types.Struct()
                struct.add_member('my_int', types.Int)
                struct.add_member('my_pointer', types.Pointer)

                struct.memory = 0x12345
                # OR
                struct.memory = 'a.out:symb'
                # OR
                struct.memory = process.memory[<whatever>]
        """

        try:
            return self.__memory
        except AttributeError:
            return None

    @memory.setter
    def memory(self, memory):

        if isinstance(memory, (int, str)):
            # Passthrough and let memory object deal with it
            if self._process is None:
                logger.error("Setting Memory via int or str requires ._process be set.")
                return
            self.__memory = self._process.memory[memory]

        elif isinstance(memory, MemoryBytes):
            self.__memory = memory
            self._process = memory._process

        else:
            logger.error("Unhandled memory property setter of type {}".format(type(memory)))

class Basic(BasicBasic):
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
    sizeof = 8

class UInt8(Basic, int):
    type = "uint8"
    sizeof = 8

class Int16(Basic, int):
    type = "int16"
    sizeof = 16

class UInt16(Basic, int):
    type = "uint16"
    sizeof = 16

class Int32(Basic, int):
    type = "int32"
    sizeof = 32

class UInt32(Basic, int):
    type = "uint32"
    sizeof = 32

class Int64(Basic, int):
    type = "int64"
    sizeof = 64

    @property
    def js(self):
        return "int64('{}')".format(hex(self))

class UInt64(Basic, int):
    type = "uint64"
    sizeof = 64

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
    sizeof = 4

    @property
    def js(self):
        return str(self)

class Double(Float):
    type = "double"
    sizeof = 8

class Pointer(UInt64):
    type = "pointer"
    
    @property
    @require_process
    def sizeof(self):
        return self._process.bits

    @property
    def js(self):
        return "ptr('{}')".format(hex(self))

#
# These don't directly have a return type value, they will just be pointers..
# 

class StringUTF8(BasicBasic, str):
    type = 'utf8'
    sizeof = Pointer.sizeof

    @property
    def js(self):
        logger.error("Shouldn't be asking for js on this object...")
        return str(self)

class StringUTF16(BasicBasic, str):
    type = 'utf16'
    sizeof = Pointer.sizeof

    @property
    def js(self):
        logger.error("Shouldn't be asking for js on this object...")
        return str(self)

class Struct(Pointer):
    """Defines a C structure."""

    def add_member(self, name, value=None):
        """Adds given member to the end of this current structure.
        
        Args:
            name (str): Name of the Struct member
            value (revenge.types.all_types): Type and/or value for member.

        Examples:
            .. code-block:: python3

                s = revenge.types.Struct()
                s.add_member('my_int', revenge.types.Int(12))

                # Or, just the definition
                s = revenge.types.Struct()
                s.add_member('my_int', revenge.types.Int)
        """

        if not type(name) is str:
            logger.error("Member name must be of type str.")
            return

        if not isinstance(value, all_types) and not value in all_types:
            logger.error("Entry added must be one of the revenge.types.* classes.")
            return

        if name in self.members:
            logger.warning("Member name already exists! This will overwrite the old member with the new value!")

        self.members[name] = value

    @require_process
    def _get_member_offset(self, member_name):
        """int: Figure out how far in from the struct a given member is."""

        if member_name not in self.members:
            logger.error("This member doesn't exist.")
            return

        offset = 0
        for name, member in self.members.items():
            if name == member_name:
                return offset

            if type(member) is type:
                member = member()
            member._process = self._process
            offset += member.sizeof

    @property
    @require_process
    def sizeof(self):
        """Equivalent of calling 'sizeof(this_struct)'."""

        sum = 0
        for name, value in self.members.items():
            # Temporarily make an object so we can figure out size
            if type(value) is type:
                value = value()
            value._process = self._process
            sum += value.sizeof

        return sum

    @property
    def members(self):
        try:
            return self.__members
        except AttributeError:
            self.__members = collections.OrderedDict()
            return self.__members

    @members.setter
    def members(self, members):

        if isinstance(members, tuple):
            members = list(members)

        if not isinstance(members, list):
            logger.error("Setting members property requires a list.")
            return

        self.__members = members


    def __getitem__(self, member_name):

        if not isinstance(member_name, str):
            logger.error("Only member names are currently supported.")
            return

        if member_name not in self.members:
            logger.error("Member {} doesn't appear to exist in this struct.".format(member_name))
            return

        member = self.members[member_name]

        if self.memory is not None:
            # Assume we want to read the actual value
            member_offset = self._get_member_offset(member_name)
            return self.memory._process.memory[self.memory.address + member_offset].cast(member)

        return member

    def __setitem__(self, member_name, value):
        
        # If not bound, this is the same as [re]adding a member
        if self.memory is None:
            return self.add_member(member_name, value)

        if not isinstance(member_name, str):
            logger.error("Only member names are currently supported.")
            return

        if member_name not in self.members:
            logger.error("Member {} doesn't appear to exist in this struct.".format(member_name))
            return

        member = self.members[member_name]

        if type(member) is not type:
            member_type = type(member)
        else:
            member_type = member

        member_offset = self._get_member_offset(member_name)

        # Auto type-casting it
        self.memory._process.memory[self.memory.address + member_offset] = member_type(value)

        
all_types = (Pointer, Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64, Char, UChar, Short, UShort, Int, UInt, Long, ULong, Float, Double, StringUTF8, StringUTF16, Struct)

from .memory import MemoryBytes
from .process import Process
