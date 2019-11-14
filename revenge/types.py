
import logging
logger = logging.getLogger(__name__)

import weakref
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
    ctype = "char"
    sizeof = 1

class UInt8(Basic, int):
    type = "uint8"
    ctype = "unsigned char"
    sizeof = 1

class Int16(Basic, int):
    type = "int16"
    ctype = "short"
    sizeof = 2

class UInt16(Basic, int):
    type = "uint16"
    ctype = "unsigned short"
    sizeof = 2

class Int32(Basic, int):
    type = "int32"
    ctype = "int"
    sizeof = 4

class UInt32(Basic, int):
    type = "uint32"
    ctype = "unsigned int"
    sizeof = 4

class Int64(Basic, int):
    type = "int64"
    ctype = "long"
    sizeof = 8

    @property
    def js(self):
        return "int64('{}')".format(hex(self))

class UInt64(Basic, int):
    type = "uint64"
    ctype = "unsigned long"
    sizeof = 8

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
    ctype = "float"
    sizeof = 4

    @property
    def js(self):
        return str(self)

class Double(Float):
    type = "double"
    ctype = "double"
    sizeof = 8

class Pointer(UInt64):
    type = "pointer"
    ctype = "void *"
    # Handle recursing down into sub object to get ctype
    # i.e.: char *
    
    @property
    @require_process
    def sizeof(self):
        return int(self._process.bits/8)

    @property
    def js(self):
        return """ptr("{}")""".format(hex(self))

class Padding(BasicBasic):
    """Defines the spacing between struct entries.

    Example:
        .. code-block:: python3

            struct = types.Struct()
            struct['one'] = types.Int8
            struct['pad1'] = types.Padding(3)
            struct['two'] = types.Int16
    """

    def __init__(self, size):
        self.sizeof = size

#
# These don't directly have a return type value, they will just be pointers..
# 

class StringUTF8(BasicBasic, str):
    type = 'utf8'
    ctype = "char *"
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
    """Defines a C structure.

    Examples:
        .. code-block:: python3

            # Create a struct
            my_struct = types.Struct()
            my_struct.add_member('member_1', types.Int)
            my_struct.add_member('pad1', types.Padding(1))
            my_struct.add_member('member_2', types.Pointer)

            # Alternatively, add them IN ORDER via dict setter
            my_struct = types.Struct()
            my_struct['member_1'] = types.Int
            my_struct['member_2'] = types.Pointer

            # Use cast to bind your struct to a location
            my_struct = process.memory[0x12345].cast(my_struct)

            # Or set memory property directly
            my_struct.memory = process.memory[0x12345]

            # Read out the values
            my_struct['member_1']
            my_struct['member_2']

            # Write in some new values (this will auto-cast based on struct def)
            my_struct['member_1'] = 12

            # Allocate a struct and use it in a function call
            my_struct = process.memory.alloc_struct(my_struct)
            process.memory[<some function>](types.Pointer(my_struct))
    """

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
        """int: Figure out how far in (in bytes) from the struct a given member is."""

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

    @property
    def name(self):
        try:
            return self.__name
        except AttributeError:
            return None

    @name.setter
    def name(self, name):
        if not isinstance(name, str):
            logger.error("Name must be instance of str.")
            return

        self.__name = name

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

    def __repr__(self):
        attrs = ['Struct']

        if self.name is not None:
            attrs.append(self.name)

        attrs += ['members:' + str(len(self.members))]

        return '<' + ' '.join(attrs) + '>'

    def __str__(self):
        # No. This is not meant to be actual working struct code!

        s = "struct {} {{\n".format(self.name if self.name is not None else "")

        for name, value in self.members.items():
            if isinstance(value, Padding):
                continue

            s += "  " + name + " = "
            s += str(self[name])
            s += ";\n"

        s += "}"
        return s

    def __int__(self):
        try:
            return int(self.memory.address)
        except AttributeError:
            return 0

    def __hex__(self):
        return hex(int(self))

    def __index__(self):
        return int(self)

class Telescope(BasicBasic):
    _flyweight_cache = weakref.WeakValueDictionary()

    def __init__(self, process, address=None, data=None):
        """Create a telescoped variable object.

        Args:
            process: Base process object
            address (int, optional): Address to telescope
            data (dict, optional): Dictionary object of information to populate
                from. see telescope.js.
        """
        # Doing setup in __new__
        pass

    def __new__(klass, process, address=None, data=None):
        
        # Implementing auto flyweight pattern for telescope magic
        telescope = super(Telescope, klass).__new__(klass)

        telescope._process = process
        telescope.address = address

        if data is not None:
            telescope._parse_dict(data)

        # If this object already exists, just use that one
        h = hash(telescope)
        if h in telescope._flyweight_cache:
            return telescope._flyweight_cache[h]

        # Save this object off
        telescope._flyweight_cache[h] = telescope
        return telescope

    def _telescope(self):
        d = self._process.run_script_generic(r"""send(telescope({}));""".format(
                int(self.address)),
            raw=True,
            include_js="telescope.js",
            unload=True,
            runtime="v8")[0][0]
        self._parse_dict(d)

    def _parse_dict(self, d):
        """Parses a dict generated by js telescope call."""
        if "telescope" not in d or d["telescope"] is not True:
            raise RevengeInvalidArgumentType("dictionary does not appear to be a telescope dictionary.")
        
        # Type must be set first!
        self.type = d['type']
        self.thing = d['thing']
        self.next = d['next']
        self.memory_range = d['mem_range']

    def __repr__(self):
        return "<Telescope " + self.description + ">"

    def __int__(self):
        if self.type != "int":
            raise RevengeInvalidArgumentType("Asking for int of Telescope value that is type {}".format(self.type))

        return self.thing

    def __index__(self):
        return self.__int__()

    def __hex__(self):
        return hex(int(self))

    def __and__(self, other):
        return int(self) & other

    def __rshift__(self, shift):
        return int(self) >> shift
    
    def __hash__(self):
        return hash((self.address, self.type, self.thing, self.next, self.memory_range))

    @property
    def thing(self):
        """Whatever this part of the telescope is."""
        try:
            return self.__thing
        except AttributeError:
            return None

    @thing.setter
    def thing(self, thing):
        # Immutable after set due to flyweight
        if self.thing is not None:
            raise RevengeImmutableError("thing argument is immutable.")

        # Sometimes we get ints returned as string hex rep
        if self.type == "int":
            thing = common.auto_int(thing)
        elif self.type == "instruction":
            thing = AssemblyInstruction.from_frida_dict(self._process, thing)
        self.__thing = thing

    @property
    def next(self):
        """Next step in the telescope."""
        return self.__next

    @next.setter
    def next(self, next):

        if next is None:
            self.__next = None

        else:
            self.__next = Telescope(self._process, data=next)

    @property
    def address(self):
        """int: Address of this variable."""
        return self.__address

    @address.setter
    def address(self, address):
        if address is None:
            self.__address = None
            return

        if isinstance(address, Symbol):
            address = address.address

        if not isinstance(address, int): raise RevengeInvalidArgumentType(
                "address must be of int type. Got {}".format(type(address)))

        self.__address = address
        self._parse_dict(
            self._process.run_script_generic(
                    r"""send(telescope({}));""".format(self.address),
                    raw=True,
                    include_js="telescope.js",
                    unload=True,
                    runtime="v8")[0][0])

    @property
    def memory_range(self):
        """Information about the memory range this is in."""
        return self.__memory_range

    @memory_range.setter
    def memory_range(self, memory_range):
        if memory_range is None:
            self.__memory_range = None

        else:
            self.__memory_range = MemoryRange._from_frida_find_json(self._process, memory_range)

    @property
    def description(self):
        """str: String representational description of this telescope."""
        attrs = []

        next_thing = self
        while next_thing is not None:
            if next_thing.type == "int":
                attrs.append(hex(next_thing.thing))
            else:
                attrs.append(str(next_thing.thing))
            next_thing = next_thing.next

        return ' -> '.join(attrs)


        
frida_types = (Pointer, Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64, Char, UChar, Short, UShort, Int, UInt, Long, ULong, Float, Double)
all_types = frida_types + (Struct, Padding, StringUTF8, StringUTF16)

from .memory import MemoryBytes, MemoryRange
from .process import Process
from .symbols import Symbol
from .cpu.assembly import AssemblyInstruction
from . import common
