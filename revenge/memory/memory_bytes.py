
import logging
logger = logging.getLogger(__name__)

import json
import time
from .. import common, types
from ..exceptions import *
import inspect

class MemoryBytes(object):
    """Meta-class used for resolving bytes into something else."""

    def __init__(self, process, address, address_stop=None):
        """Abstracting what memory location is.

        Args:
            process: Util object
            address (int): Starting address of the memory location.
            address_stop (int, optional): Optional stopping memory location.

        Examples:
            .. code-block:: python3

                # Trace specifically the function "win"
                win = process.memory['a.out:win']
                trace = process.techniques.NativeInstructionTracer(exec=True)
                
                # This will populate the trace
                win("input", techniques=trace)
                print(trace)
        """
        self._process = process
        self.address = address
        self.address_stop = address_stop
        self.return_type = types.Pointer # Default

    def free(self):
        """bool: Free this memory location. This is only valid if this memory location has been allocated by us."""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    def cast(self, cast_to):
        """Returns this memory cast to whatever type you give it.

        Examples:
            .. code-block:: python3

                ptr = memory.cast(types.Pointer)

                struct = types.Struct()
                struct.add_member('my_int', types.Int)
                struct.add_member('my_pointer', types.Pointer)
                struct = memory.cast(struct)
        """
        
        if type(cast_to) is type:
            cast_type = cast_to

        elif isinstance(cast_to, types.all_types):
            cast_type = type(cast_to)

        else:
            logger.error("Unexpected cast type. Please use revenge.types.*")
            return

        if not cast_type in types.all_types:
            logger.error("Unexpected cast type. Please use revenge.types.*")
            return

        if cast_type == types.Struct:
            if not isinstance(cast_to, types.Struct):
                logger.error("To cast to an struct, you MUST provide an instance of the struct.")
                return

            cast_to.memory = self
            return cast_to

        elif cast_type == types.Int8:
            return self.int8

        elif cast_type == types.UInt8:
            return self.uint8

        elif cast_type == types.Int16:
            return self.int16

        elif cast_type == types.UInt16:
            return self.uint16

        elif cast_type in [types.Int32, types.Int]:
            return self.int32

        elif cast_type == types.UInt32:
            return self.uint32

        elif cast_type == types.Int64:
            return self.int64

        elif cast_type == types.UInt64:
            return self.uint64

        elif cast_type == types.Double:
            return self.double

        elif cast_type == types.Float:
            return self.float

        elif cast_type == types.Pointer:
            return self.pointer

        elif cast_type == types.StringUTF8:
            return self.string_utf8

        elif cast_type == types.StringUTF16:
            return self.string_utf16

        else:
            logger.error("Unhandled memory cast type of {}".format(cast_type))

    def _call_as_thread(self, *args, **kwargs):
        """This is meant to be called by __call__ handler. Don't call directly unless you know what you're doing."""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    def __repr__(self):
        attrs = ['MemoryBytes', hex(self.address)]

        if self.size is not None:
            attrs.append(str(self.size) + ' bytes')

        if self.replace is not None:
            attrs.append("Replaced")

        return "<{}>".format(' '.join(attrs))

    def __call__(self, *args, **kwargs):
        """Call this memory location as a function.
        
        *args will be parsed and passed to the actual function
        **kwargs will be passed to Process.run_script_generic
        """

        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    def _remove_replace(self):
        """Reverts any replacement of this function."""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    def _remove_on_enter(self):
        """Reverts any on_enter hook of this function."""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def replace_on_message(self):
        """callable: Optional callable to be called if/when something inside the function replace sends data back.
        
        Example:
            .. code-block:: python3

                # If you just wanted to print out the messages that came back
                def on_message(x,y):
                    print(x,y)

                strlen.replace_on_message = on_message
        """
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @replace_on_message.setter
    def replace_on_message(self, replace_on_message):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def replace(self):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @replace.setter
    def replace(self, replace):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def implementation(self):
        return self.replace

    @implementation.setter
    def implementation(self, implementation):
        self.replace = implementation

    @property
    def argument_types(self):
        """tuple: Returns the registered arguments types for this function or
        None if none have been found/registered."""

        try:
            return self.__argument_types
        except AttributeError:
            return None

    @argument_types.setter
    def argument_types(self, arg_types):
        
        if arg_types is None:
            self.__argument_types = None
            return

        if isinstance(arg_types, list):
            arg_types = tuple(arg_types)

        if not isinstance(arg_types, tuple):
            arg_types = (arg_types,)

        if not all(t in types.all_types for t in arg_types):
            logger.error("All argument types must be valid revenge.type types.")
            return

        self.__argument_types = arg_types

        # force reload the modification with the new on_message handler
        self.replace = self.replace

    @property
    def return_type(self):
        """What's the return type for this? Only valid if this is a function."""
        return self.__return_type

    @return_type.setter
    def return_type(self, ret):

        if type(ret) is not type:
            logger.error('Please set with types.<type>.')
            return

        if ret not in types.all_types:
            logger.error('Unexpected type of {}. Please use types.<type>.'.format(ret))
            return

        self.__return_type = ret

        # force reload the modification with the new on_message handler
        self.replace = self.replace

    @property
    def int8(self):
        """Signed 8-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @int8.setter
    def int8(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def uint8(self):
        """Unsigned 8-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @uint8.setter
    def uint8(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def int16(self):
        """Signed 16-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @int16.setter
    def int16(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def uint16(self):
        """Unsigned 16-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @uint16.setter
    def uint16(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def int32(self):
        """Signed 32-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @int32.setter
    def int32(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def uint32(self):
        """Unsigned 32-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @uint32.setter
    def uint32(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def int64(self):
        """Signed 64-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @int64.setter
    def int64(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")
    
    @property
    def uint64(self):
        """Unsigned 64-bit int"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @uint64.setter
    def uint64(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def string_ansi(self):
        """Read as ANSI string"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @string_ansi.setter
    def string_ansi(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def string_utf8(self):
        """Read as utf-8 string"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @string_utf8.setter
    def string_utf8(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def string_utf16(self):
        """Read as utf-16 string"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @string_utf16.setter
    def string_utf16(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def double(self):
        """Read as double val"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @double.setter
    def double(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def float(self):
        """Read as float val"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @float.setter
    def float(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")
    
    @property
    def pointer(self):
        """Read as pointer val"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @pointer.setter
    def pointer(self, val):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def breakpoint(self):
        """bool: Does this address have an active breakpoint?"""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @breakpoint.setter
    def breakpoint(self, val):
        """bool: Set this as a breakpoint or remove the breakpoint."""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def bytes(self):
        """bytes: Return this as raw bytes."""
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @bytes.setter
    def bytes(self, b):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def size(self):
        """int: Size of this MemoryBytes. Only valid if it was generated as a slice, alloc or something else that has known size."""
        if self.address_stop is None:
            return None

        return self.address_stop - self.address

    @property
    def address(self):
        """Pointer: Address of this MemoryBytes."""
        return self.__address

    @address.setter
    def address(self, address):
        # Standardize to Pointer
        if type(address) is int:
            address = types.Pointer(address)
        self.__address = address

    @property
    def address_stop(self):
        """Pointer: Stop address of this MemoryBytes."""
        return self.__address_stop

    @address_stop.setter
    def address_stop(self, address):
        # Standardize to Pointer
        if type(address) is int:
            address = types.Pointer(address)
        self.__address_stop = address
    
    @property
    def instruction(self):
        """AssemblyInstruction: Returns an assembly instruction parsed from what is in memory at this location."""
        return AssemblyInstruction(self._process, self.address)

    @property
    def instruction_block(self):
        """AssemblyBlock: Returns an AssemblyBlock starting at this instruction."""
        return AssemblyBlock(self._process, self.address)

    @property
    def struct(self):
        """Write as a struct.
        
        Example:
            .. code-block:: python3

                struct = types.Struct()
                struct.add_member('test1', types.Int32(-5))
                struct.add_member('test2', types.Int8(-12))
                struct.add_member('test3', types.UInt16(16))
                process.memory[0x12345].struct = struct

                # Or
                process.memory[0x12345] = struct
        """
        raise NotImplementedError

    @struct.setter
    def struct(self, struct):
        raise NotImplementedError(inspect.currentframe().f_code.co_name + ": not implemented in this engine yet.")

    @property
    def name(self):
        """str: Descriptive name for this address. Optional."""

        try:
            return self.__name
        except AttributeError:
            return None

    @name.setter
    def name(self, name):
        if not isinstance(name, (str, type(None))): raise RevengeInvalidArgumentType("name must be of type str.")
        self.__name = name

    @property
    def _dynamic_assembly_call_str(self):
        """str: Return C code for a dynamic function call to this address."""

        if self.name is None:
            logger.error("Must have set name before calling this.")
            return

        template = "{ret_type} (*{func_name})({func_args}) = ({ret_type} (*)({func_args})) {addr};"

        ret_type = self.return_type.ctype
        func_name = self.name
        func_args = ', '.join(arg.ctype for arg in self.argument_types) if self.argument_types is not None else ""

        template = template.format(
                ret_type = ret_type,
                func_name = func_name,
                func_args = func_args,
                addr = hex(self.address),
                )

        return template

#
# Doc Updates
#
MemoryBytes.implementation.__doc__ = MemoryBytes.replace.__doc__
MemoryBytes.__doc__ = MemoryBytes.__init__.__doc__


from ..cpu.assembly import AssemblyInstruction, AssemblyBlock
from ..native_exception import NativeException
from .memory_range import MemoryRange
from ..techniques import Technique
