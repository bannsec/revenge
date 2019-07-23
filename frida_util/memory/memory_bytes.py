
import logging
logger = logging.getLogger(__name__)

import json
from .. import common, types

class MemoryBytes(object):
    """Meta-class used for resolving bytes into something else."""

    def __init__(self, process, address, address_stop=None):
        """Abstracting what memory location is.

        Args:
            process: Util object
            address (int): Starting address of the memory location.
            address_stop (int, optional): Optional stopping memory location.
        """
        self._process = process
        self.address = address
        self.address_stop = address_stop
        self.return_type = types.Pointer # Default

    def free(self):
        """bool: Free this memory location. This is only valid if this memory location has been allocated by us."""

        # Make sure we allocated it
        if self.address not in self._process.memory._allocated_memory:
            logger.error("Can't free this memory as we didn't allocate it.")
            return False

        # Free it implicitly by freeing our script
        script = self._process.memory._allocated_memory.pop(self.address)
        script[0].unload()
        return True

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

        # Generically use pointers and figure it out later

        # Resolve args to memory strings and such if needed
        args_resolved = []
        to_free = []
        args_types = []

        for arg in args:

            if type(arg) is MemoryBytes:
                arg = arg.address

            # Make temporary string first
            if type(arg) in [types.StringUTF16, types.StringUTF8]:
                s = self._process.memory.alloc_string(arg)
                args_resolved.append('ptr("' + hex(s.address) + '")')
                to_free.append(s)
                args_types.append('pointer')

            # Make temporary string in memory
            elif type(arg) in [str, bytes]:
                s = self._process.memory.alloc_string(arg)
                args_resolved.append('ptr("' + hex(s.address) + '")')
                to_free.append(s)
                args_types.append('pointer')

            elif type(arg) is int:
                # Defaulting these to pointers for now.
                args_resolved.append('ptr("' + hex(arg) + '")')
                args_types.append('pointer')

            elif isinstance(arg, types.all_types):
                args_resolved.append(arg.js)
                args_types.append(arg.type)

            else:
                logger.error("Unexpected argument type of {}".format(type(arg)))
                return None

        js = """var f = new NativeFunction(ptr("{ptr}"), '{ret_type}', {args_types});""".format(
                ptr = hex(self.address),
                ret_type = self.return_type.type,
                args_types = json.dumps(args_types),
            )

        # If we are not passing to a context, then sync send it
        if kwargs.get("context", None) is None:
            js += "send(f({args}))".format(args = ', '.join(args_resolved))
        else:
            # We're passing to a context, let it handle the message back.
            js += "f({args})".format(args = ', '.join(args_resolved))

        ret = self._process.run_script_generic(js, raw=True, unload=True, **kwargs)

        # If we changed on_message or context, this might be None. That's ok.
        if ret is None:
            ret = 0
        else:
            ret = ret[0][0]

        # Free stuff up
        for alloc in to_free:
            # If we dynamically allocated something but we're in a context, we
            # cannot free it yet.  Warn the user.
            if kwargs.get("context", None) is not None:
                logger.warn("Not freeing dynamically allocated memory due to use of context. This will cause a memory leak!!")
            else:
                alloc.free()
        
        return self.return_type(common.auto_int(ret))

    def _remove_replace(self):
        """Reverts any replacement of this function."""

        if self.address in self._process.memory._active_replacements:
            self._process.memory._active_replacements[self.address][1][0].unload()
            self._process.memory._active_replacements.pop(self.address)


    @property
    def replace(self):
        """What is this function being replaced by? None if there's no replacement."""
        try:
            return self._process.memory._active_replacements[self.address][0]
        except:
            return None

    @replace.setter
    def replace(self, replace):

        if replace is None:
            self._remove_replace()

        #
        # Replace function with simple return value
        #

        elif isinstance(replace, int):
            self._remove_replace()

            replace_address = self.address.js

            # If it's not already a defined type
            if type(replace) is int:
                replace = self.return_type(replace)
                replace_val = replace.js
                replace_type = self.return_type.type

            else:
                replace_val = replace.js
                replace_type = replace.type

            replace_vars = {
                "FUNCTION_RETURN_VALUE": replace_val,
                "FUNCTION_RETURN_TYPE": replace_type,
                "FUNCTION_ADDRESS": replace_address,
            }

            self._process.run_script_generic("replace_function.js", replace=replace_vars, unload=False)
            script = self._process._scripts.pop(0)
            self._process.memory._active_replacements[self.address] = (replace, script)

        else:
            logger.error("Invalid replacement type of {}".format(type(replace)))

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

    @property
    def int8(self):
        """Signed 8-bit int"""
        return types.Int8(self._process.run_script_generic("""send(ptr("{}").readS8())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @int8.setter
    def int8(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeS8({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def uint8(self):
        """Unsigned 8-bit int"""
        return types.UInt8(self._process.run_script_generic("""send(ptr("{}").readU8())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @uint8.setter
    def uint8(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeU8({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def int16(self):
        """Signed 16-bit int"""
        return types.Int16(self._process.run_script_generic("""send(ptr("{}").readS16())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @int16.setter
    def int16(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeS16({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def uint16(self):
        """Unsigned 16-bit int"""
        return types.UInt16(self._process.run_script_generic("""send(ptr("{}").readU16())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @uint16.setter
    def uint16(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeU16({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def int32(self):
        """Signed 32-bit int"""
        return types.Int32(self._process.run_script_generic("""send(ptr("{}").readS32())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @int32.setter
    def int32(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeS32({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def uint32(self):
        """Unsigned 32-bit int"""
        return types.UInt32(self._process.run_script_generic("""send(ptr("{}").readU32())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @uint32.setter
    def uint32(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeU32({}))""".format(hex(self.address), val), raw=True, unload=True)[0][0]

    @property
    def int64(self):
        """Signed 64-bit int"""
        return types.Int64(common.auto_int(self._process.run_script_generic("""send(ptr("{}").readS64())""".format(hex(self.address)), raw=True, unload=True)[0][0]))

    @int64.setter
    def int64(self, val):
        self._process.run_script_generic("""ptr("{}").writeS64(int64('{}'))""".format(hex(self.address), val), raw=True, unload=True)
    
    @property
    def uint64(self):
        """Unsigned 64-bit int"""
        return types.UInt64(common.auto_int(self._process.run_script_generic("""send(ptr("{}").readU64())""".format(hex(self.address)), raw=True, unload=True)[0][0]))

    @uint64.setter
    def uint64(self, val):
        self._process.run_script_generic("""ptr("{}").writeU64(uint64('{}'))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def string_ansi(self):
        """Read as ANSI string"""
        return self._process.run_script_generic("""send(ptr("{}").readAnsiString())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @string_ansi.setter
    def string_ansi(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeAnsiString(\"{}\"))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def string_utf8(self):
        """Read as utf-8 string"""
        return self._process.run_script_generic("""send(ptr("{}").readUtf8String())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @string_utf8.setter
    def string_utf8(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeUtf8String(\"{}\"))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def string_utf16(self):
        """Read as utf-16 string"""
        return self._process.run_script_generic("""send(ptr("{}").readUtf16String())""".format(hex(self.address)), raw=True, unload=True)[0][0]

    @string_utf16.setter
    def string_utf16(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeUtf16String(\"{}\"))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def double(self):
        """Read as double val"""
        return types.Double(self._process.run_script_generic("""send(ptr("{}").readDouble())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @double.setter
    def double(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeDouble({}))""".format(hex(self.address), val), raw=True, unload=True)

    @property
    def float(self):
        """Read as float val"""
        return types.Float(self._process.run_script_generic("""send(ptr("{}").readFloat())""".format(hex(self.address)), raw=True, unload=True)[0][0])

    @float.setter
    def float(self, val):
        self._process.run_script_generic("""send(ptr("{}").writeFloat({}))""".format(hex(self.address), val), raw=True, unload=True)
    
    @property
    def pointer(self):
        """Read as pointer val"""
        return types.Pointer(common.auto_int(self._process.run_script_generic("""send(ptr("{}").readPointer())""".format(hex(self.address)), raw=True, unload=True)[0][0]))

    @pointer.setter
    def pointer(self, val):
        common.auto_int(self._process.run_script_generic("""send(ptr("{}").writePointer(ptr("{}")))""".format(hex(self.address), hex(val)), raw=True, unload=True)[0][0])

    @property
    def breakpoint(self):
        """bool: Does this address have an active breakpoint?"""
        return self.address in self._process.memory._active_breakpoints

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
            self._process.run_script_generic("""ptr("{}").writeS8(1);""".format(hex(self._process.memory._active_breakpoints[self.address])), raw=True, unload=True)
            self._process.memory._active_breakpoints.pop(self.address)

        # Add breakpoint
        else:
            # Breakpoint already exists
            if self.breakpoint:
                return

            unbreak = int(self._process.run_script_generic('generic_suspend_until_true.js', replace={"FUNCTION_HERE": hex(self.address)})[0][0],16)
            #print('Unsuspend pointer: ' + hex(unbreak))
            self._process.memory._active_breakpoints[self.address] = unbreak


    @property
    def bytes(self):
        """bytes: Return this as raw bytes."""
        if self.address_stop is None:
            length = 1 # Default to 1 byte
        else:
            length = self.address_stop - self.address

        return self._process.run_script_generic("""send('array', ptr("{}").readByteArray({}))""".format(hex(self.address), hex(length)), raw=True, unload=True)[1][0]

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

        self._process.run_script_generic("""ptr("{}").writeByteArray({});""".format(
            hex(self.address),
            json.dumps(list(b)),
            ), raw=True, unload=True)

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

from ..tracer.assembly_instruction import AssemblyInstruction, AssemblyBlock
