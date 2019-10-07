
import logging
logger = logging.getLogger(__name__)

import json
from .. import common, types, exceptions

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

        # Wrap call to watch for native exceptions
        js = "try { " + js + """} catch (exception) { 
            if ( Object.keys(exception).indexOf('memory') == -1 ) {
                var bt = [];
            } else {
                var bt = Thread.backtrace(exception['memory']['context']);
            }
            send({
                "exception": exception,
                "backtrace": bt,
            })}"""

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
                logger.warning("Not freeing dynamically allocated memory due to use of context. This will cause a memory leak!!")
            else:
                alloc.free()

        # Handle the case where the process did something bad
        if isinstance(ret, dict) and "exception" in ret:
            return NativeException._from_frida_dict(self._process, ret['exception'], ret['backtrace'])
        
        return self.return_type(common.auto_int(ret))

    def _remove_replace(self):
        """Reverts any replacement of this function."""

        if self.address in self._process.memory._active_replacements:
            self._process.memory._active_replacements[self.address][1][0].unload()
            self._process.memory._active_replacements.pop(self.address)

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

        try:
            return self.__replace_on_message
        except AttributeError:
            return None

    @replace_on_message.setter
    def replace_on_message(self, replace_on_message):

        if replace_on_message is None:
            self.__replace_on_message = None
            return

        if not callable(replace_on_message):
            logger.error("On Message handler must be callable.")
            return

        self.__replace_on_message = replace_on_message

        # force reload the modification with the new on_message handler
        self.replace = self.replace

    @property
    def replace(self):
        """What is this function being replaced by? None if there's no replacement.
        
        Examples:
            
            Replacing strlen with a function that sends back the argument

            .. code-block:: python3

                strlen = process.memory[':strlen']
                strlen.return_type = types.Int64
                strlen.argument_types = types.Pointer

                # If you're not sending messages, you don't need this
                def on_message(x,y):
                    print(x,y)

                strlen.replace_on_message = on_message

                # Replacing strlen with some arbitrary js function
                # "original" is always going to be the function you're replacing
                # In this case, take response and decrement it by one
                strlen.replace = "function (s) { send(s); return original(s)-1;}"
                assert strlen("hello") == 4

                # Remove the replace
                strlen.replace = None
                assert strlen("test") == 4

            Replacing alarm to return 1

            .. code-block:: python3

                alarm = process.memory[':alarm']
                # Replace function by just returning static value
                alarm.replace = 1

                # Alarm is not set
                assert alarm(1) == 1
        """
        try:
            return self._process.memory._active_replacements[self.address][0]
        except:
            return None

    @replace.setter
    def replace(self, replace):

        self._remove_replace()

        if replace is None:
            return

        #
        # Replace function with simple return value
        #

        if isinstance(replace, int):

            # If it's not already a defined type
            if type(replace) is int:
                replace = self.return_type(replace)
                replace_val = replace.js
                replace_type = self.return_type.type

            else:
                replace_val = replace.js
                replace_type = replace.type

            replace_func = """function () {{ return {}; }}""".format(replace_val)

            replace_vars = {
                "FUNCTION_RETURN_TYPE": replace_type,
                "FUNCTION_ADDRESS": self.address.js,
                "FUNCTION_REPLACE": replace_func,
                "FUNCTION_ARG_TYPES": str([])
            }

            self._process.run_script_generic("replace_function.js", replace=replace_vars, unload=False)
            script = self._process._scripts.pop(0)
            self._process.memory._active_replacements[self.address] = (replace, script)

        #
        # Replace function with js
        #

        elif isinstance(replace, str):

            # Default return to pointer
            return_type = self.return_type.type or types.Pointer

            # Default to no argument types
            arg_types = [x.type for x in self.argument_types] if self.argument_types is not None else []
            arg_types = str(arg_types)

            replace_vars = {
                "FUNCTION_RETURN_TYPE": return_type,
                "FUNCTION_ADDRESS": self.address.js,
                "FUNCTION_REPLACE": replace,
                "FUNCTION_ARG_TYPES": arg_types
            }

            self._process.run_script_generic("replace_function.js",
                    replace=replace_vars, unload=False,
                    on_message=self.replace_on_message)
            script = self._process._scripts.pop(0)
            self._process.memory._active_replacements[self.address] = (replace, script)

        else:
            logger.error("Invalid replacement type of {}".format(type(replace)))

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

        if not isinstance(struct, types.Struct):
            logger.error("MemoryBytes.struct must be an instance of types.Struct. Got type {} instead.".format(type(struct)))
            return

        # TODO: Maybe create a blob and just write it in at once as bytes instead of individual calls...
        addr = self.address
        for name, member in struct.members.items():

            if member in types.all_types:
                logger.warning("Member of struct '{}' was left uninitialized. Not writing anything for this member.".format(name))
                tmp = member()
                tmp._process = self._process
                addr += tmp.sizeof

            else:

                # Write in member
                # TODO: But what if this is a struct? I.e.: nested structs
                self._process.memory[addr] = member
                member._process = self._process # Just in case for sizeof
                addr += member.sizeof

    @property
    def name(self):
        """str: Descriptive name for this address. Optional."""

        try:
            return self.__name
        except AttributeError:
            return None

    @name.setter
    def name(self, name):
        if not isinstance(name, (str, type(None))): raise exceptions.RevengeInvalidArgumentType("name must be of type str.")
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


from ..cpu.assembly import AssemblyInstruction, AssemblyBlock
from ..native_exception import NativeException
