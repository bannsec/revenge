
import logging
logger = logging.getLogger(__name__)

from prettytable import PrettyTable
import binascii
import operator
import struct
import inspect
from termcolor import cprint, colored

from ....memory import Memory

class FridaMemory(Memory):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._MemoryBytes = MemoryBytes
        self._MemoryFind = MemoryFind
        self._MemoryMap = MemoryMap

        # key == hash (see MemoryBytes), value = dict of cache values
        self._thread_call_cache = {}

    def alloc(self, size):

        assert type(size) is int

        pointer = common.auto_int(self._engine.run_script_generic("""var p = Memory.alloc(uint64('{}')); send(p);""".format(hex(size)), raw=True, unload=False)[0][0])
        script = self._engine._scripts.pop(0) # We want to hold on to it here

        self._allocated_memory[pointer] = script
        return MemoryBytes(self._engine, pointer, pointer+size)

    def create_c_function(self, func_str, **kwargs):
        """Compile and inject function from c string definition.

        Args:
            func_str (str): The string to compile and inject.
            **kwargs (optional): Keyword arguments will be used to expose
                other functions in the binary. See examples.

        Returns:
            revenge.memory.MemoryBytes: Instantitated object, ready for calling.

        Examples:
            .. code-block:: python3

                func = r"int add(int x, int y) { return x+y; }"
                add = process.memory.create_c_function(func)
                assert add(1,2) == 3

                # If we want to call "time", we need to call it dynamically at
                # runtime. kwargs are used to simplify this.
                time = process.memory[':time']
                time.argument_types = types.Int
                time.return_type = types.Int
                func = r"int do_time() { return time(0); }"
                do_time = process.memory.create_c_function(func, time=time)
                do_time()

                # OR
                strlen = process.memory[':strlen']

                strlen.argument_types = types.StringUTF8
                strlen.return_type = types.Int

                my_strlen = process.memory.create_c_function(r\"\"\"
                    int my_strlen(char *s) { return strlen(s); }
                    \"\"\", strlen=strlen)

                assert my_strlen("blerg") == 5
        """
        
        # q = p.memory.create_c_function(r"""int q2() { return ((int (*)(int)) 0x7fffde1caf10)(0); }""")
        # q = p.memory.create_c_function(r"""int (*t)(int) = (int (*)(int)) 0x7fffde1caf10;""") 
        # TODO: Integrate c parsing into this to discover and set arg and return types
        js = r"""var f = new CModule("{func}"); send(f);"""

        # Add in any runtime resolutions (such as function calls)
        for name, mem_bytes in kwargs.items():
            if not isinstance(mem_bytes, MemoryBytes):
                raise exceptions.RevengeInvalidArgumentType("Dynamic function calls must be of type MemoryBytes.")

            mem_bytes.name = name
            func_str = mem_bytes._dynamic_assembly_call_str + "\n" + func_str

        func_str = func_str.replace("\n", "\\\n")
        js = js.format(func=func_str.replace('"','\"'))

        logger.debug("CModule inject: " + js)
        out = self._engine.run_script_generic(js, raw=True, unload=False, runtime='v8')[0][0]
        
        ret = []
        for func_name, func_addr in out.items():
            # Ignoring our injected things
            if func_name in kwargs.keys():
                continue

            func_addr = common.auto_int(func_addr)
            logger.debug("Found injected function '{}' at '{}'".format(func_name, hex(func_addr)))
            ret.append(self._process.memory[func_addr])

        logger.warning("This method does not auto-set your function arguments or return type for you yet. Be aware.")

        if len(ret) == 1:
            return ret[0]

        return ret

from .... import common, types, symbols
from . import MemoryBytes, MemoryMap, MemoryFind
from ....exceptions import *

#Memory.find.__doc__ = MemoryFind.__init__.__doc__
