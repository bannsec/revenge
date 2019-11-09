
import logging
logger = logging.getLogger(__name__)

import time
import json
import collections
from termcolor import cprint, colored
from prettytable import PrettyTable

from ... import types, common
from ...threads import Thread
from .. import Technique

class TraceItem(object):

    def __init__(self, process, item):
        self._process = process
        self._item = item
        self.from_ip = None
        self.from_module = None
        self.to_ip = None
        self.to_module = None
        self.type = None
        self.depth = None

        self._parse_item(item)

    def _parse_item(self, item):

        # Common
        self.type = item['type']
        self.from_ip = types.Pointer(common.auto_int(item['from_ip']))
        self.from_module = item['from_module']

        if 'to_ip' in item:
            self.to_ip = types.Pointer(common.auto_int(item['to_ip']))

        if 'to_module' in item:
            self.to_module = item['to_module']

        if 'depth' in item:
            self.depth = common.auto_int(item['depth'])

    def _str_add_table_row(self, table):
        
        if self.depth is not None:
            indent = ' '*self.depth
        else:
            indent = ''

        table.add_row([
            colored(self.type, attrs=['bold']),
            indent + self._process.memory.describe_address(self.from_ip, color=True),
            indent + self._process.memory.describe_address(self.to_ip, color=True) if self.to_ip is not None else "",
            str(self.depth) if self.depth is not None else ""
            ])

    def __str__(self):

        table = PrettyTable(['Type', 'From', 'To', 'Depth'])
        table.border = False
        table.header = False

        self._str_add_table_row(table)

        return str(table)

    def __repr__(self):
        attrs = ["TraceItem"]
        attrs.append(hex(self.from_ip))
        attrs.append(self.type)

        return "<{}>".format(' '.join(attrs))

    @property
    def type(self):
        return self.__type

    @type.setter
    def type(self, t):
        assert isinstance(t, (str, type(None))), "Invalid type for type of {}".format(type(t))

        if t is None:
            self.__type = None
            return

        t = t.lower()

        if t not in ['call', 'ret', 'exec', 'block', 'compile']:
            logger.error("Unhandled traceitem type of {}".format(t))
            logger.error(str(self._item))
            return

        self.__type = t



class Trace(object):
    
    def __init__(self, process, tid, script, callback=None):
        """Keeps information about a Trace.
        
        Args:
            process (revenge.Proces): revenge process object
            tid (int): Thread ID for this trace
            script: The associated script of this trace from run_script_generic
            callback (callable, optional): A callable to call when new trace
                items are collected
        """
        self._process = process
        self._trace = []
        self._tid = tid
        self._script = script
        self._callback = callback

    def append(self, item):
        ti = TraceItem(self._process, item)
        self._trace.append(ti)

        if self._callback is not None:
            self._callback(self._tid, ti)

    def stop(self):
        """Stop tracing."""

        if self._script is not None:
            # TODO: Why the hell is Frida freezing on attempting to unload the stalker script?
            # Must unfollow a Stalked thread in the SAME CONTEXT IT IS STALKING! Thus the RPC export here.
            self._script[0].exports.unfollow()
            # TODO: Add unload back in once it doesn't take forever for it to unload the script...
            # Until then, calling unfollow and not unloading the script seems to be OK.
            #time.sleep(1)
            #self._script[0].unload()
            self._process.techniques._active_stalks.pop(self._tid)
            self._script = None

    def wait_for(self, address):
        """Don't return until the given address is hit in the trace."""
        address = self._process._resolve_location_string(address)

        # TODO: Optimize this so I don't keep checking the same IPs over and over
        while True:
            try:
                next(x for x in self._trace if x.from_ip == address)
                break
            except StopIteration:
                continue
        
    def __iter__(self):
        return (x for x in self._trace)

    def __len__(self):
        return len(self._trace)

    def __str__(self):
        table = PrettyTable(['Type', 'From', 'To', 'Depth'])
        table.border = False
        table.header = False
        table.align = 'l'

        depth = 0

        for i in self:
            # Implicitly assign depths
            if i.depth is None:
                i.depth = depth
            
            i._str_add_table_row(table)

            if i.type == 'call':
                depth = i.depth + 1
            elif i.type == 'ret':
                depth = i.depth - 1

        return str(table)

    def __repr__(self):
        attr = ['Trace', 'Thread={}'.format(self._tid)]
        attr += [str(len(self)), 'items']

        return "<{}>".format(' '.join(attr))

    def __getitem__(self, item):

        if isinstance(item, int):
            return self._trace.__getitem__(item)

        if isinstance(item, slice):
            ret = Trace(self._process, self._tid, script=None)
            ret._trace = self._trace[item]
            return ret

        raise Exception("Unhandled getitem type of {}".format(type(item)))

class NativeInstructionTracer(Technique):
    TYPE = "stalk"

    def __init__(self, process, from_modules=None, call=False, ret=False,
                 exec=False, block=False, compile=False, callback=None,
                 exclude_ranges=None, include_function=None):
        """

        Args:
            process: Base process instantiation
            from_modules (list, optional): Restrict trace returns to those that start from one of the listed modules.
            call (bool, optional): Trace calls
            ret (bool, optional): Trace rets
            exec (bool, optional): Trace all instructions
            block (bool, optional): Trace blocks
            compile (bool, optional): Trace on Frida instruction compile
            callback (callable, optional): Callable to call with list of new
                instructions as they come in. First arg will be the thread id.
            exclude_ranges (list, optional): [low, high] range pairs to exclude
                any trace items from.
            include_function (optional): resolvable function name or
                memorybytes object. starts tracing when function is entered
                and stops tracing when function is exited (call/ret)

        Examples:
            .. code-block:: python3

                #
                # Trace all instructions in process except for those in a given range
                # Apply this to the entire program execution
                #

                trace = process.techniques.NativeInstructionTracer(exec=True, exclude_ranges=[[0x12345, 0x424242]])

                # Apply this to the whole program and run
                trace.apply()
                process.memory[process.entrypoint].breakpoint = False

                # Print out the trace
                print(trace)

                #
                # Trace only blocks starting from a given function call downwards.
                # Utilize this technique only on a specific call, rather than full program execution
                #

                trace = process.techniques.NativeInstructionTracer(exec=True, include_function='my_func')
                # or
                my_func = process.memory['my_func']
                trace = process.techniques.NativeInstructionTracer(exec=True, include_function=my_func)

                my_func(1,2,3, techniques=trace)

                # Trace object should be populated now
                print(trace)
        """

        assert callable(callback) or callback is None, "Invalid type for callback of {}".format(type(callback))

        # Santiy check
        if not any((call, ret, exec, block, compile)):
            error = "You didn't select any action to trace!"
            logger.error(error)

        self._process = process
        self.call = call
        self.ret = ret
        self.exec = exec
        self.block = block
        self.compile = compile
        self.threads = []
        self._script = {}
        self._from_modules = from_modules
        self.callback = callback
        self._exclude_ranges = exclude_ranges or []
        self._include_function = include_function

        # IMPORTANT: It's important to keep a local pointer to this trace. It's
        # possible for trace messages to come in after officially stopping the
        # trace. Using local dict in this way allows this trace to continue to
        # get information while still being stopped.
        self.traces = {}

    def _on_message(self, m, d):
        try:
            payload = m['payload']
        except:
            print(m)
            raise

        for x in payload:
            #self.traces[x['tid']].append(x)
            for y in x:
                self.traces[y['tid']].append(y)

    def apply(self, threads=None):
        self.threads = threads
        self._start()

    def _start(self):

        replace = {
            "FROM_MODULES_HERE": json.dumps([module.name for module in self._from_modules]),
            "STALK_CALL": json.dumps(self.call),
            "STALK_RET": json.dumps(self.ret),
            "STALK_EXEC": json.dumps(self.exec),
            "STALK_BLOCK": json.dumps(self.block),
            "STALK_COMPILE": json.dumps(self.compile),
            "EXCLUDE_RANGES_HERE": json.dumps(self._exclude_ranges_js),
            "INCLUDE_FUNCTION_HERE": self._include_function.address.js if self._include_function is not None else "null",
        }

        for thread in self.threads:
            s = "stalker_follow({})".format(thread.id)
            self._process.run_script_generic(s, raw=True, include_js=("dispose.js", "send_batch.js", "stalk.js"), replace=replace, unload=False, on_message=self._on_message, runtime='v8')
            self.traces[thread.id] = Trace(self._process, thread.id, self._process._scripts.pop(0), callback=self.callback)
            self._process.techniques._active_stalks[thread.id] = self.traces[thread.id]

    def remove(self):
        for thread in self.threads:
            if thread.trace is not None:
                thread.trace.stop()

    def _technique_code_range(self, range):
        # We want to ignore anything we know to not be target code.
        self._exclude_ranges.append( [ range.base, range.base + range.size ])

    def __repr__(self):
        attrs = ["NativeInstructionTracer"]
        attrs += [str(len(self.threads)), 'threads']

        return "<{}>".format(' '.join(attrs))

    def __iter__(self):
        return self.traces.values().__iter__()

    def __str__(self):
        table = PrettyTable(['tid', 'count'])

        for tid, trace in self.traces.items():
            table.add_row([str(tid), str(len(trace))])

        return str(table)

    @property
    def threads(self):
        """list: Threads that are being traced by this object."""
        return self.__threads

    @threads.setter
    def threads(self, threads):
        assert isinstance(threads, (type(None), list, tuple, Thread)), "Invalid threads type of {}".format(type(threads))

        if threads is None:
            threads = list(self._process.threads)

        if not isinstance(threads, (list, tuple)):
            threads = [threads]

        else:
            threads_new = []
            for thread in threads:
                threads_new.append(self._process.threads[thread])

            threads = threads_new

        # Make sure the threads aren't already being traced
        for thread in threads:
            if thread.id in self._process.techniques._active_stalks:
                error = "Cannot have more than one trace on the same thread at a time. Stop the existing trace with: process.threads[{}].trace.stop()".format(thread.id)
                logger.error(error)
                raise Exception(error)

        self.__threads = threads

    @property
    def _from_modules(self):
        """list,tuple,str,Module,None: What modules to restrict tracing from. Items can be strings (which will resolve) or Module objects."""
        return self.__from_modules

    @_from_modules.setter
    def _from_modules(self, modules):

        assert isinstance(modules, (list, tuple, type(None), str, Module)), "Unsupported type for from_modules of {}".format(type(modules))
        
        if modules is None:
            self.__from_modules = []
            return
        
        if not isinstance(modules, (list, tuple)):
            modules = [modules]

        new_modules = []
        for module in modules:
            if isinstance(module, Module):
                new_modules.append(module)
            elif isinstance(module, str):
                new_modules.append(self._process.modules[module])
            else:
                error = "Unsupported type for module of {}".format(type(module))
                logger.error(error)
                raise Exception(error)
        
        self.__from_modules = new_modules

    @property
    def _exclude_ranges(self):
        return self.__exclude_ranges

    @_exclude_ranges.setter
    def _exclude_ranges(self, ranges):
        if ranges is None:
            self.__exclude_ranges = []

        elif not isinstance(ranges, (list, tuple)):
            raise RevengeInvalidArgumentType("_exclude_ranges must be a tuple or list of lists.")

        else:
            self.__exclude_ranges = ranges

    @property
    def _exclude_ranges_js(self):
        ranges = []
        
        # Turn ranges into ptrs
        for low, high in self._exclude_ranges:
            ranges.append([types.Pointer(low).js, types.Pointer(high).js])

        return ranges

    @property
    def _include_function(self):
        """revenge.memory.MemoryBytes: Function that we should specifically trace."""
        return self.__include_function

    @_include_function.setter
    def _include_function(self, function):

        if function is None:
            self.__include_function = None
            return

        # Assume we need to resolve this
        if isinstance(function, str):
            f = self._process.memory[function]

            if f is None:
                logger.error("Couldn't resolve {}".format(function))
                return

            function = f

        if not isinstance(function, MemoryBytes):
            logger.error("Unhandled function of {}".format(function))
            return

        self.__include_function = function


NativeInstructionTracer.__doc__ = NativeInstructionTracer.__init__.__doc__

from ...modules import Module
from ...exceptions import *
from ...memory.memory_bytes import MemoryBytes
