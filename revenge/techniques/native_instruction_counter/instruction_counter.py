
import logging

import json
from prettytable import PrettyTable

from revenge import types
from ...threads import Thread
from .. import Technique

logger = logging.getLogger(__name__)
NoneType = type(None)


class NativeInstructionCounter(Technique):
    TYPE = "stalk"

    def __init__(self, process, from_modules=None, call=False, ret=False,
                 exec=False, block=False, compile=False, exclude_ranges=None):
        """Counts instructions executed.

        Args:
            process: Base process instantiation
            from_modules (list, optional): Restrict counting to those
                instructions that start from one of the listed modules.
            call (bool, optional): Count calls
            ret (bool, optional): Count rets
            exec (bool, optional): Count all instructions
            block (bool, optional): Count blocks
            compile (bool, optional): Count Frida instruction compile
            exclude_ranges (list, optional): [low, high] range pairs to exclude
                any trace items from.

        Examples:
            .. code-block:: python3

                # With no args, it will count individual assembly instructions
                # executed
                counter = process.techniques.NativeInstructionCounter()

                # Need to apply it to use it
                counter.apply()

                # Resume the process to get execution going again
                process.resume()

                # Some point later, print out the count
                print(counter)

                ### Can also be used as technique for specific call
                strlen = process.memory["strlen"]
                counter = process.techniques.NativeInstructionCounter()
                strlen("hello", techniques=counter)
                print(counter)
        """

        # Default to counting all instructions
        if not any((call, ret, exec, block, compile)):
            exec = True

        self._process = process
        self.call = call
        self.ret = ret
        self.exec = exec
        self.block = block
        self.compile = compile
        self._from_modules = from_modules
        self._exclude_ranges = exclude_ranges or []

        self.counts = {}

    def _on_message(self, m, d):
        try:
            payload = m['payload']
        except Exception:
            logger.error("Payload not found in this message: %s", m)
            raise

        for x in payload:
            self.counts[x['tid']].count = x['count']

    def apply(self, threads=None):
        self.threads = threads
        self._start()

    def _start(self):

        replace = {
            "FROM_MODULES_HERE": json.dumps([module.name for module in self._from_modules]),
            "EXCLUDE_RANGES_HERE": json.dumps(self._exclude_ranges_js),
            "STALK_CALL": json.dumps(self.call),
            "STALK_RET": json.dumps(self.ret),
            "STALK_EXEC": json.dumps(self.exec),
            "STALK_BLOCK": json.dumps(self.block),
            "STALK_COMPILE": json.dumps(self.compile),
        }

        for thread in self.threads:
            s = "instruction_count({})".format(thread.id)
            self._process.engine.run_script_generic(
                s, raw=True, include_js=("dispose.js", "send_repeat.js", "instruction_count.js"),
                replace=replace, unload=False, on_message=self._on_message, runtime='v8')
            self.counts[thread.id] = Counter(thread, self._process.engine._scripts.pop(0))
            self._process.techniques._active_stalks[thread.id] = self.counts[thread.id]

    def remove(self):
        for thread in self.threads:
            if thread.trace is not None:
                thread.trace.stop()

    def _technique_code_range(self, range):
        # We want to ignore anything we know to not be target code.
        self._exclude_ranges.append([range.base, range.base + range.size])

    def __repr__(self):
        attrs = ["NativeInstructionCounter"]
        attrs += [str(len(self.threads)), 'threads']

        return "<{}>".format(' '.join(attrs))

    def __iter__(self):
        return self.counts.values().__iter__()

    def __str__(self):
        table = PrettyTable(['tid', 'count'])

        for tid, count in self.counts.items():
            table.add_row([str(tid), str(count.count)])

        return str(table)

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


from revenge.modules import Module
from .counter import Counter
NativeInstructionCounter.__doc__ = NativeInstructionCounter.__init__.__doc__
