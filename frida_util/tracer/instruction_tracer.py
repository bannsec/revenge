
import logging
logger = logging.getLogger(__name__)

import json
import collections
from termcolor import cprint, colored

from prettytable import PrettyTable

from .. import types, common
from ..threads import Thread

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

    def __str__(self):
        s =  colored("{: <10}".format(self.type), attrs=['bold'])
        from_ip = self.from_symbol or hex(self.from_ip)

        s += "{: <55}".format(colored(self.from_module,"magenta") + ":" + colored(from_ip, 'magenta', attrs=['bold']))

        if self.to_ip is not None:
            to_ip = self.to_symbol or hex(self.to_ip)
            s += "-> "
            s += "{: <55}".format(colored(self.to_module, "magenta") + ":" + colored(to_ip, "magenta", attrs=["bold"]))

        if self.depth is not None:
            s += str(self.depth)

        return s.strip()

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

    @property
    def from_symbol(self):
        """Attempts to resolve from_ip into a symbol. If it can, it returns the symbol name. Otherwise it returns None."""
        return self._process.modules.lookup_symbol(self.from_ip)
        try:
            #return self._process.modules._address_to_symbol[self.from_ip]
            return self._process.modules._address_to_symbol[self.from_ip]
        except KeyError:
            return None

    @property
    def to_symbol(self):
        """Attempts to resolve to_ip into a symbol. If it can, it returns the symbol name. Otherwise it returns None."""
        try:
            return self._process.modules._address_to_symbol[self.to_ip]
        except KeyError:
            return None


class Trace(object):
    """Keeps information about a Trace."""
    
    def __init__(self, process, tid, script, callback=None):
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
            self._process.run_script_generic("""Stalker.unfollow({})""".format(self._tid), raw=True, unload=True)
            self._script[0].unload()
            self._process.tracer._active_instruction_traces.pop(self._tid)
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
        return '\n'.join(str(i) for i in self)

    def __repr__(self):
        attr = ['Trace', 'Thread={}'.format(self._tid)]
        attr += [str(len(self)), 'items']

        return "<{}>".format(' '.join(attr))

    def __getitem__(self, item):
        return self._trace.__getitem__(item)

class InstructionTracer(object):

    def __init__(self, process, threads=None, from_modules=None, call=False,
            ret=False, exec=False, block=False, compile=False, callback=None):
        """

        Args:
            process: Base process instantiation
            threads (list, optional): What threads to trace. If None, it will trace all threads.
            from_modules (list, optional): Restrict trace returns to those that start from one of the listed modules.
            call (bool, optional): Trace calls
            ret (bool, optional): Trace rets
            exec (bool, optional): Trace all instructions
            block (bool, optional): Trace blocks
            compile (bool, optional): Trace on Frida instruction compile
            callback (callable, optional): Callable to call with list of new
                instructions as they come in. First arg will be the thread id.
        """

        assert callable(callback) or callback is None, "Invalid type for callback of {}".format(type(callback))

        # Santiy check
        if not any((call, ret, exec, block, compile)):
            error = "You didn't select any action to trace!"
            logger.error(error)
            #raise Exception(error)

        self._process = process
        self.call= call
        self.ret = ret
        self.exec = exec
        self.block = block
        self.compile = compile
        self.threads = threads
        self._script = {}
        self._from_modules = from_modules
        self.callback = callback

        # IMPORTANT: It's important to keep a local pointer to this trace. It's
        # possible for trace messages to come in after officially stopping the
        # trace. Using local dict in this way allows this trace to continue to
        # get information while still being stopped.
        self.traces = {}

        self._start()

    def _on_message(self, m, d):
        try:
            payload = m['payload']
        except:
            print(m)
            raise

        for x in payload:
            self.traces[x['tid']].append(x)

    def _start(self):

        replace = {
            "FROM_MODULES_HERE": json.dumps([module.name for module in self._from_modules]),
            "STALK_CALL": json.dumps(self.call),
            "STALK_RET": json.dumps(self.ret),
            "STALK_EXEC": json.dumps(self.exec),
            "STALK_BLOCK": json.dumps(self.block),
            "STALK_COMPILE": json.dumps(self.compile),
        }

        for thread in self.threads:
            replace['THREAD_ID_HERE'] = str(thread.id)
            self._process.run_script_generic("stalk.js", replace=replace, unload=False, on_message=self._on_message, runtime='v8')
            self.traces[thread.id] = Trace(self._process, thread.id, self._process._scripts.pop(0), callback=self.callback)
            self._process.tracer._active_instruction_traces[thread.id] = self.traces[thread.id]

    def __repr__(self):
        attrs = ["InstructionTracer"]
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
                if isinstance(thread, Thread):
                    threads_new.append(thread)
                elif isinstance(thread, int):
                    threads_new.append(self._process.threads[thread])
                else:
                    raise Exception("Unable to resolve requested thread of type {}".format(type(thread)))

            threads = threads_new

        # Make sure the threads aren't already being traced
        for thread in threads:
            if thread.id in self._process.tracer._active_instruction_traces:
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

from ..modules import Module
