
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import json
import collections
from termcolor import cprint, colored

from .. import types, common

class TraceItem(object):

    def __init__(self, util, item):
        self._util = util
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
        """
            print("{type: <10}{tid: <10}{module_from}:{module_from_offset} -> {module_to}:{module_to_offset} {depth}".format(
                type = type,
                tid = hex(tid),
                module_from = module_from,
                module_from_offset = hex(module_from_offset),
                module_to = module_to,
                module_to_offset = hex(module_to_offset),
                depth=depth
                ))
        """
        s =  colored("{: <10}".format(self.type), attrs=['bold'])
        s += "{: <55}".format(colored(self.from_module,"magenta") + ":" + colored(hex(self.from_ip), 'magenta', attrs=['bold']))

        if self.to_ip is not None:
            s += "-> "
            s += "{: <55}".format(colored(self.to_module, "magenta") + ":" + colored(hex(self.to_ip), "magenta", attrs=["bold"]))

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
    """Keeps information about a Trace."""
    
    def __init__(self, util):
        self._util = util
        self._trace = []

    def append(self, item):
        self._trace.append(TraceItem(self._util, item))

    def __iter__(self):
        return (x for x in self._trace)

    def __len__(self):
        return len(self._trace)

    def __str__(self):
        return str(self._trace)

    def __repr__(self):
        attr = ['Trace']
        attr += [str(len(self)), 'items']

        return "<{}>".format(' '.join(attr))

    def __getitem__(self, item):
        return self._trace.__getitem__(item)

class InstructionTracer(object):

    def __init__(self, util, threads=None, call=False, ret=False, exec=False, block=False, compile=False):
        """

        Args:
            util: Base util instantiation
            threads (list, optional): What threads to trace. If None, it will trace all threads.
            call (bool, optional): Trace calls
            ret (bool, optional): Trace rets
            exec (bool, optional): Trace all instructions
            block (bool, optional): Trace blocks
            compile (bool, optional): Trace on Frida instruction compile
        """

        self._util = util
        self.call= call
        self.ret = ret
        self.exec = exec
        self.block = block
        self.compile = compile
        self.threads = threads
        self._script = {}
        self.traces = collections.defaultdict(lambda: Trace(self._util))

        self._start()

    def _on_message(self, m, d):
        payload = m['payload']

        for x in payload:
            self.traces[x['tid']].append(x)

    def _start(self):

        # TODO: Implement modules then implement module downselect on trace

        replace = {
            "INCLUDE_MODULE_HERE": json.dumps([]),
            "STALK_CALL": json.dumps(self.call),
            "STALK_RET": json.dumps(self.ret),
            "STALK_EXEC": json.dumps(self.exec),
            "STALK_BLOCK": json.dumps(self.block),
            "STALK_COMPILE": json.dumps(self.compile),
        }

        for thread in self.threads:
            replace['THREAD_ID_HERE'] = str(thread.id)
            self._util.run_script_generic("stalk.js", replace=replace, unload=False, on_message=self._on_message)
            self._script[thread.id] = self._util._scripts.pop(0)

    def __del__(self):

        for thread in self.threads:
            self._util.run_script_generic("""Stalker.unfollow({})""".format(thread.id), raw=True, unload=True)

        for tid, script in self._script.items():
            script[0].unload()

        self._script = None

    def __repr__(self):
        attrs = ["InstructionTracer"]
        attrs += [str(len(self.threads)), 'threads']

        return "<{}>".format(' '.join(attrs))

    def __iter__(self):
        return self.traces.values().__iter__()

    @property
    def threads(self):
        """list: Threads that are being traced by this object."""
        return self.__threads

    @threads.setter
    def threads(self, threads):

        if threads is None:
            threads = list(self._util.threads)

        else:
            error = "Unhandled threads type of {}".format(type(threads))
            logger.error(error)
            raise Exception(error)

        self.__threads = threads
