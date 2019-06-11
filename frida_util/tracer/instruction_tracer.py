
import logging
logging.basicConfig(level=logging.WARN)

import json
import collections

class Trace(object):
    """Keeps information about a Trace."""
    
    def __init__(self, util):
        self._util = util
        self._trace = []

    def append(self, item):
        self._trace.append(item)

    def __iter__(self):
        return (x for x in self._trace)

    def __len__(self):
        return len(self._trace)

    def __repr__(self):
        attr = ['Trace']
        attr += [str(len(self)), 'items']

        return "<{}>".format(' '.join(attr))

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

        for script in self._script.values():
            script[0].unload()

        self._script = None

    def __repr__(self):
        attrs = ["InstructionTracer"]
        attrs += [str(len(self.threads)), 'threads']

        return "<{}>".format(' '.join(attrs))

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
