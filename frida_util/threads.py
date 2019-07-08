
import logging
logger = logging.getLogger(__name__)

from prettytable import PrettyTable

from . import common

class Thread(object):

    def __init__(self, process, info):
        self._process = process
        self._info = info
        self.context = Context(self._process, **self._info['context'])

    def __repr__(self):
        attrs = ['Thread', hex(self.id), '@', hex(self.pc), self.state, self.module]
        if self.trace is not None:
            attrs.append('tracing')
        return "<{}>".format(' '.join(attrs))

    def __getattr__(self, elm):
        return common.auto_int(self._info['context'][elm])

    def __str__(self):

        table = PrettyTable(['attr', 'value'])

        table.add_row(['TID', str(self.id)])
        table.add_row(["State", self.state])
        table.add_row(["Module", self.module])
        table.add_row(["Tracing?", "Yes" if self.trace is not None else "No"])

        """
        for reg in self._info['context']:
            table.add_row([reg, hex(getattr(self, reg))])
        
        """
        table.header = False
        table.align = "l"

        return str(table) + '\n' + str(self.context)


    @property
    def id(self):
        return self._info['id']

    @property
    def state(self):
        return self._info['state']

    @property
    def pc(self):
        return int(self._info['context']['pc'],16)

    @property
    def module(self):
        return self._process.get_module_by_addr(self.pc) or "Unknown"
    
    @property
    def trace(self):
        """Trace or None: Returns Trace object if this thread is currently being traced, otherwise None."""
        if self.id in self._process.tracer._active_instruction_traces:
            return self._process.tracer._active_instruction_traces[self.id]


class Threads(object):

    def __init__(self, process):
        self._process = process

    def __len__(self):
        return len(self.threads)

    def __iter__(self):
        return iter(self.threads)

    def __repr__(self):
        return "<{} {}>".format(len(self), "Thread" if len(self) == 1 else "Threads")

    def __str__(self):
        table = PrettyTable(['id', 'state', 'pc', 'module', 'Trace'])

        for thread in self:
            table.add_row([str(thread.id), thread.state, hex(thread.pc), thread.module, 'Yes' if thread.trace is not None else 'No'])

        return str(table)

    def __getitem__(self, elm):

        if type(elm) is int:
            try:
                return next(thread for thread in self.threads if thread.id == elm)
            except StopIteration:
                logger.error("Invalid thread id selected.")

        else:
            logger.error("Not sure how to handle this.")

    @property
    def threads(self):
        threads = self._process.run_script_generic("""send(Process.enumerateThreadsSync());""", raw=True, unload=True)[0][0]
        return [Thread(self._process, thread) for thread in threads]

from frida_util.tracer.contexts import Context
