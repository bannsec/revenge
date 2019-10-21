
import logging
logger = logging.getLogger(__name__)

from prettytable import PrettyTable

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
            table.add_row([str(thread.id), thread.state,
                self._process.memory.describe_address(thread.pc).split(":")[-1], thread.module, 'Yes' if thread.trace is not None else 'No'])

        return str(table)

    def __getitem__(self, elm):

        if type(elm) is int:
            try:
                return next(thread for thread in self.threads if thread.id == elm)
            except StopIteration:
                # If this is the Frida thread, it will be hidden. Create a dummy one
                if self._process.run_script_generic(r"""send(Process.getCurrentThreadId())""", unload=True, raw=True)[0][0] == elm:
                    return Thread(self._process, {'id': elm, 'state': 'waiting', 'context': {'pc': '0'}})
                logger.error("Invalid thread id selected.")

        else:
            logger.error("Not sure how to handle this.")

    @property
    def threads(self):
        """Current snapshop of active threads."""
        threads = self._process.run_script_generic("""send(Process.enumerateThreadsSync());""", raw=True, unload=True)[0][0]
        return [Thread(self._process, thread) for thread in threads]

from . import Thread
