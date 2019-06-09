
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

from prettytable import PrettyTable

from . import common

class Thread(object):

    def __init__(self, util, info):
        self._util = util
        self._info = info

    def __repr__(self):
        return "<Thread {tid} @ {pc} {state} ({module})>".format(
                tid=hex(self.id),
                pc=hex(self.pc),
                state=self.state,
                module=self.module,
                )

    def __getattr__(self, elm):
        return common.auto_int(self._info['context'][elm])

    def __str__(self):

        table = PrettyTable(['attr', 'value'])

        table.add_row(['TID', str(self.id)])
        table.add_row(["State", self.state])
        table.add_row(["Module", self.module])

        for reg in self._info['context']:
            table.add_row([reg, hex(getattr(self, reg))])
        
        table.header = False
        table.align = "l"
        return str(table)


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
        return self._util.get_module_by_addr(self.pc)


class Threads(object):

    def __init__(self, util):
        self._util = util

    def __len__(self):
        return len(self.threads)

    def __iter__(self):
        return iter(self.threads)

    def __repr__(self):
        return "<{} {}>".format(len(self), "Thread" if len(self) == 1 else "Threads")

    def __str__(self):
        table = PrettyTable(['id', 'state', 'pc', 'module'])

        for thread in self:
            table.add_row([str(thread.id), thread.state, hex(thread.pc), thread.module])

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
        threads = self._util.run_script_generic("""send(Process.enumerateThreadsSync());""", raw=True, unload=True)[0][0]
        return [Thread(self._util, thread) for thread in threads]
