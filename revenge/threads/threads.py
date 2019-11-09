
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

        elif isinstance(elm, Thread):
            return elm

        else:
            logger.error("Not sure how to handle this.")


    def create(self, callback):
        """Create and start a new thread on the given callback.

        Args:
            callback: Pointer to function to start the thread on. This can be
                created via CModule, NativeCallback or use an existing
                function in the binary

        Returns:
            revenge.threads.Thread: The new thread that was created or None if either the thread create failed or the thread finished before this method returned.

        Example:
            .. code-block:: python3

                # Create a stupid callback that just spins
                func = process.memory.create_c_function("void func() { while ( 1 ) { ; } }")

                # Start the thread
                t = process.threads.create(func.address)
                assert isinstance(t, revenge.threads.thread.Thread)

                # View it running
                print(process.threads)

                # Grab the return value (in this case the thread won't end though)
                return_val = t.join()
        """

        pre = set([t.id for t in self])
        out = create_thread(self._process, callback)
        post = set([t.id for t in self])

        diff = post.difference(pre)
        if diff != {}:
            diff = list(diff)

            if len(diff) == 0:
                # It may just already be done... Not necessarily an error
                # Create a mock thread
                new_thread = Thread(self._process, {'context': {'pc': "0x0"}, 'id': 0, 'state': 'completed'})
            elif len(diff) > 1:
                logger.warning("More than one thread has been created... Returning first.")

            else:
                new_thread = self[diff[0]]

            if self._process.device_platform == 'linux':
                new_thread.pthread_id = out

            return new_thread

    @property
    def threads(self):
        """Current snapshop of active threads."""
        threads = self._process.run_script_generic("""send(Process.enumerateThreadsSync());""", raw=True, unload=True)[0][0]
        return [Thread(self._process, thread) for thread in threads]

from . import Thread
from .create import create_thread
