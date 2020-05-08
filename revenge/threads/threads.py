
import logging
from prettytable import PrettyTable
import collections

from revenge import common
from revenge.exceptions import *

logger = logging.getLogger(__name__)


class Threads(object):

    def __init__(self, process):
        self._process = process

        # tid: list of exceptions, appended as they come in
        self._exceptions = collections.defaultdict(lambda: list())

        # tid: breakpoint_context to keep track of when we hit a breakpoint
        # and what the thread state is at that point
        self._breakpoint_context = {}

        # addr: bytes -- what bytes were in the binary at this location before
        # we overwrote them with stuff (like Frida Interceptor)
        self._breakpoint_original_bytes = {}

    def __len__(self):
        return len(self.threads)

    def __iter__(self):
        return iter(self.threads)

    def __repr__(self):
        return "<{} {}>".format(len(self), "Thread" if len(self) == 1 else "Threads")

    def __str__(self):
        table = PrettyTable(['id', 'state', 'pc', 'module', 'Trace', 'Breakpoint'])

        for thread in self:
            table.add_row([str(thread.id), thread.state,
                           self._process.memory.describe_address(thread.pc).split(":")[-1],
                           thread.module,
                           'Yes' if thread.trace is not None else 'No',
                           "Yes" if thread.breakpoint else "No"
                           ])

        return str(table)

    def __getitem__(self, elm):

        if type(elm) is int:
            try:
                return next(thread for thread in self.threads if thread.id == elm)
            except StopIteration:
                # If this is the Frida thread, it will be hidden. Create a dummy one
                if self._process.engine.run_script_generic(r"""send(Process.getCurrentThreadId())""", unload=True, raw=True)[0][0] == elm:
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
            revenge.threads.Thread: The new thread that was created or None if
            either the thread create failed or the thread finished before this
            method returned.

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

    @common.validate_argument_types(name=str)
    def _register_plugin(self, plugin, name):
        """Registers this plugin to be exposed as a thread plugin.

        Args:
            plugin (callable): A class constructor. Must take an argument for
                the current thread
            name (str): What will this be called?

        The plugin will be instantiated at most once per thread instance, and
        done only when referenced.

        Examples:
            .. code-block:: python

                class MyPlugin:
                    @classmethod
                    def _thread_plugin(klass, thread):
                        self = klass()
                        self._thread = module
                        return self

                process.threads._register_plugin(MyPlugin._thread_plugin, "myplugin")

                # This first call will instantiate the plugin
                process.threads[1234].myplugin
        """

        def getter(self):
            try:
                return getattr(self, "__" + name)
            except AttributeError:
                setattr(self, "__" + name, plugin(self))
                return getattr(self, "__" + name)

        if not callable(plugin):
            raise RevengeInvalidArgumentType("plugin must be callable")

        if name in Thread.__dict__:
            raise RevengeModulePluginAlreadyRegistered("Property name " + name + " is already taken.")

        # Add the new plugin
        setattr(Thread, name, property(getter, doc=plugin.__doc__))

    @property
    def threads(self):
        """Current snapshop of active threads."""
        threads = self._process.engine.run_script_generic(
            "send(Process.enumerateThreadsSync());",
            raw=True,
            unload=True)[0][0]
        return [Thread(self._process, thread) for thread in threads]


from . import Thread
from .create import create_thread
