
import logging
from ...process import Process as ProcessBase
from ... import common

class Process(ProcessBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.__frida_process_general_init()

        if self.device.platform == "linux":
            self.__frida_process_linux_init()

        self.__stdout = b""
        self.__stderr = b""
        self._stdout_echo = False
        self._stderr_echo = False
        self.engine._frida_device.on('output', self.__fd_cb)

    def __handle_process_exception(self, data, msg):

        def cleanup():
            self.memory[wait_for].int8 = 1

        assert data['type'] == 'send', "Unexpected type of " + data['type']
        assert 'payload' in data, "No payload found in data."

        exception = data['payload']
        wait_for = common.auto_int(exception['wait_for'])
        thread_id = exception['thread_id']

        native_exception = NativeException._from_frida_dict(self, exception, [])

        # Append this to the appropriate thread
        # NOTE: For whatever reason, anything that attempts to interact with frida at this point in execution will hang...
        self.threads._exceptions[thread_id].append(native_exception)

        LOGGER.warning("Caught exception in thread {thread} of type {type} at {at}.\n\tView with process.threads[{thread}].exceptions[-1]".format(
            thread=thread_id,
            type=exception['type'],
            at=exception['address'],
        ))

        # Make sure this auto-cleans up on exit
        self._register_cleanup(cleanup)

    def __frida_process_general_init(self):
        """General purpose frida initializations."""

        # TODO: Optionally specify which signals to allow (such as int3)
        self.engine.run_script_generic("exception_handler.js", unload=False, runtime='v8', on_message=self.__handle_process_exception, timeout=0,
                include_js=["dispose.js", "send_batch.js", "telescope.js", "timeless.js"])

    def __frida_process_linux_init(self):
        """Setup stuff specifically for Frida process on linux."""

        stdout = self.memory['stdout']
        setbuf = self.memory['setbuf']

        # Unbuffer stdout
        setbuf(stdout.pointer, 0)

    def __fd_cb(self, pid, fd, data):

        if pid != self.pid:
            return

        if fd == 1:
            if self._stdout_echo:
                print(data.decode('utf-8'), end='', flush=True)

            else:
                self.__stdout += data

        elif fd == 2:
            if self._stderr_echo:
                print(data.decode('utf-8'), end='', flush=True)

            else:
                self.__stderr += data

        else:
            LOGGER.warning("Unhandled fd callback: fd == " + hex(fd))

    @common.validate_argument_types(thing=(str, bytes))
    def stdin(self, thing):
        thing = common.auto_bytes(thing)
        self.engine._frida_device.input(self.pid, thing)

    @common.validate_argument_types(n=(int, str, bytes))
    def stderr(self, n=0):

        if n == 0:
            ret = self.__stderr
            self.__stderr = b""
            return ret
        
        # String acts as an expect
        if isinstance(n, (str, bytes)):
            n = common.auto_bytes(n)
            # TODO: Might be more efficient to use try/except...
            while n not in self.__stderr: sleep(0.01)
            index = self.__stderr.index(n) + len(n)
            ret = self.__stderr[:index]
            self.__stderr = self.__stderr[index:]
            return ret

        else:
            # n is an int. take that much
            ret = self.__stderr[:n]
            self.__stderr = self.__stderr[n:]
            return ret

    @common.validate_argument_types(n=(int, str, bytes))
    def stdout(self, n=0):

        if n == 0:
            ret = self.__stdout
            self.__stdout = b""
            return ret
        
        # String acts as an expect
        if isinstance(n, (str, bytes)):
            n = common.auto_bytes(n)
            # TODO: Might be more efficient to use try/except...
            while n not in self.__stdout: sleep(0.01)
            index = self.__stdout.index(n) + len(n)
            ret = self.__stdout[:index]
            self.__stdout = self.__stdout[index:]
            return ret

        else:
            # n is an int. take that much
            ret = self.__stdout[:n]
            self.__stdout = self.__stdout[n:]
            return ret

    def interactive(self):
        old_stdout_echo = self._stdout_echo
        self._stdout_echo = True

        # TODO: Update this so that stdout doesn't clobber stderr and vice vera..
        old_stderr_echo = self._stderr_echo
        self._stderr_echo = True

        # Flush out stdout buffer
        #print(self.stdout('all').decode('utf-8'), end="", flush=True)
        print(self.stdout().decode('utf-8'), end="", flush=True)

        # TODO: Maybe change this to single char get and send at some point?
        while True:
            try:
                thing = prompt_toolkit.prompt()
                self.stdin(thing + "\n")
            except KeyboardInterrupt:
                break

        self._stdout_echo = old_stdout_echo
        self._stderr_echo = old_stderr_echo

from time import sleep
import prompt_toolkit
from ...exceptions import *
from ...native_exception import NativeException

LOGGER = logging.getLogger(__name__)
