
from ...process import Process as ProcessBase
from ... import common

class Process(ProcessBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.device.platform == "linux":
            self.__frida_process_linux_init()

        self.__stdout = b""
        self.__stderr = b""
        self._stdout_echo = False
        self._stderr_echo = False
        self.engine._frida_device.on('output', self.__fd_cb)

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

    @common.validate_argument_types(thing=(str, bytes))
    def stdin(self, thing):
        if isinstance(thing, str):
            thing = thing.encode('latin-1')

        self.engine._frida_device.input(self.pid, thing)

    @common.validate_argument_types(n=(int, str))
    def stderr(self, n):
        
        if isinstance(n, str):
            if n.lower() == "all":
                ret = self.__stderr
                self.__stderr = b""
                return ret
            else:
                raise RevengeInvalidArgumentType("Only valid string is 'all'")

        ret = self.__stderr[:n]
        self.__stderr = self.__stderr[n:]
        return ret

    @common.validate_argument_types(n=(int, str))
    def stdout(self, n):
        
        if isinstance(n, str):
            if n.lower() == "all":
                ret = self.__stdout
                self.__stdout = b""
                return ret
            else:
                raise RevengeInvalidArgumentType("Only valid string is 'all'")

        ret = self.__stdout[:n]
        self.__stdout = self.__stdout[n:]
        return ret

    def interactve(self):
        old_stdout_echo = self._stdout_echo
        self._stdout_echo = True

        # TODO: Update this so that stdout doesn't clobber stderr and vice vera..
        old_stderr_echo = self._stderr_echo
        self._stderr_echo = True

        # Flush out stdout buffer
        print(self.stdout('all').decode('utf-8'), end="", flush=True)

        # TODO: Maybe change this to single char get and send at some point?
        while True:
            try:
                thing = prompt_toolkit.prompt()
                self.stdin(thing + "\n")
            except KeyboardInterrupt:
                break

        self._stdout_echo = old_stdout_echo
        self._stderr_echo = old_stderr_echo

import prompt_toolkit
from ...exceptions import *
