
from . import Colorer
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import frida
import colorama
colorama.init()

import os
import sys
from termcolor import cprint, colored
from prettytable import PrettyTable
import time

import atexit
import signal
import json
import pprint
import collections

import importlib
from . import common

here = os.path.dirname(os.path.abspath(__file__))

class Process(object):

    def __init__(self, target, resume=False, verbose=False, load_symbols=None,
                 envp=None, engine=None):
        """Represents a process.
        
        Args:
            target (str, int, list): File name or pid to attach to. If target
                is a list, it will be set as argv.
            resume (bool, optional): Resume the binary if need be after loading?
            verbose (bool, optional): Enable verbose logging
            load_symbols (list, optional): Only load symbols from those modules
                in the list. Saves some startup time. Can use glob ('libc*')
            envp (dict, optional): Specify what you want the environment
                pointer list to look like. Defaults to whatever the current
                envp is.
            engine (revenge.engines.Engine): Instantiated Engine for this
                process

        Examples:
            .. code-block:: python3

                # Kick off ls
                p = revenge.Process("/bin/ls")

                # Kick off ls for /tmp with custom environment
                p = revenge.Process(["/bin/ls","/tmp/"], envp={'var1':'thing1'})

                #
                # Interaction
                #

                # Write to stdin
                p.stdin(b"hello\n")

                # Read from stdout
                p.stdout(16)

                # Read up to expected output in stdout
                p.stdout("expected")

                # Interact like a shell
                p.interactive()
        """

        self.__engine = engine
        self.__file_name = None
        self.__file_type = None
        self.__entrypoint = None
        self._resume_addr = None
        self.__endianness = None
        self.__bits = None
        self._spawn_target = None
        self.verbose = verbose
        self._envp = envp
        self.target = target
        self._registered_cleanup = []

        if not isinstance(load_symbols, (list, type, type(None))):
            load_symbols = [load_symbols]
        self._load_symbols = load_symbols

        #self.memory = self.engine.memory.Memory(self)
        self.memory = self.engine.memory
        self.threads = Threads(self)
        self.modules = Modules(self)
        self.techniques = Techniques(self)

        atexit.register(self._at_exit)
        self.engine.start_session()
        self._register_plugins()

        # TODO: move this into frida engine
        # ELF binaries start up in ptrace, which causes some issues, shim at entrypoint so we can remove ptrace
        if self._spawned_pid is not None and self.file_type == 'ELF':

            # Set breakpoint at entry
            self.memory[self.entrypoint].breakpoint = True

            # Set breakpoints at exit calls
            for c in [':exit', ':_exit']:
                self.memory[c].breakpoint = True

            # Resume to remove ptrace
            self.engine.resume(self._spawned_pid)

        if self.device_platform == 'linux':
            try:
                str(self.threads)
            except IndexError:
                logger.error("Can't enumerate threads. Please check sysctl kernel.yama.ptrace_scope=0 or run as root.")

        # Resume file if need be
        if resume:

            # If we are using a resume variable
            if self.memory[self.entrypoint].breakpoint:
                self.memory[self.entrypoint].breakpoint = False
            
            else:
                self.engine.resume(self._spawned_pid)

    def _register_plugins(self):
        """Figures out which plugins to load and loads them."""

        for plugin_name in dir(self.engine.plugins):
            if plugin_name.startswith("_"):
                continue

            plugin_mod = getattr(self.engine.plugins, plugin_name)

            for item, value in plugin_mod.__dict__.items():

                if inspect.isclass(value) and issubclass(value, Plugin):

                    # Instantiate the plugin
                    plugin = value(self)

                    if plugin._is_valid:
                        setattr(self, item.lower(), plugin)

    def quit(self):
        """Call to quit your session without exiting. Do NOT continue to use this object after.
        
        If you spawned the process, it will be killed. If you attached to the
        process, frida will be cleaned out, detatched, and the process should
        continue normally.
        """
        for c in self._registered_cleanup:
            c()
        self._at_exit()

    def _register_cleanup(self, c):
        self._registered_cleanup.append(c)

    def _at_exit(self):
        """Called to clean-up at exit."""
        self.engine._at_exit()

    def target_type(self, x):
        # Maybe it's PID
        try:
            return int(x)

        # Probably process name
        except:
            return x

    @common.implement_in_engine()
    def stdout(self, n):
        """Read n bytes from stdout.
        
        Args:
            n (int, str, bytes): Number of bytes to read or string to expect.
                If no value is given, it's presumed you are trying to read 
                all currently queued output.

        Returns:
            bytes: Output of stdout
        """
        pass

    @common.implement_in_engine()
    def stderr(self, n):
        """Read n bytes from stderr.
        
        Args:
            n (int, str, bytes): Number of bytes to read or string to expect.
                If no value is given, it's presumed you are trying to read 
                all currently queued output.

        Returns:
            bytes: Output of stderr
        """
        pass

    @common.implement_in_engine()
    def stdin(self, thing):
        """Write thing to stdin.
        
        Args:
            thing (str, bytes): If str, it will be encoded as latin-1.

        Note: There's no newline auto appended. Remember to add one if you want it.
        """
        pass

    @common.implement_in_engine()
    def interactive(self):
        """Go interactive. Return back to your shell with ctrl-c."""
        pass

    def __repr__(self):
        attrs = ['Process', self.file_name + ":" + str(self.pid)]
        return '<' + ' '.join(attrs) + '>'

    ############
    # Property #
    ############

    @property
    def argv(self):
        """list: argv for this process instantitation."""
        return self.__argv

    @argv.setter
    @common.validate_argument_types(argv=(list, tuple))
    def argv(self, argv):
        self.__argv = argv

    @property
    def device_platform(self):
        """Wrapper to discover the device's platform."""

        self.device_platform = self.engine.run_script_generic(r"send(Process.platform)", raw=True, unload=True)[0][0]
        return self.__device_platform

    @device_platform.setter
    def device_platform(self, platform):
        self.__device_platform = platform

    @property
    def pid(self):
        return self.engine.session._impl.pid

    @property
    def entrypoint(self):
        """int: Returns the entrypoint for this running program."""
        mod = self.modules[self.file_name]

        if self.__entrypoint is None:
            if self.file_type == 'ELF':
                self.__entrypoint = self.memory[mod.base+0x18].pointer
                
                if mod.elf.type_str == 'DYN':
                    self.__entrypoint = self.__entrypoint + mod.base

            else:
                logger.warn('entrypoint not implemented for file of type {}'.format(self.file_type))
                return None
            
        # TODO: Windows?
        # TODO: Mac?

        return self.__entrypoint

    @property
    def endianness(self):
        """Determine which endianness this binary is. (little, big)"""

        if self.__endianness != None:
            return self.__endianness

        if self.device_platform == 'windows':
            # TODO: Technically assumption, but like 99% of the time it's right.
            self.__endianness = 'little'

        elif self.file_type == 'ELF':
            endianness = self.engine.run_script_generic("""send(ptr(Number(Process.enumerateModulesSync()[0].base) + 5).readS8())""", raw=True, unload=True)[0][0]
            self.__endianness = 'little' if endianness == 1 else 'big'

        else:
            logger.warn("Unhandled endianness check for ({}, {}), assuming little".format(self.file_type, self.device_platform))

        return self.__endianness

    @property
    def file_type(self):
        """Guesses the file type."""

        # TODO: Android processes we attach to can't getModuleByName for their file name...
        # Maybe use "app_process64" instead... Or resolve the first module and go with that..
        if isinstance(self.device, devices.AndroidDevice):
            return "ELF"

        # TODO: Update this with other formats. PE/COFF/MACHO/etc
        if self.__file_type is None:
            if self.engine.run_script_generic("""send('bytes', Process.getModuleByName('{}').base.readByteArray(4))""".format(self.file_name), raw=True, unload=True)[1][0] == b'\x7fELF':
                self.__file_type = 'ELF'
            elif self.engine.run_script_generic("""send('bytes', Process.getModuleByName('{}').base.readByteArray(2))""".format(self.file_name), raw=True, unload=True)[1][0] == b'MZ':
                self.__file_type = "PE"
            else:
                self.__file_type = 'Unknown'

        return self.__file_type

    @property
    def file_name(self):
        """str: The base file name."""
        # TODO: This assumes the base module is always first...
        if self.__file_name is None:
            self.__file_name = self.engine.run_script_generic("""send(Process.enumerateModulesSync())""", raw=True, unload=True)[0][0][0]['name']

        return self.__file_name

    @property
    def bits(self):
        """int: How many bits is the CPU?"""
        if self.__bits == None:
            self.__bits = self.engine.run_script_generic("""send(Process.pointerSize);""", raw=True, unload=True)[0][0] * 8
        
        return self.__bits

    @property
    def arch(self):
        """str: What architecture? (x64, ia32, arm, others?)"""
        try:
            return self.__arch
        except:
            known_arch = ['x64', 'ia32', 'arm']
            arch = self.engine.run_script_generic("""send(Process.arch);""", raw=True, unload=True)[0][0]

            if arch not in known_arch:
                raise Exception("Unknown arch returned from Frida: {}".format(arch))
            self.__arch = arch
            return self.__arch

    @property
    def verbose(self):
        """bool: Output extra debugging information."""
        return self.__verbose

    @verbose.setter
    def verbose(self, verbose):
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            #logger.setLevel(logging.DEBUG)
        self.__verbose = verbose

    @property
    def target(self):
        """str, int: Target for this session."""
        return self.__target

    @target.setter
    def target(self, target):

        # target set will implicitly set argv
        if isinstance(target, (list, tuple)):
            self.argv = list(target)
            target = target[0]

        else:
            # Place holder until we resolve target
            self.argv = [target]


        # Check if this is a pid
        try:
            p = next(x for x in self.engine._frida_device.enumerate_processes() if x.pid == common.auto_int(target))
            target = p.pid
            self.__file_name = p.name
            self.argv[0] = p.name

        except (StopIteration, ValueError):
            pass

        if isinstance(target, str):
            full_path = os.path.abspath(target)
            self.__file_name = os.path.basename(full_path)

            # If this string points to an actual file, we will launch it later
            if os.path.isfile(full_path):
                self._spawn_target = full_path
            

        self.__target = target

    @property
    def alive(self):
        """bool: Is this process still alive?"""
        try:
            next(True for x in self.engine._frida_device.enumerate_processes() if x.pid == self.pid)
            return True
        except StopIteration:
            return False

    @property
    def device(self):
        """revenge.devices.BaseDevice: What device is this process associated with?"""
        return self.engine.device

    @property
    def BatchContext(self):
        """Returns a BatchContext class for this process.

        Example:
            .. code-block:: python3

                with process.BatchContext() as context:
                    something(context=context)

        """
        return lambda *args, **kwargs: BatchContext(self, *args, **kwargs)

    @property
    def _envp(self):
        """dict: This holds the USER SPECIFIED environment variables. If you
        do not specify envp, this will be empty but your program will still
        have the default environment."""
        return self.__envp

    @_envp.setter
    @common.validate_argument_types(envp=(dict, type(None)))
    def _envp(self, envp):
        self.__envp = envp

    @property
    def engine(self):
        """The current engine revenge is using."""

        try:
            self.__engine._process
        except AttributeError:
            self.__engine._process = self

        return self.__engine

import inspect
from . import types, config, devices
from .memory import Memory
from .threads import Threads
from .modules import Modules
from .contexts import BatchContext
from .exceptions import *
from .techniques import Techniques
from .plugins import Plugin
from .engines import Engine

# Doc fixups
Process.BatchContext.__doc__ += BatchContext.__init__.__doc__
Process.__doc__ = Process.__init__.__doc__

def sigint_handler(sig, frame):
    sys.exit()

signal.signal(signal.SIGINT, sigint_handler)

def main():
    signal.signal(signal.SIGINT, sigint_handler)

    global process
    process = Process()

    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
