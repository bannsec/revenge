
from . import Colorer
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import frida
import argparse
import colorama
colorama.init()

import os
from termcolor import cprint, colored
from prettytable import PrettyTable
import time

import atexit
import signal
import json
import psutil
import pprint
from copy import copy

from . import common, actions, types
from .memory import Memory
from .threads import Threads
from .tracer import Tracer

here = os.path.dirname(os.path.abspath(__file__))

class Util(object):

    def __init__(self, *args, **kwargs):
        # Just variable to ensure we don't garbage collect
        self._scripts = []
        # Cache common module addrs
        self._module_by_addr_cache = {}
        self.session = None
        self.__file_name = None
        self.__file_type = None
        self.__entrypoint = None
        self._resume_addr = None
        self.__endianness = None
        self.__bits = None

        self.memory = Memory(self)
        self.threads = Threads(self)
        self.tracer = Tracer(self)

        self.parse_args(kwargs!={})

        # Generic passthrough of arguments
        for key, val in kwargs.items():
            setattr(self._args, key, val)

        if self._args.verbose:
            logger.setLevel(logging.DEBUG)

        atexit.register(self.at_exit)
        self.load_device()
        self.start_session()
        self.enumerate_modules()

        # ELF binaries start up in ptrace, which causes some issues, shim at entrypoint so we can remove ptrace
        if self._spawned is not None and self.file_type == 'ELF':

            # Set breakpoint at entry
            self.memory[self.entrypoint_rebased].breakpoint = True

            # Set breakpoints at exit calls
            for c in [':exit', ':_exit']:
                self.memory[c].breakpoint = True

            # Resume to remove ptrace
            self.device.resume(self._spawned)

            time.sleep(1)

        if self._args.rw_everything:
            print('RW\'ing memory areas\t\t... ', end='', flush=True)
            self.run_script_generic('rw_everything.js', unload=True)
            cprint('[ DONE ]', 'green')

        # Replace any functions needed
        for f in self._args.replace_function:
            self.replace_function(f)

        # Setup any requested pauses
        for location in self._args.pause_at:
            self.pause_at(location)

        if self._args.action == 'stalk':
            # Issue where stalk elf doesn't enumerate threads...
            self.action_stalker = actions.ActionStalker(self, **vars(self._args))
            self.action_stalker.run()

        elif self._args.action == 'windows_messages':
            self.action_windows_messages = actions.ActionWindowsMessages(self, **vars(self._args))
            self.action_windows_messages.run()

        elif self._args.action == 'find':
            self.action_find = actions.ActionFind(self, **vars(self._args))
            self.action_find.run()
            print({hex(x):y for x,y in self.action_find.discovered_locations.items()})

        elif self._args.action == 'diff_find':
            self.action_diff = actions.ActionDiffFind(self, **vars(self._args))
            self.action_diff.run()
        
        time.sleep(1)
        # Resume file if need be
        if self._args.resume:

            # If we are using a resume variable
            if self.memory[self.entrypoint_rebased].breakpoint:
                self.memory[self.entrypoint_rebased].breakpoint = False
            
            else:
                self.device.resume(self._spawned)

        if self._args.action == 'ipython':
            process = self
            import IPython
            IPython.embed()


    def load_device(self):
        # For now, assuming local
        # TODO: Make this variable

        self.device = frida.get_local_device()

    def enumerate_modules(self):

        self.modules = {}

        def modules_match(module, data=None):
            module = module['payload']
            module['base'] = int(module['base'], 16)
            self.modules[module['name']] = module

        print("Enumerating modules\t\t... ", end='', flush=True)

        script = self.session.create_script(self.load_js('enumerate_modules.js'))
        script.on('message', modules_match)
        script.load()
        script.unload()

        cprint("[ DONE ]", "green")

        # Sanity check
        if self._args.include_module is not None:
            try:
                bad_mod = next(module for module in self._args.include_module if module not in self.modules)
                logger.warn("Your chosen include_module ({}) doesn't match any modules found. Double check the capitalization or spelling.".format(bad_mod))
            except:
                pass

        self.print_modules()

    def print_modules(self):
        logger.debug('\n' + str(self.modules_table))

    def pause_at(self, location):
        """Pause at a given point in execution."""

        pause_location = self._resolve_location_string(location)
        self.run_script_generic('pause_at2.js', replace={"FUNCTION_ADDRESS_HERE": hex(pause_location)})
        

    def replace_function(self, f):
        """Replace a given function to always return a given value. <module:offset|symbol>?<return_val>"""
        assert type(f) == str, "Unexpected replace function argument type of {}".format(type(f))

        location, return_value = f.split("?")
        replace_location = self._resolve_location_string(location)

        replace_vars = {
                "FUNCTION_RETURN_VALUE_HERE": return_value,
                "FUNCTION_ADDRESS_HERE": hex(replace_location),
                }

        self.run_script_generic("replace_function.js", replace=replace_vars)


    def at_exit(self):
        """Called to clean-up at exit."""

        self.run_script_generic("""Interceptor.detachAll()""", raw=True, unload=True)

        # Unallocate our memory
        for addr in copy(self.memory._allocated_memory):
            logger.debug("Unallocating memory: " + hex(addr))
            self.memory[addr].free()

        # Remove breakpoints
        for addr in copy(self.memory._active_breakpoints):
            logger.debug("Removing breakpoint: " + hex(addr))
            self.memory[addr].breakpoint = False

        # Unload our scripts
        for script, text in self._scripts:
            logger.debug("Unloading Script: %s", text)

            try:
                script.unload()
            except frida.InvalidOperationError:
                # Already unloaded probably
                pass

        logger.debug("Done unloading")

        # If we spawned it, kill it
        try:
            if self._spawned is not None:
                return self.device.kill(self._spawned)

        except (frida.PermissionDeniedError, frida.ProcessNotFoundError) as e:
            # This can indicate the process is already dead.
            try:
                next(x for x in self.device.enumerate_processes() if x.pid == self._spawned)
                logger.error("Device kill permission error, with process apparently %d still alive.", self._spawned)
                raise e
            except StopIteration:
                return

        # Unload anything we loaded first
        #for script in self._scripts:
        #    script.unload()

        try:

            # Genericall unstalk everything
            for thread in self.threads:
                self.run_script_generic("Stalker.unfollow({tid})".format(tid=thread.id), raw=True, unload=True)
        
        except frida.InvalidOperationError:
            # Session is already detached.
            pass

        # Detach our session
        self.session.detach()

    
    #######################
    # On Message Handlers #
    #######################

    def on_message(self, message, data=None):
        """Generic on message handler."""
        print("Caught message", message, data)

    def parse_args(self, defaults=False):
        """

        Args:
            defaults (bool, optional): Just use argparse to set up default values.
        """

        parser = argparse.ArgumentParser(
            description='CLI wrapper around Frida Stalker.'
            )

        parser.add_argument('--tid', type=int, default=None,
                help="Thread to stalk. (Default: all threads.)")
        parser.add_argument('--include-module', "-I", type=str, default=None, metavar='module', nargs='+',
                help="Module to include for stalking (default: All modules).")
        parser.add_argument('--include-function', "-i", type=str, default=None, metavar='module:offset',
                help="Function to include for stalking (default: All functions).")
        parser.add_argument('--replace-function', "-rf", type=str, default=[], metavar='<module:offset|symbol>?<return_val>', nargs='+',
                help="Replace given function by simply returning the given value instead.")
        parser.add_argument('--pause-at', type=str, default=[], metavar='<module:offset|symbol>', nargs='+',
                help="Pause execution at address.")
        parser.add_argument('--verbose', "-v", action='store_true', default=False,
                help="Output more verbose information (defualt: False)")

        stalk_group = parser.add_argument_group('stalk options')
        stalk_group.add_argument('--call', action='store_true', default=False,
                help="Stalk calls")
        stalk_group.add_argument('--ret', action='store_true', default=False,
                help="Stalk rets")
        stalk_group.add_argument('--exec', action='store_true', default=False,
                help="Stalks every single instruction.")
        stalk_group.add_argument('--block', action='store_true', default=False,
                help="Stalks every code block.")
        stalk_group.add_argument('--compile', action='store_true', default=False,
                help="Stalks every time Frida needs to compile.")
        stalk_group.add_argument('--rw-everything', '-rw', default=False, action='store_true',
                help="Change all r-- memory areas into rw-. This can sometimes help segfault issues (default: off)")

        windows_group = parser.add_argument_group('windows options')
        windows_group.add_argument('--windows-message', '-wm', default=None, type=str, nargs='+', metavar='Message',
                help="Down select to these specific windows messages (i.e.: WM_KEYUP, WM_KEYDOWN).")

        find_group = parser.add_argument_group('find options')
        find_group.add_argument('--string', type=str, default=None,
                help="Search for string in program memory.")
        find_group.add_argument('--uint8', type=int, default=None,
                help="Search for unsigned 8bit int in program memory.")
        find_group.add_argument('--int8', type=int, default=None,
                help="Search for signed 8bit int in program memory.")
        find_group.add_argument('--uint16', type=int, default=None,
                help="Search for unsigned 16bit int in program memory.")
        find_group.add_argument('--int16', type=int, default=None,
                help="Search for signed 16bit int in program memory.")
        find_group.add_argument('--uint32', type=int, default=None,
                help="Search for unsigned 32bit int in program memory.")
        find_group.add_argument('--int32', type=int, default=None,
                help="Search for signed 32bit int in program memory.")
        find_group.add_argument('--uint64', type=int, default=None,
                help="Search for unsigned 64bit int in program memory.")
        find_group.add_argument('--int64', type=int, default=None,
                help="Search for signed 64bit int in program memory.")
        find_group.add_argument('--number', type=int, default=None,
                help="Search for number of any size in program memory.")

        spawn_group = parser.add_argument_group('spawn options')
        spawn_group.add_argument('--file', '-f', type=str, metavar=('FILE','ARGS'), default=None, nargs='+',
                help="Spawn file.")
        spawn_group.add_argument('--resume', default=False, action='store_true',
                help="Resume binary after spawning it (default: false).")

        parser.add_argument('action', choices=('stalk', 'windows_messages', 'find', 'diff_find', 'ipython'),
                help="What type of stalking.")

        parser.add_argument('target', type=self.target_type, 
                help="Target to attach to.")

        if defaults != False:
            self._args = parser.parse_args(['stalk','PLACEHOLDER'])
        else:
            self._args = parser.parse_args()

        # Clean up windows messages
        if self._args.windows_message is not None:
            self._args.windows_message = [common.windows_messages_by_name[x] for x in self._args.windows_message]


    def start_session(self):

        self._spawned = None

        if self._args.file is not None:
            print("Spawning file\t\t\t... ", end='', flush=True)
            self._spawned = self.device.spawn(self._args.file)
            cprint("[ DONE ]", "green")

        print('Attaching to the session\t... ', end='', flush=True)

        try:
            # Default attach to what we just spawned
            self.session = frida.attach(self._spawned or self._args.target)
        except frida.ProcessNotFoundError:
            logger.error('Could not find that target process to attach to!')
            exit(1)

        print(colorama.Fore.GREEN + '[ DONE ]' + colorama.Style.RESET_ALL)

    def target_type(self, x):
        # Maybe it's PID
        try:
            return int(x)

        # Probably process name
        except:
            return x

    def load_js(self, name):
        with open(os.path.join(here, "js", name), "r") as f:
            return f.read().strip()

    def get_module_by_addr(self, addr):

        if type(addr) is str:

            try:
                addr = int(addr, 0)
            except:
                return None

        try:
            return self._module_by_addr_cache[addr]
        except:
            pass

        for name, module in self.modules.items():
            base = module['base']
            size = module['size']

            if addr >= base and addr <= base+size:
                self._module_by_addr_cache[addr] = module['name'] # Add to cache
                return module['name']

        return None

    def run_script_generic(self, script_name, raw=False, replace=None, unload=False, runtime='duk', on_message=None):
        """Run scripts that don't require anything special.
        
        Args:
            script_name (str): What script to load from the js directory
            raw (bool, optional): Should the script_name actually be considered the script contents?
            replace (dict, optional): Replace key strings from dictionary with value into script.
            unload (bool, optional): Auto unload the script. Set to true if the script is fully synchronous.
            runtime (str, optional): Runtime to use for this script, either 'duk' or 'v8'.
            on_message(callable, optional): Set the on_message handler to this instead.

        Returns:
            tuple: msg, data return from the script
        """

        msg = []
        data = []

        if not on_message is None and not callable(on_message):
            logger.error('on_message handler must be callable.')
            return None

        def on_msg(m, d):

            if m['type'] == 'error':
                logger.error(pprint.pformat(m['description']))
                return

            logger.debug("on_message: {}".format([m,d]))
            msg.append(m['payload'])
            data.append(d)

        on_message = on_msg if on_message is None else on_message

        if not raw:
            js = self.load_js(script_name)
        else:
            js = script_name

        if replace is not None:
            assert type(replace) == dict, "Unexpected replace type of {}".format(type(replace))

            for key, value in replace.items():
                js = js.replace(key, value)

        logger.debug("Running script: %s", js)

        script = self.session.create_script(js, runtime=runtime)
        script.on('message', on_message)
        script.load()
        
        if unload:
            script.unload()
        else:
            # Inserting instead of appending since earlier scripts need to be unloaded later
            self._scripts.insert(0, [script, js])

        return msg, data

    def _resolve_location_string(self, location):
        """Take location string s and resolve it into an integer address."""
        assert type(location) is str, "Invalid call to resolve_location_string with type {}".format(type(location))

        module, offset, symbol = common.parse_location_string(location)

        replace_vars = {
                "FUNCTION_SYMBOL_HERE": symbol,
                "FUNCTION_MODULE_HERE": module,
                "FUNCTION_OFFSET_HERE": offset,
                }

        return common.auto_int(self.run_script_generic("resolve_location_address.js", replace=replace_vars, unload=True)[0][0])


    ############
    # Property #
    ############

    @property
    def modules_table(self):
        table = PrettyTable(['name', 'base', 'size', 'path'])

        for name, module in self.modules.items():
            table.add_row([name, hex(module['base']), hex(module['size']), module['path']])

        table.align['path'] = 'l'
        
        return table

    @property
    def device_platform(self):
        """Wrapper to discover the device's platform."""

        def message(x, y):
            self.device_platform = x['payload']

        try:
            return self.__device_platform
        except:
            pass

        js = "send(Process.platform)"
        script = self.session.create_script(js)
        script.on('message', message)
        script.load()
        return self.__device_platform

    @device_platform.setter
    def device_platform(self, platform):
        self.__device_platform = platform

    @property
    def pid(self):
        return self.session._impl.pid

    @property
    def entrypoint_rebased(self):
        """Entrypoint as it exists in the current rebased program."""
        return self.entrypoint + next(module['base'] for name, module in self.modules.items() if name == self.file_name)

    @property
    def entrypoint(self):
        """int: Returns the entrypoint for this running program."""

        if self.__entrypoint is None:
            if self.file_type == 'ELF':
                self.__entrypoint = int(self.run_script_generic("""send(Memory.readPointer(ptr(Number(Process.getModuleByName('{}').base) + 0x18)))""".format(self.file_name), raw=True, unload=True)[0][0],16)

            else:
                logger.warn('entrypoint not implemented for file of type {}'.format(self.file_type))
                return None
            
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
            endianness = self.run_script_generic("""send(ptr(Number(Process.enumerateModulesSync()[0].base) + 5).readS8())""", raw=True, unload=True)[0][0]
            self.__endianness = 'little' if endianness == 1 else 'big'

        else:
            logger.warn("Unhandled endianness check for ({}, {}), assuming little".format(self.file_type, self.device_platform))

        return self.__endianness

    @property
    def file_type(self):
        """Guesses the file type."""

        # TODO: Update this with other formats. PE/COFF/MACHO/etc
        if self.__file_type is None:
            if self.run_script_generic("""send('bytes', Process.getModuleByName('{}').base.readByteArray(4))""".format(self.file_name), raw=True, unload=True)[1][0] == b'\x7fELF':
                self.__file_type = 'ELF'
            else:
                self.__file_type = 'Unknown'

        return self.__file_type

    @property
    def file_name(self):
        """The base file name."""
        # TODO: This assumes the base module is always first...
        if self.__file_name is None:
            self.__file_name = self.run_script_generic("""send(Process.enumerateModulesSync())""", raw=True, unload=True)[0][0][0]['name']

        return self.__file_name

    @property
    def bits(self):
        """int: How many bits is the CPU?"""
        if self.__bits == None:
            self.__bits = self.run_script_generic("""send(Process.pointerSize);""", raw=True, unload=True)[0][0] * 8
        
        return self.__bits

def sigint_handler(sig, frame):
    exit()

def main():
    signal.signal(signal.SIGINT, sigint_handler)

    global util
    util = Util()

    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
