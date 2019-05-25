
import logging

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
from . import common

here = os.path.dirname(os.path.abspath(__file__))

class Stalker(object):

    def __init__(self):
        # Just variable to ensure we don't garbage collect
        self._scripts = []
        # Cache common module addrs
        self._module_by_addr_cache = {}

        self.parse_args()

        if self._args.verbose:
            logger.level = logging.DEBUG

        atexit.register(self.at_exit)
        self.load_device()
        self.start_session()
        self.enumerate_modules()
        self.enumerate_threads()

        if self._args.action == 'stalk':
            self.action_stalk()

        elif self._args.action == 'windows_messages':
            self.action_windows_messages()

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

        cprint("[ DONE ]", "green")

        self.print_modules()

    def enumerate_threads(self):

        self.threads = {}

        def threads_match(module, data=None):
            thread = module['payload']
            self.threads[thread['id']] = thread

        print("Enumerating threads\t\t... ", end='', flush=True)

        script = self.session.create_script(self.load_js('enumerate_threads.js'))
        script.on('message', threads_match)
        script.load()

        cprint("[ DONE ]", "green")

        self.print_threads()

    def print_modules(self):
        logger.debug(self.modules_table)

    def print_threads(self):
        logger.debug(self.threads_table)

    def action_windows_messages(self):
        """Stalk some windows messages."""

        def windows_cb(message, data):
            handler_ip = int(message['payload'], 16)
            handler_module = self.get_module_by_addr(handler_ip)
            handler_offset = handler_ip - self.modules[handler_module]['base']

            print("Found Message Handler: " + colored(handler_module, 'cyan') + ":" + colored(hex(handler_offset), "magenta"))

        # TODO: Figure out better sanity check to determine if Frida device object is on Windows
        try:
            next(True for x in self.device.enumerate_processes() if x.name.lower() == 'svchost.exe')
        except StopIteration:
            logger.error('This doesn\'t appear to be a Windows device...')
            exit(1)

        windows_js = self.load_js('windows_stalk_message_handlers.js')

        script = self.session.create_script(windows_js)
        script.on('message', windows_cb)

        logger.debug("Starting Windows Message monitor ... ")
        script.load()

        # Save so that we don't GC it
        self._scripts.append(script)

    def action_stalk(self):
        """Start the stalker."""
        
        def stalk_cb_call(message):
            """Specifically handle call stalk."""
            call_from = int(message['location'],16)
            call_to = int(message['target'], 16)
            depth = message['depth']
            #module_name = message['module']['name']
            
            module_from = self.get_module_by_addr(call_from)
            module_from_offset = call_from - self.modules[module_from]['base']

            module_to = self.get_module_by_addr(call_to)
            module_to_offset = call_to - self.modules[module_to]['base']

            print("{type: <10}{module_from}:{module_from_offset} -> {module_to}:{module_to_offset}".format(
                type = 'call',
                module_from = module_from,
                module_from_offset = hex(module_from_offset),
                module_to = module_to,
                module_to_offset = hex(module_to_offset)
                ))

        def stalk_cb(message, data):
            message = message['payload']

            if message['type'] == 'call':
                stalk_cb_call(message)
            
            else:
                logger.error('Unhandled type: ' + message['type'])
                print(message)

        # TODO: Add args for stalking other types of things
        # TODO: Print output for other types of calls

        stalk_js = self.load_js('stalk.js')
        stalk_js = stalk_js.replace("INCLUDE_MODULE_HERE", self._args.include_module)

        if self._args.tid == None:
            tid_list = self.threads.keys()
        else:
            tid_list = [self._args.tid]

        for tid in tid_list:
            stalk_js_replaced = stalk_js.replace("THREAD_ID_HERE", str(tid))
            script = self.session.create_script(stalk_js_replaced)
            script.on('message', stalk_cb)

            logger.debug("Starting stalker on TID: " + str(tid))
            script.load()

            # Save so that we don't GC it
            self._scripts.append(script)

    def at_exit(self):
        """Called to clean-up at exit."""

        # Unload anything we loaded first
        #for script in self._scripts:
        #    script.unload()

        # Detach our session
        self.session.detach()

        # If we spawned it, kill it
        if self._spawned is not None:
            self.device.kill(self._spawned)
    
    #######################
    # On Message Handlers #
    #######################

    def on_message(self, message, data=None):
        """Generic on message handler."""
        print("Caught message", message, data)


    def parse_args(self):
        parser = argparse.ArgumentParser(
            description='CLI wrapper around Frida Stalker.'
            )

        parser.add_argument('--tid', type=int, default=None,
                help="Thread to stalk. (Default: all threads.)")
        parser.add_argument('--include-module', "-I", type=str, default="",
                help="Module to include for stalking (default: All modules).")
        parser.add_argument('--verbose', "-v", action='store_true', default=False,
                help="Output more verbose information (defualt: False)")

        spawn_group = parser.add_argument_group('spawn options')
        spawn_group.add_argument('--file', '-f', type=str, metavar=('FILE','ARGS'), default=None, nargs='+',
                help="Spawn file.")
        spawn_group.add_argument('--resume', default=False, action='store_true',
                help="Resume binary after spawning it (default: false).")

        parser.add_argument('action', choices=('stalk', 'windows_messages'),
                help="What type of stalking.")

        parser.add_argument('target', type=self.target_type, 
                help="Target to attach to.")
        self._args = parser.parse_args()


    def start_session(self):

        self._spawned = None

        if self._args.file is not None:
            print("Spawning file\t\t\t... ", end='', flush=True)
            self._spawned = self.device.spawn(self._args.file)

            if self._args.resume:
                self.device.resume(self._spawned)

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

    ############
    # Property #
    ############

    @property
    def threads_table(self):
        table = PrettyTable(['id', 'state', 'pc', 'pc_module'])

        for id, thread in self.threads.items():
            table.add_row([str(id), thread['state'], thread['context']['pc'], self.get_module_by_addr(thread['context']['pc'])])

        return table

    @property
    def modules_table(self):
        table = PrettyTable(['name', 'base', 'size', 'path'])

        for name, module in self.modules.items():
            table.add_row([name, module['base'], module['size'], module['path']])

        table.align['path'] = 'l'
        
        return table


def main():
    stalk = Stalker()

    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
