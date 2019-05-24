
import logging

logger = logging.getLogger(__name__)

import frida
import argparse
import colorama
colorama.init()

import os
from termcolor import cprint
from prettytable import PrettyTable

here = os.path.dirname(os.path.abspath(__file__))

class Stalker(object):

    def __init__(self):
        # Just variable to ensure we don't garbage collect
        self._scripts = []

        self.parse_args()
        self.start_session()
        self.enumerate_modules()
        self.print_modules()

        self.enumerate_threads()
        self.print_threads()

        self.stalk()

    def enumerate_modules(self):

        self.modules = {}

        def modules_match(module, data=None):
            module = module['payload']
            self.modules[module['name']] = module

        print("Enumerating modules\t\t... ", end='', flush=True)

        script = self.session.create_script(self.load_js('enumerate_modules.js'))
        script.on('message', modules_match)
        script.load()

        cprint("[ DONE ]", "green")

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

    def print_modules(self):
        print(self.modules_table)

    def print_threads(self):
        print(self.threads_table)

    def stalk(self):
        """Start the stalker."""
        
        def stalk_cb(message, data):
            print(message)
            message = message['payload']

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

            print("Starting stalker on TID: " + str(tid))
            script.load()

            # Save so that we don't GC it
            self._scripts.append(script)
    
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
        parser.add_argument('target', type=self.target_type,
                help="Target to attach to.")
        self._args = parser.parse_args()


    def start_session(self):
        print('Attaching to the session\t... ', end='', flush=True)

        try:
            self.session = frida.attach(self._args.target)
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

        for name, module in self.modules.items():
            base = int(module['base'],0)
            size = module['size']

            if addr >= base and addr <= base+size:
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
    input("waiting")

if __name__ == '__main__':
    main()
