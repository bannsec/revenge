
from .. import Colorer
import logging
logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)

import sys

import colorama
colorama.init()
from termcolor import cprint, colored

import argparse
import frida_util

common = frida_util.common
types = frida_util.types
Process = frida_util.Process

from . import actions

def parse_args():

    parser = argparse.ArgumentParser(
        description='CLI wrapper around Frida-Util.'
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
    parser.add_argument('--rw-everything', '-rw', default=False, action='store_true',
            help="Change all r-- memory areas into rw-. This can sometimes help segfault issues (default: off)")

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

    parser.add_argument('target', type=str,
            help="Target to attach to.")

    args = parser.parse_args()

    # Clean up windows messages
    if args.windows_message is not None:
        args.windows_message = [common.windows_messages_by_name[x] for x in self._args.windows_message]

    return args

def replace_function(process, f):
    """Replace a given function to always return a given value. <module:offset|symbol>?<return_val>"""
    assert type(f) == str, "Unexpected replace function argument type of {}".format(type(f))

    location, return_value = f.split("?")
    replace_location = process._resolve_location_string(location)

    replace_vars = {
            "FUNCTION_RETURN_VALUE_HERE": return_value,
            "FUNCTION_ADDRESS_HERE": hex(replace_location),
            }

    self.run_script_generic("replace_function.js", replace=replace_vars)

def main():
    args = parse_args()

    process = Process(args.target, resume=args.resume, verbose=args.verbose)

    if args.rw_everything:
        print("RW'ing memory areas\t\t... ", end='', flush=True)
        process.run_script_generic('rw_everything.js', unload=True)
        cprint('[ DONE ]', 'green')


    for f in args.replace_function:
        location, return_value = f.split("?")
        mem = process.memory[location]
        mem.replace = int(return_value, 0)

    # Setup any requested pauses
    for location in args.pause_at:
        process.memory[location].breakpoint = True

    if args.action == 'ipython':
        import IPython
        IPython.embed()

    elif args.action == 'find':
        action_find = actions.ActionFind(process, **vars(args))
        action_find.run()
        print({hex(x):y for x,y in action_find.discovered_locations.items()})
        
    elif args.action == 'stalk':
        action_stalker = actions.ActionStalker(process, **vars(args))
        action_stalker.run()

    """
    elif self._args.action == 'windows_messages':
        self.action_windows_messages = actions.ActionWindowsMessages(self, **vars(self._args))
        self.action_windows_messages.run()


    elif self._args.action == 'diff_find':
        self.action_diff = actions.ActionDiffFind(self, **vars(self._args))
        self.action_diff.run()
    
    time.sleep(1)
    """

    """
    # Make sure the requested include module exists
    # TODO: Move this into UI module once i make it..
    if self._args.include_module is not None:
        try:
            bad_mod = next(module for module in self._args.include_module if module not in self.modules)
            logger.warn("Your chosen include_module ({}) doesn't match any modules found. Double check the capitalization or spelling.".format(bad_mod))
        except:
            pass
    """

if __name__ == '__main__':
    main()
