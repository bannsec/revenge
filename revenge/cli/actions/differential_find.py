
import logging
logger = logging.getLogger(__name__)

import colorama
from copy import copy
from termcolor import cprint, colored
from .. import common
from . import ActionFind

class ActionDiffFind:
    """Handle finding things in memory differentially."""


    def __init__(self, process, *args, **kwargs):
        """
        Args:
            process: Parent process instantiation
        """
        self._process = process
        self._args = args
        self._kwargs = kwargs
        self.memory_locations = {}
        self.memory_locations_new = None

    def run(self):
        self.run_menu()

    def run_menu(self):

        menu_options = {
            'n': {'description': 'Search for number', 'action': self.search_number},
            'p': {'description': 'Print current found locations', 'action': self.print_locations},
            'q': {'description': 'Quit', 'action': exit},
        }

        while True:
            
            print("Total memory locations = " + str(len(self.memory_locations)))
            print("")

            for key, info in menu_options.items():
                print("[{key}] {description}".format(key=key, description=info['description']))

            i = input("> ").lower()

            if i not in menu_options:
                logger.error("Invalid choice '{}'.".format(i))
                continue

            menu_options[i]['action']()
            self.merge_results()

    
    def print_locations(self):
        """Prints out what we've found so far."""
        print({hex(x): y for x,y in self.memory_locations.items()})
    
    def merge_results(self):
        """Merge the new results with the existing results."""

        # We didn't actually search
        if self.memory_locations_new is None:
            return

        # If this is the first query, just copy over
        if self.memory_locations == {}:
            self.memory_locations = self.memory_locations_new

        else:
            orig_set = set(self.memory_locations.keys())
            new_set = set(self.memory_locations_new.keys())

            self.memory_locations = {x:self.memory_locations_new[x] for x in orig_set.intersection(new_set)}


        self.memory_locations_new = None

    
    def search_number(self):

        try:
            n = int(input("Number> "), 0)
        except ValueError:
            logger.error("Invalid number")
            return

        kwargs = copy(self._kwargs)

        kwargs['number'] = n
        find = ActionFind(self._process, **kwargs)
        find.run()

        self.memory_locations_new = copy(find.discovered_locations)


    def action_diff(self):

        def find_cb(message, data):
            #print(message)
            found = message['payload']
            
            if found is not None:
                assert type(found) is list, 'Unexpected found type of {}'.format(type(found))
                for f in found:
                    self.discovered_locations[int(f['address'],16)] = pattern_type

        return

        #
        # Actually do search
        #

        for find_pattern, pattern_type in find_patterns.items():

            find_js = self._process.load_js('find_in_memory.js')
            find_js = find_js.replace("SCAN_PATTERN_HERE", find_pattern)

            script = self._process.session.create_script(find_js)
            script.on('message', find_cb)

            logger.debug("Starting Memory find ... ")
            script.load()
