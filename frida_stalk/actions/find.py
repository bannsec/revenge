
import logging
logger = logging.getLogger(__name__)

import colorama
from termcolor import cprint, colored
from .. import common

import binascii
import time

class ActionFind:
    """Handle finding things in memory."""

    def __init__(self, stalker, include_module=None, string=None, *args, **kwargs):
        """
        Args:
            stalker: Parent stalker instantiation
        """
        self._stalker = stalker
        self.include_module = include_module or []
        self.string = string

        self.discovered_locations = set()

    def run(self):
        self.action_find()
        print([hex(x) for x in self.discovered_locations])

    def action_find(self):

        def find_cb(message, data):
            #print(message)
            found = message['payload']
            
            if found is not None:
                assert type(found) is list, 'Unexpected found type of {}'.format(type(found))
                for f in found:
                    self.discovered_locations.add(int(f['address'],16))

        find_patterns = []

        if self.string is not None:

            # Normal string
            hexed = binascii.hexlify(self.string.encode()).decode()
            find_patterns.append(hexed)

            # Wide Char String (Windows/UTF16)
            wchar = ''
            for i in range(0, len(hexed), 2):
                wchar += hexed[i:i+2] + '00'

            find_patterns.append(wchar)


        for find_pattern in find_patterns:

            find_js = self._stalker.load_js('find_in_memory.js')
            find_js = find_js.replace("SCAN_PATTERN_HERE", find_pattern)

            script = self._stalker.session.create_script(find_js)
            script.on('message', find_cb)

            logger.debug("Starting Memory find ... ")
            script.load()
