
import logging
logger = logging.getLogger(__name__)

import colorama
from termcolor import cprint, colored
from .. import common

import binascii
import time
import struct

class ActionFind:
    """Handle finding things in memory."""

    def __init__(self, stalker, include_module=None, string=None, uint8=None, 
            int8=None, uint16=None, int16=None, uint32=None, int32=None,
            uint64=None, int64=None, *args, **kwargs):
        """
        Args:
            stalker: Parent stalker instantiation
        """
        self._stalker = stalker
        self.include_module = include_module or []
        self.string = string
        self.uint8 = uint8
        self.int8 = int8
        self.uint16 = uint16
        self.int16 = int16
        self.uint32 = uint32
        self.int32 = int32
        self.uint64 = uint64
        self.int64 = int64

        # Couple sanity checks
        if self._stalker.bits < 64:
            self.uint64 = None
            self.int64 = None

        if self._stalker.bits < 32:
            self.uint32 = None
            self.int32 = None

        self.discovered_locations = {}

    def run(self):
        self.action_find()
        #print([hex(x) for x in self.discovered_locations])
        print({hex(x):y for x,y in self.discovered_locations.items()})

    def action_find(self):

        def find_cb(message, data):
            #print(message)
            found = message['payload']
            
            if found is not None:
                assert type(found) is list, 'Unexpected found type of {}'.format(type(found))
                for f in found:
                    self.discovered_locations[int(f['address'],16)] = pattern_type

        find_patterns = {}
        endian_str = "<" if self._stalker.endianness == 'little' else '>'

        #
        # Create search patterns
        #

        if self.string is not None:

            # Normal string
            hexed = binascii.hexlify(self.string.encode()).decode()
            #find_patterns.append({'type': 'utf-8', 'search': hexed})
            find_patterns[hexed] = 'utf-8'

            # Wide Char String (Windows/UTF16)
            wchar = binascii.hexlify(self.string.encode('utf-16')[2:]).decode()

            #find_patterns.append({'type': 'utf-16', 'search': wchar})
            find_patterns[wchar] = 'utf-16'

        if self.uint8 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "B", self.uint8)).decode()] = 'uint8'

        if self.int8 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "b", self.int8)).decode()] = 'int8'

        if self.uint16 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "H", self.uint16)).decode()] = 'uint16'

        if self.int16 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "h", self.int16)).decode()] = 'int16'

        if self.uint32 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "I", self.uint32)).decode()] = 'uint32'

        if self.int32 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "i", self.int32)).decode()] = 'int32'

        if self.uint64 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "Q", self.uint64)).decode()] = 'uint64'

        if self.int64 is not None:
            find_patterns[binascii.hexlify(struct.pack(endian_str + "q", self.int64)).decode()] = 'int64'

        #
        # Actually do search
        #

        for find_pattern, pattern_type in find_patterns.items():

            find_js = self._stalker.load_js('find_in_memory.js')
            find_js = find_js.replace("SCAN_PATTERN_HERE", find_pattern)

            script = self._stalker.session.create_script(find_js)
            script.on('message', find_cb)

            logger.debug("Starting Memory find ... ")
            script.load()
