
import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored

from ... import types, common

class SectionHeaders(object):

    def __init__(self, process, elf):
        self._process = process
        self._elf = elf
        self._headers = None

        # Give us ability to read
        mem = self._process.memory.maps[self.address]
        if mem.protection == '---':
            mem.protection = 'r--'
    
    def __len__(self):
        return self._elf.shnum

    def __iter__(self):
        return self._headers.__iter__()

    @property
    def _headers(self):
        """list: Headers for this elf."""
        if self.__headers is None:
            self._headers = []
            address = self.address
            for _ in range(len(self)):
                self._headers.append(SectionHeader(self._process, self._elf, address))
                address += self._elf.shentsize
        return self.__headers

    @_headers.setter
    def _headers(self, headers):
        self.__headers = headers

    @property
    def address(self):
        """ptr: Address where the section headers start."""
        return self._elf.shoff


from .section_header import SectionHeader
