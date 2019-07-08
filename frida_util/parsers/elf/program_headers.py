
import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored

from ... import types, common

class ProgramHeaders(object):

    def __init__(self, process, elf):
        self._process = process
        self._elf = elf
        self._headers = None
    
    def __len__(self):
        return self._elf.phnum

    def __iter__(self):
        return self._headers.__iter__()

    @property
    def _headers(self):
        """list: Headers for this elf."""
        if self.__headers is None:
            self._headers = []
            address = self.address
            for _ in range(len(self)):
                self._headers.append(ProgramHeader(self._process, self._elf, address))
                address += self._elf.phentsize
        return self.__headers

    @_headers.setter
    def _headers(self, headers):
        self.__headers = headers

    @property
    def address(self):
        """ptr: Address where the program header starts."""
        return self._elf.phoff


from .program_header import ProgramHeader
