
import logging
from ...decompiler.base import DecompilerBase

class GhidraDecompiler(DecompilerBase):
    def __init__(self, radare2):
        self._radare2 = radare2
        self._process = self._radare2._process

    def decompile_function(self, address):

        # Figure out relative name and offset
        out = self._process.modules.lookup_offset(address)

        if out is None:
            LOGGER.error("Couldn't lookup offset. Is this a valid offset for your current binary?")
            return

        fname, foff = out

        # If this name doesn't match up, bail
        if fname.lower() != self._radare2.file:
            LOGGER.error("revenge image '{}' doesn't match radare2 image '{}'.".format(fname, self._radare2.file))
            return

        adjusted_offset = self._radare2.base_address + foff
        out = self._r2.cmd("pdg* @ " + hex(adjusted_offset))
        for (b, a) in re.findall("base64:(.+?) @ (.+)", out):
            b = b64decode(b)
            a = int(a,16)

            if a == adjusted_offset:
                decomp = Decompiled(self._process)
                decomp[adjusted_offset].address = adjusted_offset
                decomp[adjusted_offset].src = b.decode()

                return decomp

    def lookup_address(self, address):

        # Figure out relative name and offset
        out = self._process.modules.lookup_offset(address)

        if out is None:
            LOGGER.error("Couldn't lookup offset. Is this a valid offset for your current binary?")
            return

        fname, foff = out

        # If this name doesn't match up, bail
        if fname.lower() != self._radare2.file:
            LOGGER.error("revenge image '{}' doesn't match radare2 image '{}'.".format(fname, self._radare2.file))
            return

        adjusted_offset = self._radare2.base_address + foff
        out = self._r2.cmd("pdg* @ " + hex(adjusted_offset))
        for (b, a) in re.findall("base64:(.+?) @ (.+)", out):
            b = b64decode(b)
            a = int(a,16)

            if a == adjusted_offset:
                decomp = Decompiled(self._process)
                decomp[adjusted_offset].address = adjusted_offset
                decomp[adjusted_offset].src = b.decode()

                return decomp

    @property
    def _r2(self):
        """Active r2pipe instance."""
        return self._radare2._r2

from base64 import b64decode
import re

from revenge.plugins.decompiler.decompiled import Decompiled

LOGGER = logging.getLogger(__name__)
