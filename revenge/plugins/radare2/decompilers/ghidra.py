
import logging
import re
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
        if fname.lower() != self._radare2.file.lower():
            LOGGER.error("revenge image '{}' doesn't match radare2 image '{}'.".format(fname, self._radare2.file))
            return

        adjusted_offset = self._radare2.base_address + foff

        # TODO: This is hacky... But seems like pdgo is currently the easiest way to get this information
        out = self._r2.cmd("pdgo @ " + hex(adjusted_offset)).strip()

        # Strip out colors
        out = common.strip_ansi_escapes(out)

        # Gotta seek past the junk up top
        infunc = False
        buf = []
        decomp = Decompiled(self._process, file_name=fname)

        for line in out.strip().split("\n"):
            #addr, code = line.split("|")
            out = line.split("|")
            addr = out[0]
            code = "|".join(out[1:]).rstrip()
            addr = addr.strip()

            buf.append(code)
            
            if not infunc:
                # TODO: This is a hacky heuristic to determine when we get into the function...
                if code.strip().startswith("{"):
                    infunc = True
                    decomp._header = "\n".join(buf)
                    buf = []
                continue
            
            # If we've found our offset
            if addr != "":

                # Save it off!
                addr = int(addr, 16) - self._radare2.base_address
                decomp[addr].address = addr
                decomp[addr].src = "\n".join(buf)
                buf = []

        # Stuff that didn't get matched up at the end of the function
        decomp._footer = "\n".join(buf)

        if len(decomp) == 0:
            LOGGER.warning("Nothing decompiled. Be sure you have defined your function start or run process.radare2.analyze().")

        return decomp
        
    def decompile_address(self, address):

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
                decomp = Decompiled(self._process, file_name=fname)
                decomp[adjusted_offset].address = adjusted_offset
                decomp[adjusted_offset].src = b.decode()

                return decomp

    @property
    def _r2(self):
        """Active r2pipe instance."""
        return self._radare2._r2

from base64 import b64decode

from ... import common
from revenge.plugins.decompiler.decompiled import Decompiled

LOGGER = logging.getLogger(__name__)
