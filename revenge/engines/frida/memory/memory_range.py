import logging
logger = logging.getLogger(__name__)

from ....memory import MemoryRange
from .... import common

class FridaMemoryRange(MemoryRange):

    def set_protection(self, read, write, execute):

        protection = "{}{}{}".format(
            "r" if read else "-",
            "w" if write else "-",
            "x" if execute else "-"
        )

        self._engine.run_script_generic("""Memory.protect({}, {}, '{}')""".format(
            self.base.js,
            hex(self.size),
            protection,
            ), raw=True, unload=True)

        # Update this object
        self._MemoryRange__protection = protection

    @classmethod
    @common.validate_argument_types(d=dict)
    def _from_frida_find_json(klass, process, d):
        """Build this MemoryRange directly from Frida dictionary object.

        This is returned from Process.findRangeByAddress(address) and others"""
        #    process, base, size, protection, file=None
        
        return klass(process, base=d['base'], size=d['size'],
                protection=d['protection'], file=d.get('file', None))

from .... import common, types, exceptions
