import logging
logger = logging.getLogger(__name__)

from .. import Engine

class UnicornEngine(Engine):

    def __init__(self, *args, **kwargs):
        kwargs['klass'] = self.__class__
        super().__init__(*args, **kwargs)

    def _at_exit(self):
        pass

import os
import unicorn

"""
https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_x86.py

# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
        # map this memory in with 2MB in size
        uc.mem_map(0xaaaa0000, 2 * 1024*1024)
        # return True to indicate we want to continue emulation
        return True
    else:
        # return False to indicate we want to stop emulation
        return False
"""

Engine = UnicornEngine 
here = os.path.dirname(os.path.abspath(__file__))
