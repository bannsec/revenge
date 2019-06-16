
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import frida_util
from frida_util.memory import MemoryRange
types = frida_util.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one = frida_util.Process(basic_one_path, resume=False, verbose=False)

def test_memory_map_basic():

    strlen = basic_one.memory[':strlen']
    assert basic_one.memory.maps[strlen.address] is not None
    assert basic_one.memory.maps[123] is None
    assert basic_one.memory.maps[123.12] is None

    str(basic_one.memory.maps)
    repr(basic_one.memory.maps)
    list(basic_one.memory.maps)
