
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import time
from copy import copy
import re

import frida_util
types = frida_util.types

from time import sleep

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one_i8_addr = 0x201010
basic_one_ui8_addr = 0x201011
basic_one_i16_addr = 0x201012
basic_one_ui16_addr = 0x201014
basic_one_i32_addr = 0x201018
basic_one_ui32_addr = 0x20101C
basic_one_i64_addr = 0x201020
basic_one_ui64_addr = 0x201028
basic_one_string_addr = 0x724
basic_open_func_addr = 0x64A

process = frida_util.Util(action="find", target="basic_one", file=basic_one_path, resume=False, verbose=False)

def test_memory_find_general():

    f = process.memory.find(types.StringUTF8("This is my string"))
    
    while not f.completed:
        sleep(0.1)

    assert len(f) > 0
    for addr in f:
        assert process.memory[addr].string_utf8 == "This is my string"

    """ This doesn't work. Probably because Frida is hiding it's own memory regions from returning

    my_string = types.StringUTF8('Hello world!')
    mem = process.memory.alloc_string(my_string)

    f = process.memory.find(my_string)

    while not f.completed:
        sleep(0.1)

    assert mem.address in f
    """
