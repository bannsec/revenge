
from frida_util import Colorer

import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import random
import numpy as np

import frida_util

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

util = frida_util.Util(action="find", target="basic_one", file=basic_one_path, resume=True)

def test_memory_read_int():

    assert util.memory['basic_one:{}'.format(hex(basic_one_i8_addr))].int8 == -13
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui8_addr))].uint8 == 13
    assert util.memory['basic_one:{}'.format(hex(basic_one_i16_addr))].int16 == -1337
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui16_addr))].uint16 == 1337
    assert util.memory['basic_one:{}'.format(hex(basic_one_i32_addr))].int32 == -1337
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui32_addr))].uint32 == 1337
    assert util.memory['basic_one:{}'.format(hex(basic_one_i64_addr))].int64 == -1337
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint64 == 1337

    assert util.memory['basic_one:{}'.format(hex(basic_one_string_addr))].string_utf8 == "This is my string"

def test_memory_write():

    x = -random.randint(1, 2**7-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int8 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int8 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint8 == np.uint8(x)
    
    x = random.randint(1, 2**7-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint8 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int8 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint8 == x

    x = -random.randint(1, 2**15-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int16 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int16 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint16 == np.uint16(x)

    x = random.randint(1, 2**15-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint16 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int16 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint16 == x

    x = -random.randint(1, 2**31-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int32 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int32 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint32 == np.uint32(x)

    x = random.randint(1, 2**31-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint32 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int32 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint32 == x

    """
    # TODO: Re-enable this once Frida fixes it: https://github.com/frida/frida/issues/917
    x = -random.randint(1, 2**63-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int64 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int64 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint64 == np.uint64(x)

    x = random.randint(1, 2**63-1)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint64 = x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].int64 == x
    assert util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].uint64 == x
    """

    x = round(random.random(),4)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].float = x
    assert abs(util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].float - x) < 0.0001

    x = round(random.random(),4)
    util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].double = x
    assert abs(util.memory['basic_one:{}'.format(hex(basic_one_ui64_addr))].double - x) < 0.0001
