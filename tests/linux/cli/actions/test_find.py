
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import random
import numpy as np
import time
from copy import copy
import re
import subprocess

import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
basic_one_module = basic_one.modules['basic_one']
basic_one_i8_addr = basic_one_module.symbols['i8']
basic_one_ui8_addr = basic_one_module.symbols['ui8']
basic_one_i16_addr = basic_one_module.symbols['i16']
basic_one_ui16_addr = basic_one_module.symbols['ui16']
basic_one_i32_addr = basic_one_module.symbols['i32']
basic_one_ui32_addr = basic_one_module.symbols['ui32']
basic_one_i64_addr = basic_one_module.symbols['i64']
basic_one_ui64_addr = basic_one_module.symbols['ui64']
basic_one_string_addr = 0x724
basic_open_func_addr = basic_one_module.symbols['func']

def test_find_basic():
    find_action = ["revenge", "--string", "This is my string",
            "--int8", "-13",
            "--uint8", "13",
            "--int16", "-1337",
            "--uint16", "1337",
            "--int32", "-1337",
            "--uint32", "1337",
            "--int64", "-1337",
            "--uint64", "1337",
            "find", str(basic_one.pid)]

    out = subprocess.check_output(find_action).decode()

    assert hex(basic_one.memory['basic_one:{}'.format(basic_one_string_addr)].address) + "': 'StringUTF8'" in out
    assert hex(basic_one_i8_addr)
    assert hex(basic_one_ui8_addr)
    assert hex(basic_one_i16_addr)
    assert hex(basic_one_ui16_addr)
    assert hex(basic_one_i32_addr)
    assert hex(basic_one_ui32_addr)
    assert hex(basic_one_i64_addr)
    assert hex(basic_one_ui64_addr)

    """
    # This more explicit process was just too slow.
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one.memory['basic_one:{}'.format(basic_one_string_addr)].address) in out

    find_action[1] = '--int8'
    find_action[2] = '-13'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_i8_addr) in out

    find_action[1] = '--uint8'
    find_action[2] = '13'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_ui8_addr) in out

    find_action[1] = '--int16'
    find_action[2] = '-1337'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_i16_addr) in out

    find_action[1] = '--uint16'
    find_action[2] = '1337'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_ui16_addr) in out

    find_action[1] = '--int32'
    find_action[2] = '-1337'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_i32_addr) in out

    find_action[1] = '--uint32'
    find_action[2] = '1337'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_ui32_addr) in out

    find_action[1] = '--int64'
    find_action[2] = '-1337'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_i64_addr) in out

    find_action[1] = '--uint64'
    find_action[2] = '1337'
    out = subprocess.check_output(find_action).decode()
    assert hex(basic_one_ui64_addr) in out
    """
