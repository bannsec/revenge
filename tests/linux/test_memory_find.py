
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import time
import pytest

import revenge
types = revenge.types

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

process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

def test_memory_find_ranges():

    # Invalid range
    with pytest.raises(Exception):
        f = process.memory.find(types.Int64(1), ranges=12)

    # Single range ability
    range = next(m for m in process.memory.maps if m.file is not None and "basic_one" in m.file)
    f = process.memory.find(types.Int64(1), ranges=range)
    f.ranges = range

def test_memory_find_thing():

    with pytest.raises(Exception):
        f = process.memory.find(12)

def test_memory_find_completed():

    class test(object):
        def unload(self):
            return

    f = process.memory.find(types.Int64(1))
    f.sleep_until_completed()
    f._script = [test(), '']
    f.completed = True
    assert f._script == None

def test_memory_find_repr():

    f = process.memory.find(types.Int64(1))
    f.sleep_until_completed()
    repr(f)
    f.completed = False
    repr(f)

def test_memory_find_del():

    class test(object):
        def unload(self):
            return

    f = process.memory.find(types.Int64(1))
    f.sleep_until_completed()
    time.sleep(0.1)
    f.__del__()

    assert f._script is None
    f._script = [test(),'']
    f.__del__()
    assert f._script is None

def test_memory_find_iter():

    f = process.memory.find(types.Int64(1))
    f.sleep_until_completed()

    assert len(f) > 0
    assert all(type(x) is types.Pointer for x in f)

    # Excersize warning path
    f.completed = False
    list(f)


def test_memory_on_message():

    f = process.memory.find(types.StringUTF8("This is my string"))
    f.sleep_until_completed()    

    payload = {'payload': [{'address': 1337}, {'address': 31337}]}
    f._on_message(payload, None)
    assert 1337 in f
    assert 31337 in f

    f.completed = False
    f._script = None
    payload = {'payload': "DONE"}
    f._on_message(payload, None)
    assert f.completed == True

    # Unexpected message
    payload = {'payload': 1.12}
    f._on_message(payload, None)


def test_memory_find_ranges():

    ranges = [m for m in process.memory.maps if m.file is not None and "basic_one" in m.file]

    f = process.memory.find(types.StringUTF8("This is my string"), ranges=ranges)
    f.sleep_until_completed()

    assert len(f) > 0
    for addr in f:
        assert process.memory[addr].string_utf8 == "This is my string"

def test_memory_find_general():

    f = process.memory.find(types.StringUTF8("This is my string"))
    f.sleep_until_completed()
    
    assert len(f) > 0
    for addr in f:
        assert process.memory[addr].string_utf8 == "This is my string"

    # Test invalid find
    with pytest.raises(Exception):
        util.memory.find(1.12)

    """ This doesn't work. Probably because Frida is hiding it's own memory regions from returning

    my_string = types.StringUTF8('Hello world!')
    mem = process.memory.alloc_string(my_string)

    f = process.memory.find(my_string)
    f.sleep_until_completed()

    assert mem.address in f
    """
