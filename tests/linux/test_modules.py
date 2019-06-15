
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import pytest
import frida_util
types = frida_util.types

import random

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")
process = frida_util.Process(action="find", target="basic_one", file=basic_one_path, resume=False, verbose=False)

def test_modules_by_int():

    libc = process.modules['libc*']
    
    for _ in range(10):
        r = random.randint(libc.base, libc.base + libc.size)
        assert process.modules[r] == libc

    assert process.modules[123] == None

def test_modules_basic():

    assert process.modules['libc*'] is not None
    assert process.modules['basic_one'] is not None


    m = process.modules['basic_one']

    # Just make sure it does something..
    repr(m)

    with pytest.raises(Exception):
        m.name = 12

    m.path = "test"
    assert m.path == "test"

    with pytest.raises(Exception):
        m.path = 12

    assert isinstance(m.base, types.Pointer)

    m.base = types.Pointer(123)
    assert m.base == 123

    # Hopefully this doesn't change all that often
    assert len(process.modules) == 10

    # Just making sure this returns something for now
    repr(process.modules)

    assert "basic_one" in str(process.modules)

    with pytest.raises(NotImplementedError):
        process.modules[:]
    
    with pytest.raises(StopIteration):
        process.modules["Not a valid module"]
