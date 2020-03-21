
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
common = revenge.common
from revenge.exceptions import *

import pytest

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

class Blerg:
    @common.validate_argument_types(x=int, y=(float,str))
    def my_func(self, x, y=None):
        """mydoc"""
        return (x, y)

@common.validate_argument_types(x=int, y=(float,str))
def my_func(x, y=None):
    """mydoc"""
    return (x, y)

def test_common_auto_bytes():
    assert common.auto_bytes(b"test") == b"test"
    assert common.auto_bytes("test") == b"test"

def test_common_strip_escapes():
    x = '\x1b[30mHello\x1b[0m'
    y = b'\x1b[30mHello\x1b[0m'
    assert common.strip_ansi_escapes(x) == "Hello"
    assert common.strip_ansi_escapes(y) == b"Hello"

def test_common_validate_argument_types():

    #
    # Classes
    # 

    b = Blerg()

    with pytest.raises(RevengeInvalidArgumentType):
        b.my_func("test")

    with pytest.raises(RevengeInvalidArgumentType):
        b.my_func(x="test")

    with pytest.raises(RevengeInvalidArgumentType):
        b.my_func(1, 1)

    with pytest.raises(RevengeInvalidArgumentType):
        b.my_func(1, y=1)

    with pytest.raises(RevengeInvalidArgumentType):
        b.my_func(y=1)

    assert b.my_func(1) == (1, None)
    assert b.my_func(x=1) == (1, None)
    assert b.my_func(1, 1.1) == (1, 1.1)
    assert b.my_func(1, "1") == (1, "1")
    assert b.my_func.__doc__ == "mydoc"

    #
    # Func
    #

    with pytest.raises(RevengeInvalidArgumentType):
        my_func("test")

    with pytest.raises(RevengeInvalidArgumentType):
        my_func(x="test")

    with pytest.raises(RevengeInvalidArgumentType):
        my_func(1, 1)

    with pytest.raises(RevengeInvalidArgumentType):
        my_func(1, y=1)

    with pytest.raises(RevengeInvalidArgumentType):
        my_func(y=1)

    assert my_func(1) == (1, None)
    assert my_func(x=1) == (1, None)
    assert my_func(1, 1.1) == (1, 1.1)
    assert my_func(1, "1") == (1, "1")
    assert my_func.__doc__ == "mydoc"
    

def test_common_int_to_signed():

    assert revenge.common.int_to_signed(0, 8) == 0
    assert revenge.common.int_to_signed(127, 8) == 127
    assert revenge.common.int_to_signed(128, 8) == -128
    assert revenge.common.int_to_signed(255, 8) == -1

    assert revenge.common.int_to_signed(0, 16) == 0
    assert revenge.common.int_to_signed(2**15-1, 16) == 2**15-1
    assert revenge.common.int_to_signed(2**15, 16) == -2**15
    assert revenge.common.int_to_signed(2**16-1, 16) == -1

    assert revenge.common.int_to_signed(0, 32) == 0
    assert revenge.common.int_to_signed(2**31-1, 32) == 2**31-1
    assert revenge.common.int_to_signed(2**31, 32) == -2**31
    assert revenge.common.int_to_signed(2**32-1, 32) == -1

    assert revenge.common.int_to_signed(0, 64) == 0
    assert revenge.common.int_to_signed(2**63-1, 64) == 2**63-1
    assert revenge.common.int_to_signed(2**63, 64) == -2**63
    assert revenge.common.int_to_signed(2**64-1, 64) == -1

def test_common_auto_int():

    assert revenge.common.auto_int(1) == 1
    assert revenge.common.auto_int('1') == 1
    assert revenge.common.auto_int('0x1') == 1
    assert revenge.common.auto_int('0x10') == 16
    assert revenge.common.auto_int(1.1) == 1.1
    assert revenge.common.auto_int(None) == None

def test_common_load_file():

    process = revenge.Process(os.path.join(bin_location, 'basic_one'), resume=False, verbose=False, load_symbols=['basic_one'])

    with open("/bin/ls","rb") as f:
        ls = f.read()

    #
    # Local read
    #

    ls_local = revenge.common.load_file(process, "/bin/ls")
    assert ls_local.read() == ls
    assert revenge.common.load_file(process, "/notreallyhere") is None

    #
    # Remote ELF read
    #

    process.device.type = 'remote'

    ls_remote = revenge.common.load_file(process, "/bin/ls")
    assert ls_remote.read() == ls
    assert revenge.common.load_file(process, "/notreallyhere") is None

    #
    # Bad platform
    #

    #process.device_platform = 'not_a_real_platform'
    #assert revenge.common.load_file(process, "/bin/ls") is None

    process.quit()
