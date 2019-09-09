
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

import random

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")
process = revenge.Process(basic_one_path, resume=False, verbose=False)

basic_one_64_nopie_path = os.path.join(bin_location, "basic_one_64_nopie")
basic_one_64_nopie = revenge.Process(basic_one_64_nopie_path, resume=False)

basic_one_ia32_path = os.path.join(bin_location, "basic_one_ia32")
basic_one_ia32 = revenge.Process(basic_one_ia32_path, resume=False)

basic_one_ia32_nopie_path = os.path.join(bin_location, "basic_one_ia32_nopie")
basic_one_ia32_nopie = revenge.Process(basic_one_ia32_nopie_path, resume=False)

chess_path = os.path.join(bin_location, "ChessAI.so")

def test_load_library():

    process = revenge.Process(basic_one_path, resume=False, verbose=False)

    with pytest.raises(StopIteration):
        process.modules["ChessAI.so"]

    chess = process.modules.load_library(chess_path)

    assert chess is not None
    assert process.memory[chess.symbols['getAiName']()].string_utf8 == "DeepFLARE"
    assert process.memory[process.memory[':getAiGreeting']()].string_utf8 == "Finally, a worthy opponent. Let us begin"

def test_plt():

    #
    # First parse
    # 

    basic_one_mod = process.modules['basic_one']
    assert basic_one_mod.plt & 0xfff == 0x510
    printf = process.memory[basic_one_mod.symbols['plt.printf']]
    assert printf("123456") == 6
    assert 'printf' in process.memory.describe_address(basic_one_mod.symbols['plt.printf'])
    assert 'printf' in process.memory.describe_address(basic_one_mod.symbols['got.printf'])
    assert 'printf' in process.memory.describe_address(process.memory[basic_one_mod.symbols['got.printf']].pointer)

    basic_one_mod = basic_one_64_nopie.modules['basic_one*']
    assert basic_one_mod.plt == 0x4003e0
    printf = basic_one_64_nopie.memory[basic_one_mod.symbols['plt.printf']]
    assert printf("123456") == 6
    assert 'printf' in basic_one_64_nopie.memory.describe_address(basic_one_mod.symbols['plt.printf'])
    assert 'printf' in basic_one_64_nopie.memory.describe_address(basic_one_mod.symbols['got.printf'])
    assert 'printf' in basic_one_64_nopie.memory.describe_address(basic_one_64_nopie.memory[basic_one_mod.symbols['got.printf']].pointer)

    basic_one_mod = basic_one_ia32.modules['basic_one*']
    assert basic_one_mod.plt & 0xfff == 0x3a0
    printf = basic_one_ia32.memory[basic_one_mod.symbols['plt.printf']]
    # This uses thunks... No easy way of testing call through plt rn..
    #assert printf("123456") == 6
    assert 'printf' in basic_one_ia32.memory.describe_address(basic_one_mod.symbols['plt.printf'])
    assert 'printf' in basic_one_ia32.memory.describe_address(basic_one_mod.symbols['got.printf'])
    assert 'printf' in basic_one_ia32.memory.describe_address(basic_one_ia32.memory[basic_one_mod.symbols['got.printf']].pointer)

    basic_one_mod = basic_one_ia32_nopie.modules['basic_one*']
    assert basic_one_mod.plt == 0x80482d0
    printf = basic_one_ia32_nopie.memory[basic_one_mod.symbols['plt.printf']]
    # This uses thunks... No easy way of testing call through plt rn..
    assert printf("123456") == 6
    assert 'printf' in basic_one_ia32_nopie.memory.describe_address(basic_one_mod.symbols['plt.printf'])
    assert 'printf' in basic_one_ia32_nopie.memory.describe_address(basic_one_mod.symbols['got.printf'])
    assert 'printf' in basic_one_ia32_nopie.memory.describe_address(basic_one_ia32_nopie.memory[basic_one_mod.symbols['got.printf']].pointer)

def test_modules_symbols():

    basic_one_mod = process.modules['basic_one']
    assert basic_one_mod.symbols['func'] - basic_one_mod.base == 0x64A
    assert basic_one_mod.symbols['i8'] - basic_one_mod.base == 0x201010
    assert basic_one_mod.symbols['ui8'] - basic_one_mod.base == 0x201011
    assert basic_one_mod.symbols['i16'] - basic_one_mod.base == 0x201012
    assert basic_one_mod.symbols['ui16'] - basic_one_mod.base == 0x201014
    assert basic_one_mod.symbols['i32'] - basic_one_mod.base == 0x201018
    assert basic_one_mod.symbols['ui32'] - basic_one_mod.base == 0x20101C
    assert basic_one_mod.symbols['i64'] - basic_one_mod.base == 0x201020
    assert basic_one_mod.symbols['ui64'] - basic_one_mod.base == 0x201028
    assert isinstance(basic_one_mod.symbols['ui64'].address, types.Pointer)


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
