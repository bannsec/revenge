
import logging
logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")

def test_symbol_basic():
    process = revenge.Process(basic_one_path, resume=False, verbose=False)

    s = revenge.symbols.Symbol(process, name='test', address=123456)
    str(s)
    repr(s)
    hex(s)

    assert s.name == 'test'
    assert s.address == 123456

    assert s.startswith('te')
    assert str(s) == 'test'

    assert s > 1234
    assert s >= 123456
    assert s < 0xffffff
    assert s <= 123456

    process.quit()

def test_symbol_memory():
    process = revenge.Process(basic_one_path, resume=False, verbose=False)

    strlen = process.modules['*libc*'].symbols['strlen']

    # Modern libc, this will just be a lookup for which version of strlen to use
    assert process.memory[strlen.memory()]('test') == 4
    assert process.memory[strlen()]('test') == 4

    process.quit()
