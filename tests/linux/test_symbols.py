
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
process = revenge.Process(basic_one_path, resume=False, verbose=False)


def test_symbol_basic():

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


    
