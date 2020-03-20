
import logging
logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types
from revenge.functions import Functions

import random
from revenge.exceptions import *

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_dwarf_x64_path = os.path.join(bin_location, "basic_dwarf_x64")

def test_functions_basic():
    p = revenge.Process(basic_dwarf_x64_path, resume=False, verbose=False)

    basic = p.modules['basic*'] 

    main = p.memory[basic.symbols['main']]
    func1 = p.memory[basic.symbols['func1']]

    functions = Functions(p)
    assert functions['blerg'] is None
    assert len(functions) == 0

    with pytest.raises(RevengeInvalidArgumentType):
        functions['blerg'] = 1

    functions['main'] = main
    assert functions['main'] is main
    assert functions[b'main'] is main

    assert len(functions) == 1
    assert repr(functions) == "<Functions 1>"

    functions[func1] = 'func1'
    assert functions['func1'] is func1
    assert functions[b'func1'] is func1

    assert len(functions) == 2
    assert repr(functions) == "<Functions 2>"

    assert functions[main] == b"main"
    assert functions[main.address] == b"main"
    # Because these MemoryBytes aren't ranges right now
    assert functions[main.address+8] is None

    main = p.memory[basic.symbols['main']:basic.symbols['main']+16]
    functions['main'] = main
    assert len(functions) == 2 # Should overwrite old one
    # This should now fall in the range
    assert functions[main.address+8] == b"main"

    functions[func1.address:func1.address+16] = "func1"
    assert functions[func1.address+8] == b"func1"

    assert set(functions) == set([b"main", b"func1"])
    assert "main" in str(functions)
    assert "func1" in str(functions)

    p.quit()
