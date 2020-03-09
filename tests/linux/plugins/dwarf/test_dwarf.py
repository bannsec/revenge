
import logging

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_dwarf_x64_path = os.path.join(bin_location, "basic_dwarf_x64")
basic_dwarf_i686_path = os.path.join(bin_location, "basic_dwarf_i686")
basic_dwarf_nopie_i686_path = os.path.join(bin_location, "basic_dwarf_nopie_i686")

def dwarf_basic(process):
    """Same tests for different archs."""
    basic = process.modules['basic_dwarf*']
    libc = process.modules['*libc*']

    assert basic.dwarf.has_debug_info == True
    assert libc.dwarf.has_debug_info == False

    funcs = ["main", "func1", "func2"]
    for func in funcs:
        # Check that the dwarf info matches up with what we resolved for symbols
        assert basic.dwarf.functions[func.encode()].address == basic.symbols[func].address

    main = basic.dwarf.functions[b'main']
    assert basic.dwarf.lookup_function(main.address) == b"main"
    assert basic.dwarf.lookup_function(main.address + 5) == b"main"
    assert basic.dwarf.lookup_function(1337) is None

    assert basic.dwarf.lookup_file_line(main.address) == (b'basic_dwarf.c', 12)
    assert basic.dwarf.lookup_file_line(basic.dwarf.functions[b'func1'].address) == (b'basic_dwarf.c', 4)
    assert basic.dwarf.lookup_file_line(basic.dwarf.functions[b'main'].address_stop-1) == (b'basic_dwarf.c', 21)

def test_dwarf_x64_basic():
    process = revenge.Process(basic_dwarf_x64_path, resume=False, verbose=False)
    dwarf_basic(process)
    process.quit()

def test_dwarf_i686_basic():
    process = revenge.Process(basic_dwarf_i686_path, resume=False, verbose=False)
    dwarf_basic(process)
    process.quit()

def test_dwarf_i686_nopie_basic():
    process = revenge.Process(basic_dwarf_nopie_i686_path, resume=False, verbose=False)
    dwarf_basic(process)
    process.quit()
