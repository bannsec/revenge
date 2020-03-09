
import logging

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

from revenge.plugins.decompiler.decompiled import Decompiled
from revenge.plugins.dwarf.dwarf_decompiler import DwarfDecompiler

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

    basic.dwarf.add_source_path("/not_real_path")
    assert b"/not_real_path" not in basic.dwarf.decompiler.SOURCE_DIRECTORIES

    # Reset our source directories for testing purposes
    DwarfDecompiler.SOURCE_DIRECTORIES = [b'.']
    assert basic.dwarf.decompile_address(basic.dwarf.functions[b'main'].address) is None
    basic.dwarf.add_source_path(bin_location)

    #
    # Decompile Address
    #
    
    decomp = basic.dwarf.decompile_address(basic.dwarf.functions[b'main'].address)
    assert isinstance(decomp, Decompiled)

    assert len(decomp) == 1
    # Make sure all the relocation/base adjustments come back correct
    assert list(decomp)[0] == basic.dwarf.functions[b'main'].address
    item = decomp[basic.dwarf.functions[b'main'].address]
    repr(item)
    str(item)
    assert item.src == b'int main(int argc, char **argv) {'

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
