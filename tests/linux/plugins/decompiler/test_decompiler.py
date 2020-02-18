
import logging

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

from time import sleep

from revenge.plugins.decompiler.decompiled import Decompiled, DecompiledItem
from revenge.exceptions import *

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one_ia32_nopie_path = os.path.join(bin_location, "basic_one_ia32_nopie")
ls_path = os.path.join(bin_location, "ls")

def test_decompiler_basic():

    #
    # pie
    #

    process = revenge.Process(basic_one_path, resume=False, verbose=False)

    process.radare2._r2.cmd("aaa")
    sleep(0.2)

    a = process.decompiler.decompile_address("basic_one:0x66d")
    assert len(a) == 1
    assert 0x66d in a
    assert a[0x66d].address == 0x66d
    assert "sym.func" in a[0x66d].src

    process.quit()

    #
    # No pie
    #

    process = revenge.Process(basic_one_ia32_nopie_path, resume=False, verbose=False)

    process.radare2._r2.cmd("aaa")
    sleep(0.2)

    a = process.decompiler.decompile_address(0x08048460)
    assert len(a) == 1
    assert 0x08048460 in a
    assert a[0x08048460].address == 0x08048460
    assert "sym.func" in a[0x08048460].src

    process.quit()

