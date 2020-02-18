
import logging

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

from revenge.plugins.decompiler.decompiled import Decompiled, DecompiledItem
from revenge.exceptions import *

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one")

def test_decompiled_basic():
    process = revenge.Process(basic_one_path, resume=False, verbose=False)

    decomp = Decompiled(process)

    repr(decomp)
    len(decomp)

    decomp[0x12345].address = 0x12345
    decomp[0x12345].src = "if ( 1 ) "

    repr(decomp)
    len(decomp)

    print(decomp[0x12345])
    repr(decomp[0x12345])

    with pytest.raises(RevengeInvalidArgumentType):
        decomp[0x12345].highlight = 'blerg'

    decomp[0x12345].highlight = 'MAGENTA'
    print(decomp[0x12345])
    repr(decomp[0x12345])

    decomp[0].address = 0
    decomp[0x99999].address = 0x99999
    decomp[0x99999].src = "blerg () "

    assert set(list(decomp)) == set([0, 0x12345, 0x99999])

    print(decomp)
    process.quit()
