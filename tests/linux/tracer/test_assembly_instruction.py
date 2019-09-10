
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
from revenge.tracer import contexts
import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")

def test_assembly_instruction_amd64():
    basic_one = revenge.Process(os.path.join(bin_location, 'basic_one'), resume=False, verbose=False, load_symbols='basic_one')

    b = basic_one.memory['basic_one:func'].instruction_block
    str(b)
    repr(b)
    repr(b.instructions[0])

    assert b.instructions[0].mnemonic == 'push'
    assert b.instructions[0].args_str == 'rbp'
    assert len(b.instructions) == 5
    assert b[0] == b.instructions[0]

    basic_one.quit()

def test_assembly_instruction_x86():
    basic_one_ia32 = revenge.Process(os.path.join(bin_location, 'basic_one_ia32'), resume=False, verbose=False, load_symbols='basic_one_ia32')

    b = basic_one_ia32.memory['basic_one_ia32:func'].instruction_block
    repr(b)
    repr(b.instructions[0])

    assert b.instructions[0].mnemonic == 'push'
    assert b.instructions[0].args_str == 'ebp'
    assert len(b.instructions) == 3
    assert b[0] == b.instructions[0]
    assert "__x86.get_pc_thunk" in str(b)

    basic_one_ia32.quit()
