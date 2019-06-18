
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
from frida_util.tracer import contexts
import frida_util
types = frida_util.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")

basic_one = frida_util.Process(os.path.join(bin_location, 'basic_one'), resume=False, verbose=False, load_symbols='basic_one')
basic_one_ia32 = frida_util.Process(os.path.join(bin_location, 'basic_one_ia32'), resume=False, verbose=False, load_symbols='basic_one_ia32')

def test_assembly_instruction_amd64():
    b = basic_one.memory['basic_one:func'].instruction_block
    str(b)
    repr(b)
    repr(b.instructions[0])

    assert b.instructions[0].mnemonic == 'push'
    assert b.instructions[0].args_str == 'rbp'
    assert len(b.instructions) == 5

def test_assembly_instruction_x86():
    b = basic_one_ia32.memory['basic_one_ia32:func'].instruction_block
    str(b)
    repr(b)
    repr(b.instructions[0])

    assert b.instructions[0].mnemonic == 'push'
    assert b.instructions[0].args_str == 'ebp'
    assert len(b.instructions) == 3
