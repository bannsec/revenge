
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types
from revenge.exceptions import *

import pytest

from revenge.techniques import Technique, Techniques

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one")

def test_techniques_basic():
    p = revenge.Process(basic_one_path, resume=False, verbose=False)

    list(p.techniques)

    # All techniques (as dict) should be subclass of Technique
    assert all(issubclass(x, Technique) for x in p.techniques)

    # Everything in dict should be a callable property
    assert all(callable(getattr(p.techniques, x.__name__)) for x in p.techniques)

    repr(p.techniques)

    for t in p.techniques:
        assert t.TYPE in Technique.TYPES

    # Just make sure we're populating at least
    assert p.techniques.NativeInstructionTracer is not None

    # Try giving a memory map range
    range = p.memory.maps[p.memory['strlen'].address]
    tech = p.techniques.NativeInstructionTracer(exec=True)
    tech._technique_code_range(range)

    # Try using two stalking techniques at once
    time = p.memory['time']
    timeless = p.techniques.NativeTimelessTracer()
    trace = p.techniques.NativeInstructionTracer(exec=True)
    with pytest.raises(RevengeInvalidArgumentType):
        time(0, techniques=[timeless, trace])

    p.quit()
