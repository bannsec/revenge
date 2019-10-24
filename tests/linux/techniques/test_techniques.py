
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types

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
    assert p.techniques.InstructionTracer is not None

    p.quit()
