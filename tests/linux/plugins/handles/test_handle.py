
import logging

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

from revenge.plugins.handles import Handle

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one")

def test_handle_basic():
    process = revenge.Process(basic_one_path, resume=False, verbose=False)

    #
    # Handle without name
    #

    handle = Handle(process, handle=1337)
    assert handle.handle == 1337
    assert handle.name is None

    #
    # Handle with name
    #

    handle = Handle(process, handle=1337, name="something")
    assert handle.handle == 1337
    assert handle.name == "something"

    process.quit()

