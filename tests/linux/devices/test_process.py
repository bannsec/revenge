import logging
logger = logging.getLogger(__name__)

import os
from revenge.devices.process import Process

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")
basic_one_path = os.path.join(bin_location, "basic_one")


def test_process_basic():

    p = Process(name="calc.exe", pid=1337)

    assert p.name == "calc.exe"
    assert p.pid == 1337

    str(p)
    repr(p)
