
import logging
logger = logging.getLogger(__name__)

import os
import pytest
from revenge.devices.process import Process, Processes
from revenge.exceptions import *

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")
basic_one_path = os.path.join(bin_location, "basic_one")


def test_processes_basic():

    p = Process(name="calc.exe", pid=1337)

    procs = Processes()
    str(p)
    repr(p)
    assert len(procs) == 0

    procs = Processes([])
    assert len(procs) == 0
    procs = Processes(())
    assert len(procs) == 0
    list(procs)

    procs = Processes(p)
    str(p)
    repr(p)
    assert len(procs) == 1
    assert list(procs)[0] is p

    procs = Processes([p])
    str(p)
    repr(p)
    assert len(procs) == 1

    with pytest.raises(RevengeInvalidArgumentType):
        procs = Processes(1)

    with pytest.raises(RevengeInvalidArgumentType):
        procs = Processes([p,1])
