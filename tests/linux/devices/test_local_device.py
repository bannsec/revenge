import logging
logger = logging.getLogger(__name__)

import os
from revenge import Process, types, common, devices

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")
basic_one_path = os.path.join(bin_location, "basic_one")


def test_local_device_processes():

    d = devices.LocalDevice()

    procs = d.processes
    
    assert len(procs) > 0
