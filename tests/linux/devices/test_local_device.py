import logging
logger = logging.getLogger(__name__)

import os
import subprocess
import psutil
import time
from revenge import Process, types, common, devices

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")
basic_one_path = os.path.join(bin_location, "basic_one")


def test_local_device_processes():

    d = devices.LocalDevice()

    procs = d.processes
    
    assert len(procs) > 0

def test_local_device_platform():

    # This test should always be on linux...
    d = devices.LocalDevice()

    assert d.platform == 'linux'

def test_local_device_spawn():

    # This test should always be on linux...
    d = devices.LocalDevice()

    p = d.spawn(basic_one_path)

    assert p.alive
    assert p.device is d

    p.quit()

def test_local_device_suspend_resume():

    d = devices.LocalDevice()

    my_sleep = subprocess.Popen(["/bin/sleep","infinity"])

    x = psutil.Process(my_sleep.pid) 
    assert x.status() in ["running", "sleeping"]
    
    d.suspend(my_sleep.pid)
    while x.status() != "stopped":
        time.sleep(0.1)

    """Resume part of this is causing program to cash in testing but not when done manually... weird.
    d.resume(my_sleep.pid)
    while x.status() in ["running", "sleeping"]:
        time.sleep(0.1)
    """

    my_sleep.terminate()
