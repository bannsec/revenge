
import logging
logging.basicConfig(level=logging.DEBUG)

import os

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

from revenge import Process, types, common, devices
android = devices.AndroidDevice(type="usb")
android._wait_for_frida_server()

def test_spawn():
    
    p = android.spawn("com.android.email", gated=False, load_symbols=[])

    # First time is returned as in-memory io
    f = common.load_file(p, '/system/lib64/libssl.so')
    assert not hasattr(f, "name")

    # Second time is returned as io from file cache
    f = common.load_file(p, '/system/lib64/libssl.so')
    assert hasattr(f, "name")
    assert f.name.startswith("/tmp/")

    p.quit()
