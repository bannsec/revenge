
import logging
import os

from revenge import common, devices

logging.basicConfig(level=logging.DEBUG)


here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

android = devices.AndroidDevice(type="usb")
android._wait_for_frida_server()


def test_spawn():
    p = android.spawn("com.android.email", gated=False, load_symbols=[])

    # File should always be opened as a local cached version
    f = common.load_file(p, '/system/lib64/libssl.so')
    assert hasattr(f, "name")
    assert f.name.startswith("/tmp/")

    p.quit()
