
import logging
logging.basicConfig(level=logging.DEBUG)

import os

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

from revenge import Process, types, common, devices
from revenge.java import JavaClass

android = devices.AndroidDevice(type="usb")
android._wait_for_frida_server()

def test_basic():
    p = android.spawn("*email*", gated=False, load_symbols=[])
    c = p.java.classes
    repr(c)
    p.quit()

def test_getitem():
    p = android.spawn("com.android.email", gated=False, load_symbols=[])
    c = p.java.classes
    calc = c['android.app.admin.*']
    assert calc != []
    for x in calc:
        assert isinstance(x, JavaClass)

    assert isinstance(c[12], JavaClass)
    
    p.quit()

