
import logging
logging.basicConfig(level=logging.DEBUG)

import os

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

from frida_util import Process, types, common, device_types
from frida_util.java import JavaClass

android = device_types.AndroidDevice(type="usb")
android._wait_for_frida_server()

def test_basic():
    p = android.spawn("*email*", gated=False, load_symbols=[])
    c = p.java.classes
    repr(c)

def test_getitem():
    p = android.spawn("*calc*", gated=False, load_symbols=[])
    c = p.java.classes
    assert c['*calculator2*'] != []
    for x in c['*calculator2*']:
        assert isinstance(x, JavaClass)

    assert isinstance(c[12], JavaClass)

