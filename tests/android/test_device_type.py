
import logging
logger = logging.getLogger(__name__)

from frida_util import Process, types, common, device_types
android = device_types.AndroidDevice(type="usb")

def test_basic_connect():
    assert android.frida_server_running
    assert android.arch in ['arm64', 'x86_64', 'x86', 'arm']
    android.adb("shell uname -a")

def test_spawn():
    
    # Basically testing that these don't except out
    p = android.spawn("com.android.email", gated=False, load_symbols="*dex")
    list(p.threads)
    list(p.modules)
    list(p.memory.maps)

def test_applications():
    calc = android.applications['*calc*']
    p = android.spawn(calc, gated=False, load_symbols=[])

    list(android.applications)
    len(android.applications)


