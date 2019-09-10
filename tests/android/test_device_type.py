
import logging
logging.basicConfig(level=logging.DEBUG)

import os
from time import sleep

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

from revenge import Process, types, common, device_types
android = device_types.AndroidDevice(type="usb")
android._wait_for_frida_server()

veryandroidso = os.path.join(bin_location, "ooo.defcon2019.quals.veryandroidoso.apk")

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
    p.quit()

    # Spawn with splat
    p = android.spawn("*calc*", gated=False, load_symbols=[])
    p.quit()

def test_attach():
    p = android.attach(android.device.get_frontmost_application(), load_symbols=[])
    p.quit()

def test_applications():
    calc = android.applications['*calc*']
    p = android.spawn(calc, gated=False, load_symbols=[])

    list(android.applications)
    len(android.applications)

    p.quit()

def test_install_uninstall_application():
    android.install(veryandroidso)
    # Race condition for install vs run
    sleep(0.5)
    very = android.applications['*ooo*']
    p = android.spawn(very, gated=False, load_symbols=[])
    android.uninstall(very)

    p.quit()

def test_repr():
    repr(android)
