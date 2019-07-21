
import logging
logging.basicConfig(level=logging.DEBUG)

import os

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

from frida_util import Process, types, common, device_types

android = device_types.AndroidDevice(type="usb")
android._wait_for_frida_server()

# OOO{fab43416484944beba}
veryandroidso = os.path.join(bin_location, "ooo.defcon2019.quals.veryandroidoso.apk")
android.install(veryandroidso)

android.spawn("ooo.defcon2019.quals.veryandroidoso", gated=False, load_symbols=[])
calc = android.spawn("*calc*", gated=False, load_symbols=[])

def test_find_active_instance():
    p = android.attach("*ooo*", load_symbols=[])

    MainActivity = p.java.classes['ooo.defcon2019.quals.veryandroidoso.MainActivity']

    M = p.java.find_active_instance(MainActivity)
    assert M is not None
    assert M.parse("OOO{fab43416484944beba}")() == [250,180,52,22,72,73,68,190,186]

    M = p.java.find_active_instance('ooo.defcon2019.quals.veryandroidoso.MainActivity')
    assert M is not None
    assert M.parse("OOO{fab43416484944beba}")() == [250,180,52,22,72,73,68,190,186]

def test_basic():
    calc = android.attach("*calc*", load_symbols=[])
    calc_classes = calc.java.classes
    jclass = calc_classes[5]
    repr(jclass)
    str(jclass)

def test_call():
    calc = android.attach("*calc*", load_symbols=[])
    calc_classes = calc.java.classes
    log = calc_classes['android.util.Log']
    x = log('test')
    assert str(x) == "Java.use('android.util.Log').$new('test')"

def test_methods():
    calc = android.attach("*calc*", load_symbols=[])
    calc_classes = calc.java.classes
    log = calc_classes['android.util.Log']
    x = log.w("test1", "test2")
    assert str(x) == "Java.use('android.util.Log').w('test1','test2')"

    x = log.w.s("test1", "test2")
    assert str(x) == "Java.use('android.util.Log').w.s('test1','test2')"

def test_send_log():
    calc = android.attach("*calc*", load_symbols=[])
    calc_classes = calc.java.classes
    log = calc_classes['android.util.Log']

    # Long way
    x = log.w("test1", "test2")
    calc.java.run_script_generic(x, raw=True, unload=True)

    # Short-hand
    log.d("test3", "test4")()

    # TODO: Hook this test into a logcat monitor to ensure it gets logged

def test_implementation():
    calc = android.attach("*calc*", load_symbols=[])
    calc_classes = calc.java.classes
    Math = calc_classes['java.lang.Math']
    assert isinstance(Math.random()(), float)

    Math.random.implementation = "function () { return 123; }"
    assert Math.random()() == 123
    assert Math.random()() == 123
    assert Math.random()() == 123
    Math.random.implementation = None

    assert Math.random()() != 123

