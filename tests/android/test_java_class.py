
import logging
logging.basicConfig(level=logging.DEBUG)

import os

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

from frida_util import Process, types, common, device_types
from frida_util.java.java_class import JavaClass

android = device_types.AndroidDevice(type="usb")
android._wait_for_frida_server()

veryandroidso = os.path.join(bin_location, "ooo.defcon2019.quals.veryandroidoso.apk")

calc = android.spawn("*calc*", gated=False, load_symbols=[])

def test_is_safe_method_name():
    assert not JavaClass._is_safe_method_name("test$100")
    assert JavaClass._is_safe_method_name("This_is_a_methodName")

def test_reflective_method_and_field_discovery():
    android.install(veryandroidso)
    p = android.spawn("ooo.defcon2019.quals.veryandroidoso", gated=False, load_symbols=[])

    # Run this twice. First time should cache miss, second time should cache hit with same result.
    for i in range(2):
        MainActivity = p.java.classes['ooo.defcon2019.quals.veryandroidoso.MainActivity']

        assert hasattr(MainActivity, 'fail')
        assert isinstance(MainActivity.fail, JavaClass)
        assert MainActivity.fail._full_description == 'private void ooo.defcon2019.quals.veryandroidoso.MainActivity.fail()'
        assert MainActivity.fail._is_method
        assert not MainActivity.fail._is_field

        assert hasattr(MainActivity, 'win')
        assert isinstance(MainActivity.win, JavaClass)
        assert MainActivity.win._full_description == 'private void ooo.defcon2019.quals.veryandroidoso.MainActivity.win()'
        assert MainActivity.win._is_method
        assert not MainActivity.win._is_field

        assert hasattr(MainActivity, 'onCreate')
        assert isinstance(MainActivity.onCreate, JavaClass)
        assert MainActivity.onCreate._full_description == 'protected void ooo.defcon2019.quals.veryandroidoso.MainActivity.onCreate(android.os.Bundle)'
        assert MainActivity.onCreate._is_method
        assert not MainActivity.onCreate._is_field

        assert hasattr(MainActivity, 'parse')
        assert isinstance(MainActivity.parse, JavaClass)
        assert MainActivity.parse._full_description == 'private int[] ooo.defcon2019.quals.veryandroidoso.MainActivity.parse(java.lang.String)'
        assert MainActivity.parse._is_method
        assert not MainActivity.parse._is_field

        assert hasattr(MainActivity, 'TAG')
        assert isinstance(MainActivity.TAG, JavaClass)
        assert MainActivity.TAG._full_description == 'public static final java.lang.String ooo.defcon2019.quals.veryandroidoso.MainActivity.TAG'
        assert not MainActivity.TAG._is_method
        assert MainActivity.TAG._is_field
        assert MainActivity.TAG._class == "class java.lang.String"
        assert hasattr(MainActivity.TAG, "concat") # Testing some method populations
        assert hasattr(MainActivity.TAG, "charAt")

        # We should have saved this off to the cache
        assert p.java._cache_reflected_methods[MainActivity._name] != []

def test_find_active_instance():
    android.install(veryandroidso)
    p = android.spawn("ooo.defcon2019.quals.veryandroidoso", gated=False, load_symbols=[])

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

