
import logging
logging.basicConfig(level=logging.DEBUG)

import os

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

from frida_util import Process, types, common, device_types

android = device_types.AndroidDevice(type="usb")
android._wait_for_frida_server()
calc = android.spawn("*calc*", gated=False, load_symbols=[])

def test_basic():
    global msg
    calc = android.attach("*calc*", load_symbols=[])

    msg = []

    def on_message(messages):
        global msg
        msg += messages

    # Just testing that we get all the data back
    with calc.java.BatchContext(on_message=on_message) as context:
        for i in range(2048):
            context.run_script_generic(str(i))

    # Check the input keys
    assert set([int(x[0]) for x in msg]) == set(range(2048))

    # Check the return values
    assert set([x[1] for x in msg]) == set(range(2048))

    # The strings to be evaluated should be... strings
    assert all(isinstance(x[0], str) for x in msg)



