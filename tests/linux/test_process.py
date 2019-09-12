
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types

import time

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one_i8_addr = 0x201010
basic_one_ui8_addr = 0x201011
basic_one_i16_addr = 0x201012
basic_one_ui16_addr = 0x201014
basic_one_i32_addr = 0x201018
basic_one_ui32_addr = 0x20101C
basic_one_i64_addr = 0x201020
basic_one_ui64_addr = 0x201028
basic_one_string_addr = 0x724
basic_open_func_addr = 0x64A

basic_one_ia32_path = os.path.join(bin_location, "basic_one_ia32")

def test_process_arch():
    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    basic_one_ia32 = revenge.Process(basic_one_ia32_path, resume=False, verbose=False, load_symbols='basic_one_ia32')

    assert basic_one.arch == "x64"
    assert basic_one_ia32.arch == "ia32"

    basic_one.quit()
    basic_one_ia32.quit()

def test_process_run_script_generic_async():
    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    # Grab some memory area
    x = list(basic_one.memory.maps)[0]

    # Async mem scan
    out = basic_one.run_script_generic(r"Memory.scan(ptr('{addr}'), 1024, '00', {{onMatch: function (i, size) {{ send(i); }}, onComplete: function () {{send('DONE');}}}});".format(addr=hex(x.base)), unload=True, raw=True, onComplete="DONE")

    # For now, just make sure we got something back
    assert out[0][0] != []

    basic_one.quit()

def test_process_run_script_generic_include_js():

    messages = []

    def on_message(x,y):
        messages.append(x["payload"])

    process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    process.run_script_generic("add_echo()", raw=True, on_message=on_message, unload=False, include_js="echo.js")
    script = process._scripts[0][0]
    script.exports.echo("blergy")
    time.sleep(0.1)
    assert len(messages) == 1
    assert messages[0] == "blergy"

    process.quit()

