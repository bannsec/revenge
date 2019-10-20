
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
basic_spawn_path = os.path.join(bin_location, "basic_spawn")

def test_process_spawn_argv():
    # TODO: Add envp tests when implemented

    argc = []
    argv = []
    done = []

    def argc_on_msg(x,y):
        argc.append(x['payload'])

    def argv_on_msg(x,y):
        argv.append(x['payload'])

    def done_on_msg(x,y):
        done.append(x['payload'])

    basic_spawn = revenge.Process([basic_spawn_path,'one','two','three'], resume=False, verbose=False)
    symbols = basic_spawn.modules['basic_spawn'].symbols
    
    echo_argc = symbols['echo_argc'].memory
    echo_argc.return_type = types.Int32
    echo_argc.argument_types = types.Int32
    echo_argc.replace_on_message = argc_on_msg
    echo_argc.replace = "function (s) { send(s); return original(s); }"

    echo_argv = symbols['echo_argv'].memory
    echo_argv.return_type = types.Pointer
    echo_argv.argument_types = types.Pointer
    echo_argv.replace_on_message = argv_on_msg
    echo_argv.replace = """function (s) {
        var i = s;
        var j = i.readPointer();

        while ( j != 0) {
            send(j.readUtf8String());
            i = i.add(8);
            j = i.readPointer();
        }
        return original(s);
    }
    """

    d = symbols['done'].memory
    d.replace_on_message = done_on_msg
    d.replace = "function () { send(1); return; }"

    basic_spawn.memory[basic_spawn.entrypoint].breakpoint = False

    # Make sure we're done first
    while done == []:
        continue

    assert argc[0] == 4 
    assert os.path.basename(argv[0]) == "basic_spawn"
    assert argv[1:] == ["one", "two", "three"]

    basic_spawn.quit()

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

def test_process_run_script_generic_include_js_dispose():

    process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    mem1 = process.memory.alloc(8)
    mem2 = process.memory.alloc(8)

    mem1.int32 = 0
    mem2.int32 = 0

    script = """dispose_push(function () {{ {}.writeS32(1337); }}); dispose_push(function () {{ {}.writeS32(1337); }});""".format(mem1.address.js, mem2.address.js)

    process.run_script_generic(script, raw=True, unload=True, include_js="dispose.js")

    assert mem1.int32 == 1337
    assert mem2.int32 == 1337

    process.quit()


if __name__ == '__main__':
    test_process_spawn_argv()
