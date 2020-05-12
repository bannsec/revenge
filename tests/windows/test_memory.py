
import logging
import os
import time

import revenge

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_one_64_path = os.path.join(bin_location, "basic_one_64.exe")


def test_memory_basic():

    process = revenge.Process(basic_one_64_path, resume=False, load_symbols='basic_one_64.exe')
    process.engine.resume(process.pid)

    process.stdout("i8: ")
    assert process.memory[int(process.stdout("\n"), 16)].int8 == -13
    process.stdout("ui8: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint8 == 13

    process.stdout("i16: ")
    assert process.memory[int(process.stdout("\n"), 16)].int16 == -1337
    process.stdout("ui16: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint16 == 1337

    process.stdout("i32: ")
    assert process.memory[int(process.stdout("\n"), 16)].int32 == -1337
    process.stdout("ui32: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint32 == 1337

    process.stdout("i64: ")
    assert process.memory[int(process.stdout("\n"), 16)].int64 == -1337
    process.stdout("ui64: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint64 == 1337

    process.stdout("func: ")
    func = process.memory[int(process.stdout("\n"), 16)]
    assert func() == 12

    find = process.memory.find(types.StringUTF8("func: 0x%p\n"))
    find.sleep_until_completed()
    assert len(find) == 1
    assert process.memory[list(find)[0]].string_utf8 == "func: 0x%p\n"

    process.quit()


def test_memory_bytes_on_enter():
    process = revenge.Process(basic_one_64_path, resume=False, verbose=False)

    puts_output = []

    def on_msg(x, y):
        puts_output.append(x['payload'])

    puts = process.memory['puts']
    puts.replace_on_message = on_msg
    puts.on_enter = """function (args) { send(args[0].readUtf8String()) }"""

    puts("Hello world!")
    while puts_output == []:
        pass

    assert puts_output == ["Hello world!"]

    puts.on_enter = None
    puts_output = []

    puts("Goodbye world!")
    time.sleep(0.1)
    assert puts_output == []

    puts.replace_on_message = lambda: 1
    puts.on_enter = """function (args) { send(args[0].readUtf8String()) }"""
    puts.replace_on_message = on_msg

    puts("Blerg")

    while puts_output == []:
        pass

    assert puts_output == ["Blerg"]

    process.quit()


def test_replace_with_js():
    messages = []

    def on_message(x, y):
        messages.append(x['payload'])

    process = revenge.Process(basic_one_64_path, resume=False, load_symbols=[])

    strlen = process.memory[':strlen']

    # "original" is helper var that should always be the original function
    strlen.replace = """function (x) { send(x.readUtf8String()); return original(x)-1; }"""

    # Adding this after setting replace to test that it updates the replace
    strlen.argument_types = types.Pointer
    strlen.return_type = types.Int64
    strlen.replace_on_message = on_message

    assert strlen("123456") == 5
    while messages == []:
        pass
    assert messages == ["123456"]

    # implementation is just a pass-through
    assert strlen.replace == strlen.implementation

    strlen.implementation = None
    assert strlen("123456") == 6

    assert strlen.replace == strlen.implementation

    process.quit()
