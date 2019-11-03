
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import random
import numpy as np
import time
from copy import copy
import re

import pytest

import revenge
from revenge.memory import MemoryRange
types = revenge.types
from revenge.exceptions import *

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")

crackme_count_path = os.path.join(bin_location, "crackme_count")

util = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
basic_one_module = util.modules['basic_one']
basic_one_i8_addr = basic_one_module.symbols['i8'].address
basic_one_ui8_addr = basic_one_module.symbols['ui8'].address
basic_one_i16_addr = basic_one_module.symbols['i16'].address
basic_one_ui16_addr = basic_one_module.symbols['ui16'].address
basic_one_i32_addr = basic_one_module.symbols['i32'].address
basic_one_ui32_addr = basic_one_module.symbols['ui32'].address
basic_one_i64_addr = basic_one_module.symbols['i64'].address
basic_one_ui64_addr = basic_one_module.symbols['ui64'].address
basic_one_string_addr = 0x724
basic_open_func_addr = basic_one_module.symbols['func'].address


basic_two_path = os.path.join(bin_location, "basic_two")
basic_two_func_addr = 0x64A
basic_two_i32_addr = 0x201020
basic_two_f_addr = 0x201010
basic_two_d_addr = 0x201018

basic_looper_path = os.path.join(bin_location, "basic_looper")

def test_memory_call_with_technique():
    p = revenge.Process(crackme_count_path, resume=False, verbose=False)

    win = p.memory['crackme_count:win']
    win_ret = win.address + 0x78

    # First time around we're seeing setup instructions too..
    win._call_as_thread('bbbb')
    
    trace = p.techniques.NativeInstructionTracer(exec=True)
    assert win('bbbb', techniques=trace) == 0
    t1 = list(trace)[0]
    t1.wait_for(win_ret)
    time.sleep(0.1)
    assert len(t1) > 0

    trace = p.techniques.NativeInstructionTracer(exec=True)
    assert win('fbbb', techniques=trace) == 0
    t2 = list(trace)[0]
    t2.wait_for(win_ret)
    time.sleep(0.1)
    assert len(t2) > len(t1)

    trace = p.techniques.NativeInstructionTracer(exec=True)
    assert win('flbb', techniques=trace) == 0
    t3 = list(trace)[0]
    t3.wait_for(win_ret)
    time.sleep(0.1)
    assert len(t3) > len(t2)

    trace = p.techniques.NativeInstructionTracer(exec=True)
    assert win('flab', techniques=trace) == 0
    t4 = list(trace)[0]
    t4.wait_for(win_ret)
    time.sleep(0.1)
    assert len(t4) > len(t3)

    trace = p.techniques.NativeInstructionTracer(exec=True)
    assert win('flag', techniques=trace) == 1
    t5 = list(trace)[0]
    t5.wait_for(win_ret)
    time.sleep(0.1)
    assert len(t5) > len(t4)

    p.quit()

def test_memory_call_as_thread():
    p = revenge.Process(basic_one_path, resume=False, verbose=False)

    mystr = p.memory.alloc_string("blerg")

    strlen = p.memory['strlen']
    strlen.argument_types = types.Pointer
    strlen.return_type = types.Int

    assert strlen._call_as_thread(mystr) == 5
    assert strlen._call_as_thread(mystr) == 5 # Uses cache
    assert strlen._call_as_thread("blerg") == 5
    assert len(p.memory._thread_call_cache) == 1
    assert list(p.memory._thread_call_cache.keys())[0].startswith(hex(strlen.address))

    # Test implicit argument type as Pointer
    strlen = p.memory['strlen']
    strlen.return_type = types.Int
    assert strlen._call_as_thread(mystr) == 5
    strlen.argument_types = []
    assert strlen._call_as_thread(mystr) == 5

    time = p.memory['time']
    assert abs(time(0) - time._call_as_thread(0)) < 2

    atof = p.memory['atof']
    atof.return_type = types.Double
    assert atof._call_as_thread("12.123") == 12.123
    assert atof._call_as_thread("42.42") == 42.42

    strtof = p.memory['strtof']
    strtof.return_type = types.Float
    assert abs(strtof._call_as_thread("12.123",0) - 12.123) < 0.001

    with pytest.raises(RevengeInvalidArgumentType):
        # Not valid atm
        strlen._call_as_thread("blerg", context=1)

    with pytest.raises(RevengeInvalidArgumentType):
        # Not a valid technique
        strlen._call_as_thread("blerg", techniques=1)

    p.quit()

def test_memory_cast_struct(caplog):
    process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    basic_one_module = process.modules['basic_one']
    basic_one_i8_addr = basic_one_module.symbols['i8'].address
    
    # Just need scratch space
    addr = basic_one_i8_addr

    struct = types.Struct()
    struct.add_member('test1', types.Int32(-5))
    struct.add_member('test2', types.Int8(-12))
    struct.add_member('test3', types.UInt16(16))
    struct.add_member('test4', types.Pointer(4444))
    struct.add_member('test5', types.Int16) # This should cause warning
    struct.add_member('test6', types.Pointer(5555))

    mem = process.memory[addr]

    assert mem.cast(types.Struct) is None
    s = mem.cast(struct)
    assert s is struct
    assert s.memory is mem

    process.quit()


def test_memory_write_struct(caplog):
    process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    basic_one_module = process.modules['basic_one']
    basic_one_i8_addr = basic_one_module.symbols['i8'].address
    
    # Just need scratch space
    addr = basic_one_i8_addr

    struct = types.Struct()
    struct.add_member('test1', types.Int32(-5))
    struct.add_member('test2', types.Int8(-12))
    struct.add_member('test3', types.UInt16(16))
    struct.add_member('test4', types.Pointer(4444))
    struct.add_member('test5', types.Int16) # This should cause warning
    struct.add_member('test6', types.Pointer(5555))

    mem = process.memory[addr]
    caplog.clear()
    mem.struct = struct

    assert "was left uninitialized" in caplog.records[0].msg
    caplog.clear()

    assert mem.int32 == -5
    assert process.memory[addr+4].int8 == -12
    assert process.memory[addr+4+1].uint16 == 16
    assert process.memory[addr+4+1+2].pointer == 4444
    assert process.memory[addr+4+1+2+8+2].pointer == 5555

    process.quit()


def test_memory_setitem():
    process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    basic_one_module = process.modules['basic_one']
    basic_one_i8_addr = basic_one_module.symbols['i8'].address
    
    # Just need scratch space
    addr = basic_one_i8_addr

    process.memory[addr] = types.Int8(-4)
    assert process.memory[addr].int8 == -4

    process.memory[addr] = types.UInt8(4)
    assert process.memory[addr].uint8 == 4

    process.memory[addr] = types.Int16(-4)
    assert process.memory[addr].int16 == -4

    process.memory[addr] = types.UInt16(4)
    assert process.memory[addr].uint16 == 4

    process.memory[addr] = types.Int32(-4)
    assert process.memory[addr].int32 == -4

    process.memory[addr] = types.UInt32(4)
    assert process.memory[addr].uint32 == 4

    process.memory[addr] = types.Int64(-4)
    assert process.memory[addr].int64 == -4

    process.memory[addr] = types.UInt64(4)
    assert process.memory[addr].uint64 == 4

    process.memory[addr] = types.Float(-4)
    assert process.memory[addr].float == -4

    process.memory[addr] = types.Double(4)
    assert process.memory[addr].double == 4

    process.memory[addr] = types.StringUTF8("Test")
    assert process.memory[addr].string_utf8 == "Test"

    process.memory[addr] = types.StringUTF16("Test")
    assert process.memory[addr].string_utf16 == "Test"

    process.quit()

def test_replace_with_js():
    global messages
    messages = []

    def on_message(x,y):
        global messages
        messages.append(x['payload'])

    p = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    strlen = p.memory[':strlen']

    # "original" is helper var that should always be the original function
    strlen.replace = """function (x) { send(x.readUtf8String()); return original(x)-1; }"""

    # Adding this after setting replace to test that it updates the replace
    strlen.argument_types = types.Pointer
    strlen.return_type = types.Int64
    strlen.replace_on_message = on_message

    assert strlen("123456") == 5
    time.sleep(0.3)
    assert messages == ["123456"]

    # implementation is just a pass-through
    assert strlen.replace == strlen.implementation

    strlen.implementation = None
    assert strlen("123456") == 6

    assert strlen.replace == strlen.implementation

    p.quit()

def test_argument_types():

    p = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    strlen = p.memory[':strlen']

    assert strlen.argument_types is None
    
    # This should produce logger error and not set
    strlen.argument_types = 12
    assert strlen.argument_types is None

    strlen.argument_types = types.Int32
    assert strlen.argument_types == (types.Int32,)

    strlen.argument_types = (types.Int32, types.Double)
    assert strlen.argument_types == (types.Int32, types.Double)

    strlen.argument_types = [types.Int32, types.Double]
    assert strlen.argument_types == (types.Int32, types.Double)

    p.quit()

def test_describe_address():

    #
    # Have symbols
    #

    p = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    main_addr = p.modules['basic_one'].symbols['main']
    assert p.memory.describe_address(main_addr) == 'basic_one:main'
    assert p.memory.describe_address(main_addr + 10) == 'basic_one:main+0xa'

    func = p.modules['basic_one'].symbols['func']
    assert p.memory.describe_address(func) == 'basic_one:func'
    assert p.memory.describe_address(func + 5) == 'basic_one:func+0x5'

    p.quit()

    #
    # Don't have symbols
    # 

    p = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols=[])
    
    assert p.memory.describe_address(p.modules['basic_one'].base) == "basic_one"
    assert p.memory.describe_address(p.modules['basic_one'].base + 0x123) == "basic_one+0x123"

    p.quit()

def test_memory_local_symbol_resolve():
    assert util.memory['basic_one:i8'].address == basic_one_i8_addr
    assert util.memory['basic_one:i8'].address == util.modules['basic_one'].base + 0x201010

def test_memory_bytes_function_replace():
    basic_looper = revenge.Process(basic_looper_path, resume=False, verbose=False, load_symbols='basic_one')

    # This var constantly gets updated with the output of the function
    global_var = basic_looper.memory['basic_looper:0x201014']
    func = basic_looper.memory['basic_looper:0x64A']

    assert global_var.int64 == 0
    assert func.replace is None
    
    # Start the looper!
    basic_looper.memory[basic_looper.entrypoint].breakpoint = False
    time.sleep(0.2)

    # Base value from func is 1
    assert global_var.int64 == 1
    func.replace = 1337
    repr(func)
    assert func.replace == 1337
    time.sleep(0.2)

    assert global_var.int64 == 1337
    func.replace = types.Int64(31337)
    assert func.replace == 31337
    time.sleep(0.2)

    assert global_var.int64 == 31337
    # Replace with something not supported
    func.replace = lambda x:1
    assert func.replace == None

    func.replace = None
    assert func.replace is None
    time.sleep(0.2)

    assert global_var.int64 == 1
    func.replace = None # Shouldn't affect anything

    basic_looper.quit()


def test_memory_bytes_address_as_pointer():

    strlen = util.memory[':strlen']
    mem = util.memory[strlen.address:strlen.address+20]
    assert isinstance(mem.address, types.Pointer)
    assert isinstance(mem.address_stop, types.Pointer)

def test_memory_type_to_search():

    # TODO: This assumes little endianness of teting machine

    assert util.memory._type_to_search_string(types.StringUTF8('test')) == '74657374'
    assert util.memory._type_to_search_string(types.StringUTF16('test')) == '7400650073007400'

    assert util.memory._type_to_search_string(types.Int8(-12)) == 'f4'
    assert util.memory._type_to_search_string(types.UInt8(12)) == '0c'

    assert util.memory._type_to_search_string(types.Int16(-12)) == 'f4ff'
    assert util.memory._type_to_search_string(types.UInt16(12)) == '0c00'

    assert util.memory._type_to_search_string(types.Int32(-12)) == 'f4ffffff'
    assert util.memory._type_to_search_string(types.UInt32(12)) == '0c000000'

    assert util.memory._type_to_search_string(types.Int64(-12)) == 'f4ffffffffffffff'
    assert util.memory._type_to_search_string(types.UInt64(12)) == '0c00000000000000'


def test_memory_call():

    strlen = util.memory[':strlen']
    assert strlen("Hello!") == 6
    assert isinstance(strlen("Hello!"), types.Pointer)
    assert strlen(types.StringUTF8("Hello!")) == 6

    abs = util.memory[':abs']
    assert abs(5) == 5
    assert abs(revenge.types.Int(-12)) == 12

    atof = util.memory[':atof']
    atof.return_type = types.Double
    assert atof('12.123') == 12.123
    assert isinstance(atof('12.123'), types.Float)
    # This should fail
    atof.return_type = int
    assert atof.return_type == types.Double
    atof.return_type = 'blerg'
    assert atof.return_type == types.Double

    # Test  doing something that modifies existing memory
    mem = util.memory.alloc(128)
    sprintf = util.memory[':sprintf']
    assert not mem.bytes.startswith(b"Hello world!")
    sprintf(mem, 'Hello %s', 'world!')
    assert mem.bytes.startswith(b"Hello world!")
    mem.free()

    assert abs({}) == None

def test_memory_alloc():

    mem = util.memory.alloc(256)
    repr(mem)

    # Success
    assert mem.free()

    # Fail
    assert not mem.free()

def test_memory_maps():

    ranges = util.memory.maps

    # Expecting the following libraries to show up
    next(range for range in ranges if range.file != None and re.findall(r'/ld.+\.so', range.file) != [] and range.protection == 'rw-')
    next(range for range in ranges if range.file != None and re.findall(r'/ld.+\.so', range.file) != [] and range.protection == 'r--')

    next(range for range in ranges if range.file != None and re.findall(r'/libc.+\.so', range.file) != [] and range.protection == 'r--')
    next(range for range in ranges if range.file != None and re.findall(r'/libc.+\.so', range.file) != [] and range.protection == 'rw-')
    next(range for range in ranges if range.file != None and re.findall(r'/libc.+\.so', range.file) != [] and range.protection == 'r-x')

    next(range for range in ranges if range.file != None and range.file.endswith('basic_one') and range.protection == 'rw-')
    next(range for range in ranges if range.file != None and range.file.endswith('basic_one') and range.protection == 'r--')

def test_memory_range_class():

    # Just try the repr
    y = [repr(x) for x in util.memory.maps]

    mr = MemoryRange(util, 0x123, 0x5, 'rw-', {'offset': 12, 'path': '/bin/ls'})
    
    assert mr.file == '/bin/ls'
    assert mr.base == 0x123
    assert mr.size == 0x5
    assert mr.file_offset == 12
    assert mr.readable
    assert mr.writable
    assert not mr.executable

    mr = MemoryRange(util, 0x123, 0x5, 'rw-')
    assert mr.file is None
    assert mr.file_offset is None

def test_memory_repr_str():

    printf = util.memory[':printf']
    repr(printf)

    repr(util.memory)

    s = str(util.memory)
    assert 'libc' in s
    assert 'basic_one' in s
    assert 'rw-' in s
    assert 'r-x' in s
    assert 'rwx' in s


def test_memory_breakpoint():
    util2 = revenge.Process(basic_two_path, resume=False, verbose=False, load_symbols=['basic_one'])

    # Initial value
    assert util2.memory['basic_two:{}'.format(hex(basic_two_i32_addr))].int32 == 1337

    func = util2.memory['basic_two:{}'.format(hex(basic_two_func_addr))]
    i32 = util2.memory['basic_two:{}'.format(hex(basic_two_i32_addr))]

    # Break here
    assert func.breakpoint == False

    # Setting already false breakpoint to false shouldn't change anything
    old_breakpoints = copy(util2.memory._active_breakpoints)
    func.breakpoint = False
    assert old_breakpoints == util2.memory._active_breakpoints
    
    # Set new breakpoint, this should change our active breakpoints dict
    func.breakpoint = True
    assert old_breakpoints != util2.memory._active_breakpoints

    # Setting already true breakpoint to true shouldn't change anything
    old_breakpoints = copy(util2.memory._active_breakpoints)
    func.breakpoint = True
    assert old_breakpoints == util2.memory._active_breakpoints

    assert func.breakpoint == True

    # Release from entrypoint
    util2.memory[util2.entrypoint].breakpoint = False
    assert util2.memory[util2.entrypoint].breakpoint == False
    assert func.breakpoint == True
    
    # Ensure we're not duplicating alloc places
    assert len(util2.memory._active_breakpoints.values()) == len(set(util2.memory._active_breakpoints.values()))

    # Shouldn't have changed just yet
    time.sleep(0.2)
    assert i32.int32 == 1337

    # Let it continue to print statement
    util2.memory[':printf'].breakpoint = True
    func.breakpoint = False

    time.sleep(0.2)
    # It should have changed now
    assert i32.int32 == 31337

    util2.quit()

def test_memory_read_float_double():
    util2 = revenge.Process(basic_two_path, resume=False, verbose=False, load_symbols=['basic_one'])

    assert abs(util2.memory['basic_two:{}'.format(hex(basic_two_f_addr))].float - 4.1251) < 0.0001
    assert abs(util2.memory['basic_two:{}'.format(hex(basic_two_f_addr))].cast(types.Float) - 4.1251) < 0.0001
    assert abs(util2.memory['basic_two:{}'.format(hex(basic_two_d_addr))].cast(types.Double) - 10.4421) < 0.0001

    util2.quit()

def test_memory_read_int():

    assert util.memory[basic_one_i8_addr].int8 == -13
    assert isinstance(util.memory[basic_one_i8_addr].int8, types.Int8)
    assert util.memory[basic_one_i8_addr].cast(types.Int8) == -13
    assert isinstance(util.memory[basic_one_i8_addr].cast(types.Int8), types.Int8)

    assert util.memory[basic_one_ui8_addr].uint8 == 13
    assert isinstance(util.memory[basic_one_ui8_addr].uint8, types.UInt8)
    assert util.memory[basic_one_ui8_addr].cast(types.UInt8) == 13
    assert isinstance(util.memory[basic_one_ui8_addr].cast(types.UInt8), types.UInt8)

    assert util.memory[basic_one_i16_addr].int16 == -1337
    assert isinstance(util.memory[basic_one_i16_addr].int16, types.Int16)
    assert util.memory[basic_one_i16_addr].cast(types.Int16) == -1337
    assert isinstance(util.memory[basic_one_i16_addr].cast(types.Int16), types.Int16)

    assert util.memory[basic_one_ui16_addr].uint16 == 1337
    assert isinstance(util.memory[basic_one_ui16_addr].uint16, types.UInt16)
    assert util.memory[basic_one_ui16_addr].cast(types.UInt16) == 1337
    assert isinstance(util.memory[basic_one_ui16_addr].cast(types.UInt16), types.UInt16)

    assert util.memory[basic_one_i32_addr].int32 == -1337
    assert isinstance(util.memory[basic_one_i32_addr].int32, types.Int32)
    assert util.memory[basic_one_i32_addr].cast(types.Int32) == -1337
    assert isinstance(util.memory[basic_one_i32_addr].cast(types.Int32), types.Int32)

    assert util.memory[basic_one_ui32_addr].uint32 == 1337
    assert isinstance(util.memory[basic_one_ui32_addr].uint32, types.UInt32)
    assert util.memory[basic_one_ui32_addr].cast(types.UInt32) == 1337
    assert isinstance(util.memory[basic_one_ui32_addr].cast(types.UInt32), types.UInt32)

    assert util.memory[basic_one_i64_addr].int64 == -1337
    assert isinstance(util.memory[basic_one_i64_addr].int64, types.Int64)
    assert util.memory[basic_one_i64_addr].cast(types.Int64) == -1337
    assert isinstance(util.memory[basic_one_i64_addr].cast(types.Int64), types.Int64)

    assert util.memory[basic_one_ui64_addr].uint64 == 1337
    assert isinstance(util.memory[basic_one_ui64_addr].uint64, types.UInt64)
    assert util.memory[basic_one_ui64_addr].cast(types.UInt64) == 1337
    assert isinstance(util.memory[basic_one_ui64_addr].cast(types.UInt64), types.UInt64)

def test_memory_read_write_str_byte():

    #string_addr = util.memory['basic_one:{}'.format(hex(basic_one_string_addr))].address
    string = util.memory['basic_one:{}'.format(hex(basic_one_string_addr))]
    assert string.string_utf8 == "This is my string"
    assert string.cast(types.StringUTF8) == "This is my string"
    assert string.bytes == b'T'
    assert util.memory[string.address:string.address+17].bytes == b"This is my string"

    string.string_utf8 = "New string"
    assert string.string_utf8 == "New string"

    string.string_utf16 = "New string"
    assert string.string_utf8 != "New string"
    assert string.string_utf16 == "New string"
    assert string.cast(types.StringUTF16) == "New string"

    # This currently isn't supported
    assert util.memory[string.address:] == None
    assert util.memory[:string.address] == None
    assert util.memory[string.address:string.address+5:2] == None
    assert util.memory[b'blerg'] == None
    
    # Read/write into bytes
    mem = util.memory.alloc(22)
    mem.bytes = "Hello"
    assert mem.bytes.startswith(b"Hello")

    mem.bytes = b"\x12\x34\x56"
    assert mem.bytes.startswith(b"\x12\x34\x56")

    # Try to write something invalid, shouldn't change anything
    mem.bytes = 1.23
    assert mem.bytes.startswith(b"\x12\x34\x56")

    assert mem.size == 22

    # Testing overwrite. TODO: Catch the logger output...
    mem.bytes = "A"*23
    mem.free()

    #
    # alloc_string test
    #

    mem = util.memory.alloc_string("Test!")
    assert mem.string_utf8 == "Test!"
    mem.free()

    mem = util.memory.alloc_string(types.StringUTF8("Test!"))
    assert mem.string_utf8 == "Test!"
    mem.free()

    mem = util.memory.alloc_string("Test!", encoding='utf-16')
    assert mem.string_utf16 == "Test!"
    mem.free()

    mem = util.memory.alloc_string(types.StringUTF16("Test!"))
    assert mem.string_utf16 == "Test!"
    mem.free()

    assert util.memory.alloc_string(1.23) == None


def test_memory_write():

    ui64 = util.memory[basic_one_ui64_addr]

    x = -random.randint(1, 2**7-1)
    ui64.int8 = x
    assert ui64.int8 == x
    assert ui64.uint8 == np.uint8(x)
    
    x = random.randint(1, 2**7-1)
    ui64.uint8 = x
    assert ui64.int8 == x
    assert ui64.uint8 == x

    x = -random.randint(1, 2**15-1)
    ui64.int16 = x
    assert ui64.int16 == x
    assert ui64.uint16 == np.uint16(x)

    x = random.randint(1, 2**15-1)
    ui64.uint16 = x
    assert ui64.int16 == x
    assert ui64.uint16 == x

    x = -random.randint(1, 2**31-1)
    ui64.int32 = x
    assert ui64.int32 == x
    assert ui64.uint32 == np.uint32(x)

    x = random.randint(1, 2**31-1)
    ui64.uint32 = x
    assert ui64.int32 == x
    assert ui64.uint32 == x

    x = -random.randint(1, 2**63-1)
    ui64.int64 = x
    assert ui64.int64 == x
    assert ui64.uint64 == np.uint64(x)

    x = random.randint(1, 2**63-1)
    ui64.uint64 = x
    assert ui64.int64 == x
    assert ui64.uint64 == x

    x = random.randint(1, 2**64-1)
    ui64.pointer = x
    assert ui64.pointer == x
    assert ui64.cast(types.Pointer) == x

    x = round(random.random(),4)
    ui64.float = x
    assert abs(ui64.float - x) < 0.0001
    assert isinstance(ui64.float, types.Float)

    x = round(random.random(),4)
    ui64.double = x
    assert abs(ui64.double - x) < 0.0001
    assert isinstance(ui64.double, types.Double)

def test_memory_create_c_function():
    process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    #
    # Raw Function
    #

    function_add = r"""int add(int x, int y) { return x+y; }"""
    add = process.memory.create_c_function(function_add)
    assert add(5,6) == 11

    eq = process.memory.create_c_function("int eq(int x, int y) { return x==y; }")
    assert eq(1,1) == 1
    assert eq(1,0) == 0
    assert eq(1,-1) == 0
    assert eq(-4, -4) == 1

    add_float = process.memory.create_c_function("float add_float(float x, float y) { return x+y; }")
    add_float.return_type
    assert add_float(types.Float(1.1), types.Float(2.2)) - 3.3 < 0.001

    #
    # Requiring exported call
    #

    function_strstr = r"""void * my_strstr(char *haystack, char *needle) { return strstr(haystack, needle); }"""
    strstr = process.memory[':strstr']
    strstr.argument_types = types.StringUTF8, types.StringUTF8

    # Make sure we dynamically create the call
    my_strstr = process.memory.create_c_function(function_strstr, strstr=strstr)
    my_string = process.memory.alloc_string("This is my string")
    out = my_strstr(my_string, "my")
    assert process.memory[out].string_utf8 == "my string"

    process.quit()

def test_memorybytes_dynamic_assembly_call_str():

    process = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    strlen = process.memory[':strlen']
    strlen.name = 'strlen'
    strlen.argument_types = types.StringUTF8
    strlen.return_type = types.StringUTF8

    assert strlen._dynamic_assembly_call_str.startswith('char * (*strlen)(char *) = (char * (*)(char *)) 0x')
    assert strlen._dynamic_assembly_call_str.endswith(';')

    process.quit()

if __name__ == '__main__':
    test_memory_call_as_thread()
    #test_memory_create_c_function()
    #test_memory_read_int()
    #test_memory_write()
