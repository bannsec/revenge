
import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

import time
from copy import copy

from revenge.techniques.tracer.instruction_tracer import TraceItem, Trace

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")

# Trace items
item_call = {'tid': 16050, 'type': 'call', 'from_ip': '0x7f1154c799de', 'to_ip': '0x7f1154cc5740', 'depth': 0, 'from_module': 'libc-2.27.so', 'to_module': 'libc-2.27.so'}
item_ret = {'tid': 16050, 'type': 'ret', 'from_ip': '0x7f1154c799de', 'to_ip': '0x7f1154cc5740', 'depth': 0, 'from_module': 'libc-2.27.so', 'to_module': 'libc-2.27.so'}
item_block = {'tid': 16050, 'type': 'block', 'from_ip': '0x7f1154c799de', 'to_ip': '0x7f1154cc5740', 'from_module': 'libc-2.27.so', 'to_module': 'libc-2.27.so'}
item_compile = {'tid': 16050, 'type': 'compile', 'from_ip': '0x7f1154c799de', 'from_module': 'libc-2.27.so'}
item_exec = {'tid': 16050, 'type': 'exec', 'from_ip': '0x7f1154c799de', 'from_module': 'libc-2.27.so'}
trace_items = [item_call, item_ret, item_block, item_compile, item_exec]

crackme_count_path = os.path.join(bin_location, "crackme_count")

def test_trace_include_function():

    p = revenge.Process(crackme_count_path, resume=False, verbose=False)

    win = p.memory['crackme_count:win']

    #
    # Testing block
    #

    trace = p.techniques.InstructionTracer(call=True, block=True, include_function=win)
    assert win("flag", techniques=trace) == 1

    trace = list(trace)[0]

    # Wait for ret
    trace.wait_for(win.address+0x78)

    correct = [
        ['block', win.address, win.address+0x13],
        ['block', win.address+0x1a, win.address+0x29],
        ['block', win.address+0x30, win.address+0x3f],
        ['block', win.address+0x46, win.address+0x55],
        ['block', win.address+0x5c, win.address+0x6b],
        ['block', win.address+0x72, p.memory['crackme_count:main'].address],
        ['ret', win.address+0x78, None]
    ]

    assert len(trace) == 7

    for (type, from_ip, to_ip), t in zip(correct, trace):
        assert t.type == type
        assert t.from_ip == from_ip
        if to_ip is not None:
            assert t.to_ip == to_ip

    #
    # Testing exec
    #

    trace = p.techniques.InstructionTracer(exec=True, include_function=win)
    assert win("flag", techniques=trace) == 1

    trace = list(trace)[0]

    # Wait for ret
    trace.wait_for(win.address+0x78)

    correct = [
        ["exec",  win.address, None],
        ["exec",  win.address+0x1, None],
        ["exec",  win.address+0x4, None],
        ["exec",  win.address+0x8, None],
        ["exec",  win.address+0xc, None],
        ["exec",  win.address+0xf, None],
        ["exec",  win.address+0x11, None],
        ["exec",  win.address+0x1a, None],
        ["exec",  win.address+0x1e, None],
        ["exec",  win.address+0x22, None],
        ["exec",  win.address+0x25, None],
        ["exec",  win.address+0x27, None],
        ["exec",  win.address+0x30, None],
        ["exec",  win.address+0x34, None],
        ["exec",  win.address+0x38, None],
        ["exec",  win.address+0x3b, None],
        ["exec",  win.address+0x3d, None],
        ["exec",  win.address+0x46, None],
        ["exec",  win.address+0x4a, None],
        ["exec",  win.address+0x4e, None],
        ["exec",  win.address+0x51, None],
        ["exec",  win.address+0x53, None],
        ["exec",  win.address+0x5c, None],
        ["exec",  win.address+0x60, None],
        ["exec",  win.address+0x64, None],
        ["exec",  win.address+0x67, None],
        ["exec",  win.address+0x69, None],
        ["exec",  win.address+0x72, None],
        ["exec",  win.address+0x77, None],
        ["exec",  win.address+0x78, None],
        ["ret", win.address++0x78, None],
    ]

    assert len(trace) == 31

    for (type, from_ip, to_ip), t in zip(correct, trace):
        assert t.type == type
        assert t.from_ip == from_ip
        if to_ip is not None:
            assert t.to_ip == to_ip

    #
    # Testing call
    #

    # Setup mock main() call
    argv = p.memory.alloc(16)
    p.memory[argv.address+8] = p.memory.alloc_string(types.StringUTF8("flag")).address
    main = p.memory['crackme_count:main']
    plt_puts = p.memory['crackme_count:plt.puts']

    trace = p.techniques.InstructionTracer(call=True, include_function=main)
    main(2, argv, techniques=trace)
    trace = list(trace)[0]

    # Main ret
    trace.wait_for(main.address+0x46)

    correct = [
        ["call",  main.address+0x1d, win.address],
        ["ret",  win.address+0x78, main.address+0x22],
        ["call",  main.address+0x2d, plt_puts.address],
    ]

    # Actual depth will depend on libc of the system running the test..

    assert len(trace) > 5

    for (type, from_ip, to_ip), t in zip(correct, trace):
        assert t.type == type
        assert t.from_ip == from_ip
        if to_ip is not None:
            assert t.to_ip == to_ip

    p.quit()

def test_trace_exclude_ranges():

    p = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    # Create a thread that will just spin
    m = p.memory.alloc(8)
    m.int64 = 0
    func = p.memory.create_c_function(""" void func() {{ while ( *(void *){} == 0 ) {{ ; }} }}""".format(hex(m.address)))

    # Start-er up
    t = p.threads.create(func.address)

    # Kick off thread, explicitly ignoring the thread code itself
    trace = p.techniques.InstructionTracer(exec=True, exclude_ranges=[[func.address, func.address + 0x100]]); trace.apply(t); m.int64 = 1

    time.sleep(0.2)
    
    # We should have nothing in our trace, since we excluded it all
    assert len(t.trace) == 0

    p.quit()

def test_basic_one_trace_slice():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    
    t = basic_one.techniques.InstructionTracer(call=True, ret=True, exec=True, from_modules=['basic_one'])
    t.apply()
    t2 = list(t)[0]
    
    basic_one.memory[basic_one.entrypoint].breakpoint = False
    t2.wait_for('basic_one:0x692') # final ret

    t3 = t2[:12]
    assert isinstance(t3, Trace)

    for i in range(12):
        assert t2[i] == t3[i]

    basic_one.quit()

def test_basic_one_trace_specify_from_modules():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    
    t = basic_one.techniques.InstructionTracer(exec=True, from_modules=['basic_one'])
    t.apply()
    t2 = list(t)[0]
    
    basic_one.memory[basic_one.entrypoint].breakpoint = False
    t2.wait_for('basic_one:0x692') # final ret

    print(t2)
    for i in t2:
        assert i.from_module == 'basic_one'
    
    libc = basic_one.modules['libc*']
    t._from_modules = 'libc*'
    assert len(t._from_modules) == 1
    assert t._from_modules[0] == libc

    t._from_modules = ['libc*']
    assert len(t._from_modules) == 1
    assert t._from_modules[0] == libc

    t._from_modules = libc
    assert len(t._from_modules) == 1
    assert t._from_modules[0] == libc

    with pytest.raises(Exception):
        t._from_modules = [1.12]

    t.remove()
    basic_one.quit()

def test_basic_one_trace_thread_int():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    thread = list(basic_one.threads)[0]

    t = basic_one.techniques.InstructionTracer(exec=True)
    t.apply([thread.id])
    str(t)
    t2 = list(t)[0]
    while len(t2) < 15:
        time.sleep(0.1)

    with pytest.raises(Exception):
        t3 = basic_one.techniques.InstructionTracer(exec=True)
        t3.apply([12.12])


    # Testing exception for attempting to create another trace on a thread that is already being traced
    with pytest.raises(Exception):
        t3 = basic_one.techniques.InstructionTracer(exec=True)
        t3.apply()

    t2.stop()

    # This should not raise an exception now
    t = basic_one.techniques.InstructionTracer(exec=True)
    t.apply()

    basic_one.quit()

def test_basic_one_trace_thread():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')

    thread = list(basic_one.threads)[0]

    t = basic_one.techniques.InstructionTracer(exec=True)
    t.apply([thread])

    t2 = list(t)[0]
    while len(t2) < 15:
        time.sleep(0.1)
    assert len(t2) > 0
    t2.stop()

    time.sleep(0.3)
    t = basic_one.techniques.InstructionTracer(exec=True)
    t.apply(thread)
    t2 = list(t)[0]
    basic_one.memory[basic_one.entrypoint].breakpoint = False
    t2.wait_for('basic_one:0x692') # final ret
    assert len(t2) > 0

    # TODO: Figure out why this final trace stop causes things to hang...
    #t2.stop()

    basic_one.quit()


def test_basic_one_trace_add_remove():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    t = basic_one.techniques.InstructionTracer(call=True, ret=True)
    t.apply()
    tid = list(t)[0]._tid

    assert tid in basic_one.techniques._active_stalks
    assert basic_one.techniques._active_stalks[tid] is list(t)[0]
    assert basic_one.techniques._active_stalks[tid]._script is not None

    t2 = basic_one.techniques._active_stalks[tid]
    t2.stop()

    assert tid not in basic_one.techniques._active_stalks
    assert list(t)[0]._script is None

    # This should just do nothing
    t2.stop()

    basic_one.quit()

def test_basic_one_trace_instructions_call_ret():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    t = basic_one.techniques.InstructionTracer(call=True, ret=True)
    t.apply()
    t2 = list(t)[0]

    module = basic_one.modules['basic_one']

    # Start it
    basic_one.memory[basic_one.entrypoint].breakpoint = False
    t2.wait_for('basic_one:0x692') # final ret

    trace_copy = copy(list(t)[0])

    #
    # Start trace validation
    #
    
    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type in ['call', 'ret']
        if ti.from_ip == module.base + 0x66D:
            break

    assert ti.type == 'call'
    assert ti.to_ip == module.base + 0x64A

    ##

    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type in ['call', 'ret']
        if ti.from_ip == module.base + 0x654:
            break

    assert ti.type == 'ret'
    assert ti.to_ip == module.base + 0x672

    ##

    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type in ['call', 'ret']
        if ti.from_ip == module.base + 0x687:
            break

    assert ti.type == 'call'
    assert ti.to_ip == module.base + 0x520 # PLT

    ## Return from printf

    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type in ['call', 'ret']
        if ti.to_ip == module.base + 0x68C:
            break

    assert ti.type == 'ret'
    assert ti.from_module.startswith('libc')

    # Retun to start_libc

    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type in ['call', 'ret']
        if ti.from_ip == module.base + 0x692:
            break

    assert ti.type == 'ret'
    assert ti.to_module.startswith('libc')
    
    basic_one.quit()

def test_basic_one_trace_instructions_exec():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    t = basic_one.techniques.InstructionTracer(exec=True)
    t.apply()
    t2 = list(t)[0]

    module = basic_one.modules['basic_one']

    # Start it
    basic_one.memory[basic_one.entrypoint].breakpoint = False
    t2.wait_for('basic_one:0x692') # final ret

    trace_copy = copy(list(t)[0])

    # Some symbol resolution
    assert 'func' in str(trace_copy)
    assert 'main' in str(trace_copy)

    #
    # Start trace validation
    #

    # main
    
    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type == 'exec'
        if ti.from_ip == module.base + 0x655:
            break

    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x656
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x659
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x65D
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x664
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x668
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x66d
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x64A
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x64B
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x64E
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x653
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x654
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x672
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x674
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x678
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x67B
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x682
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x687
    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x520

    # after printf
    
    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type == 'exec'
        if ti.from_ip == module.base + 0x68C:
            break

    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x691

    ti = trace_copy._trace.pop(0)
    assert ti.from_ip == module.base + 0x692

    basic_one.quit()

"""
# Blocks are a little broken rn: https://github.com/frida/frida/issues/925

def test_basic_one_trace_instructions_block():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    t = basic_one.tracer.instructions(block=True)
    t2 = list(t)[0]

    module = basic_one.modules['basic_one']

    # Start it
    basic_one.memory[basic_one.entrypoint].breakpoint = False

    t2.wait_for('basic_one:0x692') # final ret

    trace_copy = copy(list(t)[0])

    #
    # Start trace validation
    #
    print(trace_copy)

    # _init_proc
    
    while True:
        ti = trace_copy._trace.pop(0)
        assert ti.type == 'block'
        if ti.from_ip == module.base + 0x4f0:
            break

    assert ti.to_ip == module.base + 0x500

    basic_one.quit()
"""

def test_basic_one_traceitem_manual_creation():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    module = basic_one.modules['basic_one']

    for i in trace_items:
        ti = TraceItem(basic_one, i)
        str(ti)
        repr(ti)
        assert ti.type == i['type']

    with pytest.raises(AssertionError):
        ti.type = 12

    # Invalid type
    t = ti.type
    ti.type = 'blerg'
    assert ti.type == t

    str(ti)
    repr(ti)

    basic_one.quit()

def test_basic_one_traceitem():

    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    module = basic_one.modules['basic_one']

    t = basic_one.techniques.InstructionTracer()
    t.apply()

    tid = list(t)[0]._tid

    for i in trace_items:
        i['tid'] = tid
        t._on_message({'type': 'send', 'payload': [[i]]}, None)

    repr(t)
    t2 = list(t)[0]
    
    for i in list(t2):
        assert isinstance(i, TraceItem)

    len(t2)
    str(t2)
    repr(t2)

    assert isinstance(t2[0], TraceItem)

    basic_one.quit()


