
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import pytest
import frida_util
types = frida_util.types

import time
from copy import copy

from frida_util.tracer.instruction_tracer import TraceItem

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")

def test_basic_one_trace_instructions_call_ret():

    basic_one = frida_util.Util(action="find", target="basic_one", file=basic_one_path, resume=False, verbose=False)
    t = basic_one.tracer.instructions(call=True, ret=True)

    module = basic_one.modules['basic_one']

    # Start it
    basic_one.memory[basic_one.entrypoint_rebased].breakpoint = False

    # Minor sleep
    time.sleep(0.2)

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

def test_basic_one_trace_instructions_exec():

    basic_one = frida_util.Util(action="find", target="basic_one", file=basic_one_path, resume=False, verbose=False)
    t = basic_one.tracer.instructions(exec=True)

    module = basic_one.modules['basic_one']

    # Start it
    basic_one.memory[basic_one.entrypoint_rebased].breakpoint = False

    # Minor sleep
    time.sleep(0.2)

    trace_copy = copy(list(t)[0])

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


"""
# Blocks are a little broken rn: https://github.com/frida/frida/issues/925

def test_basic_one_trace_instructions_block():

    basic_one = frida_util.Util(action="find", target="basic_one", file=basic_one_path, resume=False, verbose=False)
    t = basic_one.tracer.instructions(block=True)

    module = basic_one.modules['basic_one']

    # Start it
    basic_one.memory[basic_one.entrypoint_rebased].breakpoint = False

    # Minor sleep
    time.sleep(0.2)

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
"""

def test_basic_one_traceitem():

    basic_one = frida_util.Util(action="find", target="basic_one", file=basic_one_path, resume=False, verbose=False)
    module = basic_one.modules['basic_one']

    item_call = {'tid': 16050, 'type': 'call', 'from_ip': '0x7f1154c799de', 'to_ip': '0x7f1154cc5740', 'depth': 0, 'from_module': 'libc-2.27.so', 'to_module': 'libc-2.27.so'}
    item_ret = {'tid': 16050, 'type': 'ret', 'from_ip': '0x7f1154c799de', 'to_ip': '0x7f1154cc5740', 'depth': 0, 'from_module': 'libc-2.27.so', 'to_module': 'libc-2.27.so'}
    item_block = {'tid': 16050, 'type': 'block', 'from_ip': '0x7f1154c799de', 'to_ip': '0x7f1154cc5740', 'from_module': 'libc-2.27.so', 'to_module': 'libc-2.27.so'}
    item_compile = {'tid': 16050, 'type': 'compile', 'from_ip': '0x7f1154c799de', 'from_module': 'libc-2.27.so'}
    item_exec = {'tid': 16050, 'type': 'exec', 'from_ip': '0x7f1154c799de', 'from_module': 'libc-2.27.so'}
    items = [item_call, item_ret, item_block, item_compile, item_exec]
    
    for i in items:
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
