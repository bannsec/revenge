

import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types
common =  revenge.common

from revenge.exceptions import *

import time
import pytest

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

telescope_path = os.path.join(bin_location, "telescope")

def test_telescope_int_hex():

    p = revenge.Process(telescope_path, resume=True, verbose=False)

    d = {'thing': '0x7fc954d349c0', 'next': {'type': 'instruction', 'thing': {'groups': ['branch_relative', 'jump'], 'regsWritten': [], 'regsRead': [], 'operands': [{'type': 'imm', 'value': '140502694078472', 'size': 8}], 'opStr': '0x7fc9552ba808', 'mnemonic': 'jmp', 'size': 5, 'next': '0x7fc954d349c5', 'address': '0x7fc954d349c0'}, 'telescope': True, 'next': None, 'mem_range': None}, 'mem_range': {'base': '0x7fc954d34000', 'size': 4096, 'protection': 'rwx', 'file': {'path': '/lib/x86_64-linux-gnu/libc-2.27.so', 'offset': 524288, 'size': 0}}, 'telescope': True, 'type': 'int'}
    t = types.Telescope.from_dict(p, d)

    assert int(t) == 0x7fc954d349c0
    assert hex(t) == "0x7fc954d349c0"

    with pytest.raises(RevengeInvalidArgumentType):
        int(t.next)

    with pytest.raises(RevengeInvalidArgumentType):
        hex(t.next)

    assert t & 0xffff == 0x49c0
    assert t >> 4 == 0x7fc954d349c

    p.quit()

def test_telescope_js_basic():

    def do_telescope(addr):
        return process.run_script_generic("send(telescope(ptr('{}')))".format(hex(addr)), raw=True, unload=True, include_js="telescope.js")[0][0]

    process = revenge.Process(telescope_path, resume=True, verbose=False)

    telescope = process.modules['telescope']

    # Make sure to sleep until we're done executing main
    while telescope.symbols['string3_uninit_ptr'].memory.pointer == 0:
        time.sleep(0.01)
    
    scope = do_telescope(telescope.symbols['string1'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['string1'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert scope['mem_range']['file']['path'].endswith('/telescope')
    assert scope['next']['thing'] == "This is a test"
    assert scope['next']['next'] is None
    assert scope['next']['mem_range'] is None
    assert scope['next']['type'] == "string"

    scope = do_telescope(telescope.symbols['string2'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['string2'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert scope['mem_range']['file']['path'].endswith('/telescope')
    assert scope['next']['type'] == "int"
    assert scope['next']['telescope'] is True
    assert scope['next']['mem_range']['protection'] == 'rwx'
    assert scope['next']['next']['thing'] == 'This is a test'
    assert scope['next']['next']['type'] == 'string'

    scope = do_telescope(telescope.symbols['string1_ptr'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['string1_ptr'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert scope['next']['telescope'] is True
    assert common.auto_int(scope['next']['thing']) == common.auto_int(telescope.symbols['string1'].address)
    assert scope['next']['type'] == 'int'
    assert scope['next']['mem_range']['protection'] == 'rw-'
    assert scope['next']['mem_range']['file']['path'].endswith('/telescope')
    assert scope['next']['next']['thing'] == "This is a test"
    assert scope['next']['next']['next'] is None
    assert scope['next']['next']['mem_range'] is None
    assert scope['next']['next']['type'] == "string"
    assert common.auto_int(scope['next']['next']['int']) == 0x2073692073696854


    scope = do_telescope(telescope.symbols['string2_ptr'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['string2_ptr'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert scope['next']['telescope'] is True
    assert common.auto_int(scope['next']['thing']) == common.auto_int(telescope.symbols['string2'].address)
    assert scope['next']['type'] == 'int'
    assert scope['next']['mem_range']['protection'] == 'rw-'
    assert scope['next']['mem_range']['file']['path'].endswith('/telescope')
    assert scope['next']['next']['type'] == "int"
    assert scope['next']['next']['telescope'] is True
    assert scope['next']['next']['mem_range']['protection'] == 'rwx'
    assert scope['next']['next']['next']['thing'] == 'This is a test'
    assert scope['next']['next']['next']['type'] == 'string'
    
    scope = do_telescope(telescope.symbols['string3_uninit_ptr'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['string3_uninit_ptr'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert scope['next']['type'] == "int"
    assert scope['next']['next']['type'] == "string"
    # Not sure why this doesn't point to beginning of the string..
    assert "stack" in scope['next']['next']['thing']

    scope = do_telescope(telescope.symbols['random_int'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['random_int'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert common.auto_int(scope['next']['thing']) & 0xffffffff == 1337

    scope = do_telescope(telescope.symbols['random_int_ptr'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['random_int_ptr'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert scope['next']['telescope'] is True
    assert common.auto_int(scope['next']['thing']) == common.auto_int(telescope.symbols['random_int'].address)
    assert scope['next']['type'] == 'int'
    assert scope['next']['mem_range']['protection'] == 'rw-'
    assert common.auto_int(scope['next']['next']['thing']) & 0xffffffff == 1337

    scope = do_telescope(telescope.symbols['pointer_to_main'].address)
    assert scope['telescope'] is True
    assert common.auto_int(scope['thing']) == common.auto_int(telescope.symbols['pointer_to_main'].address)
    assert scope['type'] == 'int'
    assert scope['mem_range']['protection'] == 'rw-'
    assert scope['next']['type'] == "int"
    assert scope['next']['mem_range']['protection'] == 'rwx'
    assert common.auto_int(scope['next']['thing']) == common.auto_int(telescope.symbols['main'].address)
    assert scope['next']['next']['type'] == 'instruction'
    assert common.auto_int(scope['next']['next']['thing']['address']) == common.auto_int(telescope.symbols['main'].address)

    process.quit()

def test_telescope_class():

    process = revenge.Process(telescope_path, resume=True, verbose=False)
    telescope = process.modules['telescope']

    # Make sure to sleep until we're done executing main
    while telescope.symbols['string3_uninit_ptr'].memory.pointer == 0:
        time.sleep(0.01)
    
    scope = types.Telescope(process, telescope.symbols['string1'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.thing == "This is a test"
    assert scope.next.type == "string"
    assert hash(scope) == hash(scope)
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['string2'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "string"
    assert scope.next.next.thing == "This is a test"
    assert hash(scope) == hash(scope)
    assert hash(scope) != hash_prev
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['string1_ptr'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "string"
    assert scope.next.next.thing == "This is a test"
    assert hash(scope) == hash(scope)
    assert hash(scope) != hash_prev
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['string2_ptr'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "int"
    assert scope.next.next.next.type == "string"
    assert scope.next.next.next.thing == "This is a test"
    assert hash(scope) == hash(scope)
    assert hash(scope) != hash_prev
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['string3_uninit_ptr'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "string"
    assert "stack" in scope.next.next.thing
    assert hash(scope) == hash(scope)
    assert hash(scope) != hash_prev
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['random_int'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.thing & 0xffff == 1337
    assert hash(scope) == hash(scope)
    assert hash(scope) != hash_prev
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['random_int_ptr'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "int"
    assert scope.next.next.thing & 0xffff == 1337
    assert hash(scope) == hash(scope)
    assert hash(scope) != hash_prev
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['pointer_to_main'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.memory_range.executable == True
    assert scope.next.next.type == "instruction"
    assert isinstance(scope.next.next.thing, revenge.cpu.assembly.AssemblyInstruction)
    assert scope.next.next.thing.mnemonic == "push"
    assert scope.next.next.thing.operands[0]['value'] == "rbp"
    assert hash(scope) == hash(scope)
    assert hash(scope) != hash_prev
    hash_prev = hash(scope)
    str(scope)
    repr(scope)

    process.quit()
