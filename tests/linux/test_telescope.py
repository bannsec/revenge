

import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types
common =  revenge.common

import time

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

telescope_path = os.path.join(bin_location, "telescope")

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
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['string2'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "string"
    assert scope.next.next.thing == "This is a test"
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['string1_ptr'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "string"
    assert scope.next.next.thing == "This is a test"
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
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['string3_uninit_ptr'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "string"
    assert "stack" in scope.next.next.thing
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['random_int'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.thing & 0xffff == 1337
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['random_int_ptr'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.next.type == "int"
    assert scope.next.next.thing & 0xffff == 1337
    str(scope)
    repr(scope)

    scope = types.Telescope(process, telescope.symbols['pointer_to_main'])
    assert isinstance(scope.memory_range, revenge.memory.MemoryRange)
    assert os.path.basename(scope.memory_range.file) ==  'telescope'
    assert scope.type == "int"
    assert scope.next.type == "int"
    assert scope.next.memory_range.executable == True
    assert scope.next.next.type == "instruction"
    assert isinstance(scope.next.next.thing, revenge.tracer.AssemblyInstruction)
    assert scope.next.next.thing.mnemonic == "push"
    assert scope.next.next.thing.operands[0]['value'] == "rbp"
    str(scope)
    repr(scope)

    process.quit()
