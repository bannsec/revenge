
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import frida_util
types = frida_util.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

exceptions_path = os.path.join(bin_location, "exceptions")
p = frida_util.Process(exceptions_path, resume=False, verbose=False)

def test_arithmetic():

    do_arithmetic = p.memory[p.modules['exceptions'].symbols['do_arithmetic']] 
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_arithmetic()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'arithmetic'
    # This abort is run by throwing the signal from libc
    assert p.modules[e.address].name == 'exceptions'
    assert p.memory.describe_address(e.address).startswith("exceptions:do_arithmetic")
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)

def test_illegal_instruction():

    do_ill = p.memory[p.modules['exceptions'].symbols['do_ill']] 
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_ill()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'illegal-instruction'
    # This abort is run by throwing the signal from libc
    assert 'libc' in p.modules[e.address].name 
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)

def test_abort():

    do_abort = p.memory[p.modules['exceptions'].symbols['do_abort']] 
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_abort()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'abort'
    # This abort is run by throwing the signal from libc
    assert 'libc' in p.modules[e.address].name 
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)

def test_access_violation():

    do_access_violation = p.memory[p.modules['exceptions'].symbols['do_access_violation']]
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_access_violation()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'access-violation'
    # This abort is run by throwing the signal from libc
    assert 'exceptions' in p.modules[e.address].name 
    assert p.memory.describe_address(e.address).startswith("exceptions:do_access_violation")
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)

def test_access_violation_read():

    do_access_read_violation = p.memory[p.modules['exceptions'].symbols['do_access_read_violation']]
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_access_read_violation()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'access-violation'
    # This abort is run by throwing the signal from libc
    assert p.modules[e.address].name == 'exceptions'
    assert p.memory.describe_address(e.address).startswith("exceptions:do_access_read_violation")
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    assert e.memory_address == 0x666
    assert e.memory_operation == 'read'

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)

"""
def test_access_violation_write():
    # Frida bug: https://github.com/frida/frida/issues/987

    do_access_write_violation = p.memory[p.modules['exceptions'].symbols['do_access_write_violation']]
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_access_write_violation()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'access-violation'
    # This abort is run by throwing the signal from libc
    assert p.modules[e.address].name == 'exceptions'
    assert p.memory.describe_address(e.address).startswith("exceptions:do_access_write_violation")
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    assert e.memory_address == 0x666
    assert e.memory_operation == 'write'

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)
"""

def test_access_violation_execute():

    do_access_exec_violation = p.memory[p.modules['exceptions'].symbols['do_access_exec_violation']]
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_access_exec_violation()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'access-violation'
    # 0x666 shouldn't be in any module
    assert p.modules[e.address] is None
    assert p.memory.describe_address(e.address) == "0x666"
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    assert e.memory_address == 0x666
    assert e.memory_operation == 'execute'

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)

def test_int3():

    do_int3 = p.memory[p.modules['exceptions'].symbols['do_int3']]
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_int3()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'breakpoint'

    assert p.modules[e.address].name == 'exceptions'
    assert p.memory.describe_address(e.address).startswith("exceptions:do_int3")
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)

def test_sigsys():

    do_sigsys = p.memory[p.modules['exceptions'].symbols['do_sigsys']]
    do_good = p.memory[p.modules['exceptions'].symbols['do_good']] 

    e = do_sigsys()
    assert isinstance(e, frida_util.native_exception.NativeException)
    str(e)
    repr(e)
    assert e.type == 'system'

    assert 'libc' in p.modules[e.address].name
    assert p.memory.describe_address(e.address).startswith("libc")
    assert isinstance(e.backtrace, frida_util.native_exception.NativeBacktrace)
    assert isinstance(e.context, frida_util.tracer.contexts.x64.X64Context)

    # If we handled exception correctly, process should still be in good state
    assert not isinstance(do_good, frida_util.native_exception.NativeException)
