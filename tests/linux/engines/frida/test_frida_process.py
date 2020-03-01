
import logging
logger = logging.getLogger(__name__)

import os
import revenge
from time import sleep

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

cat_stderr_path = os.path.join(bin_location, "cat_stderr")
basic_send_signal_x86_64_path = os.path.join(bin_location, "basic_send_signal_x86_64")
basic_send_signal_x86_path = os.path.join(bin_location, "basic_send_signal_x86")

def test_frida_process_main_thread_signals_x86(capsys):
    # Make sure frida engine is handling catching signals correctly that come from the main thread.

    #
    # SIGABRT
    #

    process = revenge.Process([basic_send_signal_x86_path, "6"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "abort"

    process.quit()

    #
    # SIGSEGV
    #

    process = revenge.Process([basic_send_signal_x86_path, "11"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "access-violation"

    process.quit()

    #
    # SIGBUS
    #

    process = revenge.Process([basic_send_signal_x86_path, "7"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "access-violation"

    process.quit()

    #
    # SIGILL
    #

    process = revenge.Process([basic_send_signal_x86_path, "4"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "illegal-instruction"

    process.quit()

    #
    # SIGFPE
    #

    process = revenge.Process([basic_send_signal_x86_path, "8"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "arithmetic"

    process.quit()

    #
    # SIGSYS
    #

    process = revenge.Process([basic_send_signal_x86_path, "31"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "system"

    process.quit()

    #
    # SIGTRAP
    #

    process = revenge.Process([basic_send_signal_x86_path, "5"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "breakpoint"

    process.quit()

def test_frida_process_main_thread_signals_x86_64(capsys):
    # Make sure frida engine is handling catching signals correctly that come from the main thread.

    #
    # SIGABRT
    #

    process = revenge.Process([basic_send_signal_x86_64_path, "6"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "abort"

    process.quit()

    #
    # SIGSEGV
    #

    process = revenge.Process([basic_send_signal_x86_64_path, "11"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "access-violation"

    process.quit()

    #
    # SIGBUS
    #

    process = revenge.Process([basic_send_signal_x86_64_path, "7"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "access-violation"

    process.quit()

    #
    # SIGILL
    #

    process = revenge.Process([basic_send_signal_x86_64_path, "4"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "illegal-instruction"

    process.quit()

    #
    # SIGFPE
    #

    process = revenge.Process([basic_send_signal_x86_64_path, "8"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "arithmetic"

    process.quit()

    #
    # SIGSYS
    #

    process = revenge.Process([basic_send_signal_x86_64_path, "31"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "system"

    process.quit()

    #
    # SIGTRAP
    #

    process = revenge.Process([basic_send_signal_x86_64_path, "5"], verbose=False, resume=True)
    t = list(process.threads)[0]

    # Wait for exception to register
    while len(t.exceptions) == 0:
        sleep(0.1)

    assert len(t.exceptions) == 1
    exception = t.exceptions[0]
    assert exception.context is not None
    assert exception.type == "breakpoint"

    process.quit()

def stdout_expect(process, thing):
    out = b""

    while thing not in out:
        out += process.stdout(1)

    return out

def stderr_expect(process, thing):
    out = b""

    while thing not in out:
        out += process.stderr(1)

    return out

def test_frida_process_stdio(capsys):
    process = revenge.Process("/bin/cat", verbose=False, resume=True)
    process.stdin("hello world\n")
    assert b"hello world" in stdout_expect(process, b"world")
    process.quit()

    process = revenge.Process("/bin/cat", verbose=False, resume=False)
    process._stdout_echo = True
    process.memory[process.entrypoint].breakpoint = False
    process.stdin("hello world\n")
    sleep(0.5)
    assert "hello world" in capsys.readouterr().out
    process.quit()

    process = revenge.Process([cat_stderr_path, "hello world"], verbose=False, resume=True)
    assert b"hello world" in stderr_expect(process, b"world")
    process.quit()

    process = revenge.Process([cat_stderr_path, "Test2 Blerg"], verbose=False, resume=False)
    process._stderr_echo = True
    process.memory[process.entrypoint].breakpoint = False
    sleep(0.5)
    assert "Test2 Blerg" in capsys.readouterr().out
    process.quit()
