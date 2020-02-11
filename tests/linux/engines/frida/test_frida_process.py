
import logging
logger = logging.getLogger(__name__)

import os
import revenge
from time import sleep

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

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

    process = revenge.Process(["/usr/bin/logger", "-s", "hello world"], verbose=False, resume=True)
    assert b"hello world" in stderr_expect(process, b"world")
    process.quit()

    process = revenge.Process(["/usr/bin/logger", "-s", "Test2 Blerg"], verbose=False, resume=False)
    process._stderr_echo = True
    process.memory[process.entrypoint].breakpoint = False
    sleep(0.5)
    assert "Test2 Blerg" in capsys.readouterr().out
    process.quit()
