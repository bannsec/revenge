
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import frida_util
import time

amd64_regs = ['pc', 'sp', 'rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip']
# TODO: Test i386, arm, aarch64

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_threads_path = os.path.join(bin_location, "basic_threads")
basic_threads_after_create = 0x7df

util = frida_util.Process(basic_threads_path, resume=False, verbose=False)

def test_thread_tracing_indicator():

    process = frida_util.Process(basic_threads_path, resume=False, verbose=False)
    th = list(process.threads)[0]

    assert th.trace is None

    t = process.tracer.instructions(exec=True)
    t2 = list(t)[0]

    assert th.trace is t2
    assert "tracing" in repr(th)

    th.trace.stop()
    assert th.trace is None
    assert "tracing" not in repr(th)


def test_thread_enum():

    # Should only be one thread to start with
    assert len(util.threads) == 1

    util.memory['basic_threads:' + hex(basic_threads_after_create)].breakpoint = True

    # Continue
    util.memory[util.entrypoint_rebased].breakpoint = False

    # Race condition...
    time.sleep(0.5)

    # Should be two threads now
    assert len(util.threads) == 2


def test_thread_regs_amd64():

    # Just checking that the regs are exposed
    t = list(util.threads)[0]

    for reg in amd64_regs:
        assert type(getattr(t, reg)) is int

def test_thread_repr_str():

    # For now, just make sure they return...
    repr(util.threads)
    str(util.threads)

    t = list(util.threads)[0]
    repr(t)
    str(t)

def test_thread_getitem():

    t = list(util.threads)[0]
    assert util.threads[t.id] is not None
    assert util.threads[0] is None
    assert util.threads[b'blerg'] is None
