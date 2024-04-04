
import logging
import os
import time

import revenge

logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)
types = revenge.types

amd64_regs = ['pc', 'sp', 'rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rdi',
              'rsi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
              'rip']
# TODO: Test i386, arm, aarch64

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_threads_path = os.path.join(bin_location, "basic_threads")
basic_threads_after_create = 0x7df


def test_thread_breakpoint():
    p = revenge.Process(basic_threads_path, resume=False, verbose=False, load_symbols='basic_threads')

    #start_address = p.memory["basic_threads:0x670"].address
    #p.memory["basic_threads:0x670"].breakpoint = True
    main = p.modules["basic_threads"].symbols["main"]
    main.memory.breakpoint = True
    p.resume()

    t = list(p.threads)[0]

    # Wait to hit the breakpoint
    while not t.breakpoint:
        pass

    assert t.id in p.threads._breakpoint_context
    assert t.context.pc == main.address # start_address

    t.breakpoint = False

    # breakpoint doesn't directly update. it has to get updated by the script
    # terminating in frida
    while True:
        t = list(p.threads)[0]
        if not t.breakpoint:
            break

        elif t.breakpoint and t.context.pc != main.address: # start_address:
            break

    p.quit()


def test_thread_join_linux():

    process = revenge.Process(basic_threads_path, resume=False, verbose=False)
    main = process.modules['basic_threads'].symbols['main']
    main.memory.breakpoint = True
    process.resume()

    malloc = process.memory['malloc']
    malloc.argument_types = types.Int
    malloc.return_type = types.Pointer

    func = process.memory.create_c_function("void *func() { return (void *)1337; }")
    t = process.threads.create(func.address)
    assert t.join() == 1337

    func = process.memory.create_c_function(
            "void* func() { double d=1337; double *dp = malloc(sizeof(double)); *dp = d; return (void *)dp; }",
            malloc=malloc)
    t = process.threads.create(func.address)
    assert process.memory[t.join()].double == 1337.0

    func = process.memory.create_c_function(
            "void* func() { float f=1337; float *fp = malloc(sizeof(float)); *fp = f; return (void *)fp; }",
            malloc=malloc)
    t = process.threads.create(func.address)
    assert process.memory[t.join()].float == 1337.0

    process.quit()


def test_thread_create_linux():

    process = revenge.Process(basic_threads_path, resume=False, verbose=False)

    # Create and set an int
    a = process.memory.alloc(8)
    a.int64 = 0

    funcs = {
        'pthread_setcancelstate': process.memory['pthread_setcancelstate'],
        'pthread_setcanceltype': process.memory['pthread_setcanceltype'],
    }

    # Create the cmodule function that will set this variable
    func = process.memory.create_c_function("void func() {{ pthread_setcancelstate(0, 0); pthread_setcanceltype(1,0); long *x = (long *){}; while ( 1 ) {{ *x = 1337; }} }}".format(hex(a.address)), **funcs)

    # Kick off the thread
    t = process.threads.create(func.address)

    # Wait for it (super fast likely)
    while a.int64 == 0:
        pass

    assert a.int64 == 1337

    # Make sure we have a pthread_id
    assert t.pthread_id is not None

    t.kill()
    process.quit()


def test_frida_thread_dummy():

    process = revenge.Process(basic_threads_path, resume=False, verbose=False, load_symbols='basic_threads')

    # Frida hides it's own threads from you. revenge will create a dummy thread object when this is requested
    tid = process.engine.run_script_generic(r"""send(Process.getCurrentThreadId())""", unload=True, raw=True)[0][0]
    t = process.threads[tid]
    assert t.id == tid

    process.quit()


def test_thread_tracing_indicator():

    process = revenge.Process(basic_threads_path, resume=False, verbose=False, load_symbols='basic_threads')
    main = process.modules['basic_threads'].symbols['main']
    main.memory.breakpoint = True
    process.resume()

    th = list(process.threads)[0]

    assert th.trace is None

    t = process.techniques.NativeInstructionTracer(exec=True)
    t.apply()
    t2 = list(t)[0]

    assert th.trace is t2
    assert "tracing" in repr(th)

    # th.trace.stop()
    t.remove()
    assert th.trace is None
    assert "tracing" not in repr(th)

    process.quit()


def test_thread_enum():
    util = revenge.Process(basic_threads_path, resume=False, verbose=False, load_symbols='basic_threads')
    main = util.modules['basic_threads'].symbols['main']
    main.memory.breakpoint = True
    util.resume()

    # Should only be one thread to start with
    assert len(util.threads) == 1

    util.memory['basic_threads:' + hex(basic_threads_after_create)].breakpoint = True

    # Continue
    #util.memory[util.entrypoint].breakpoint = False
    util.resume()

    # Race condition...
    time.sleep(0.5)

    # Should be two threads now
    assert len(util.threads) == 2

    util.quit()


def test_thread_regs_amd64():
    util = revenge.Process(basic_threads_path, resume=False, verbose=False, load_symbols='basic_threads')
    main = util.modules['basic_threads'].symbols['main']
    main.memory.breakpoint = True
    util.resume()

    # Just checking that the regs are exposed
    t = list(util.threads)[0]

    for reg in amd64_regs:
        assert type(getattr(t, reg)) is int

    util.quit()


def test_thread_repr_str():
    util = revenge.Process(basic_threads_path, resume=False, verbose=False, load_symbols='basic_threads')

    main = util.modules['basic_threads'].symbols['main']
    main.memory.breakpoint = True
    util.resume()

    # For now, just make sure they return...
    repr(util.threads)
    str(util.threads)

    t = list(util.threads)[0]
    repr(t)
    str(t)

    util.quit()


def test_thread_getitem():
    util = revenge.Process(basic_threads_path, resume=False, verbose=False, load_symbols='basic_threads')
    main = util.modules['basic_threads'].symbols['main']
    main.memory.breakpoint = True
    util.resume()

    t = list(util.threads)[0]
    assert util.threads[t.id] is not None
    assert util.threads[0] is None
    assert util.threads[b'blerg'] is None
    assert util.threads[t] is t

    util.quit()


if __name__ == '__main__':
    test_thread_join_linux()
