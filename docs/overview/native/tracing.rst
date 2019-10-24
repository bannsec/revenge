=======
Tracing
=======

A core reason for creating ``revenge`` was to make tracing applications easier.
With that in mind, there will be a few different built-in tracers to run.

.. note::

    You can only have one trace running per-thread at a time! This is a
    function of of DBI works, and not a limitation with revenge specifically.

Instruction Tracing
===================

It's often interesting to simply trace an execution path. To do this with
``revenge``, you can use the instruction tracing method to get a Tracer object
and view your results. You can trace at different levels of granularity by
specifying what you want to trace in the keyword arguments.

Examples
--------

.. code-block:: python3

    # Possible tracing options are: call, ret, block, exec, compile
    # Default is False for all of them, so specify any combination
    trace = process.techniques.InstructionTracer(call=True, ret=True)

    # Since trace is a technique, you must apply it
    # By default, trace will apply to all threads if not given any arguments
    trace.apply()

    t = list(trace)[0]

    print(t)
    """
    call  ls:_init+0x211c                                           libc-2.27.so:__libc_start_main                      0
    call   libc-2.27.so:__libc_start_main+0x47                       libc-2.27.so:__cxa_atexit                          1
    call    libc-2.27.so:__cxa_atexit+0x54                            libc-2.27.so:on_exit+0xe0                         2
    ret      libc-2.27.so:on_exit+0x1a7                                libc-2.27.so:__cxa_atexit+0x59                   3
    ret     libc-2.27.so:__cxa_atexit+0xb4                            libc-2.27.so:__libc_start_main+0x4c               2
    call   libc-2.27.so:__libc_start_main+0x76                       ls:_obstack_memory_used+0xc30                      1
    call    ls:_obstack_memory_used+0xc5c                             ls:_init                                          2
    ret      ls:_init+0x16                                             ls:_obstack_memory_used+0xc61                    3
    call    ls:_obstack_memory_used+0xc79                             ls:_init+0x21f8                                   2
    ret      ls:_init+0x21a9                                           ls:_obstack_memory_used+0xc7d                    3
    ret     ls:_obstack_memory_used+0xc94                             libc-2.27.so:__libc_start_main+0x78               2
    call   libc-2.27.so:__libc_start_main+0x9a                       libc-2.27.so:_setjmp                               1
    ret     libc-2.27.so:__sigsetjmp+0x83                             libc-2.27.so:__libc_start_main+0x9f               2
    call   libc-2.27.so:__libc_start_main+0xe5                       ls:_init+0x738                                     1
    <clipped>
    """

    # Loop through each instruction in the trace
    for i in t:
        print(i)

    # Remove the trace so you can run a different one
    trace.remove()

    # Take a slice of the trace
    t2 = t[12:24]
