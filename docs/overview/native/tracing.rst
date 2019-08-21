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
    trace = process.tracer.instructions(call=True, ret=True)

    t = list(trace)[0]

    print(t)
    """
    call      libc-2.27.so:0x7f4b704f89de   -> libc-2.27.so:0x7f4b70544740
    ret       libc-2.27.so:0x7f4b7054476f   -> libc-2.27.so:0x7f4b704f89e3
    ret       libc-2.27.so:0x7f4b704f89ed   -> frida-agent-64.so:0x7f4b6df41216
    ret       ld-2.27.so:0x7f4b70c420a5     -> ls:0x5613ad9b2030
    call      ls:0x5613ad997874             -> libc-2.27.so:0x7f4b70435ab0
    call      libc-2.27.so:0x7f4b70435af7   -> libc-2.27.so:0x7f4b70457430
    call      libc-2.27.so:0x7f4b70457484   -> libc-2.27.so:0x7f4b70457220
    ret       libc-2.27.so:0x7f4b704572e7   -> libc-2.27.so:0x7f4b70457489
    <clipped>
    """

    # Loop through each instruction in the trace
    for i in t:
        print(i)

    # Stop the trace so you can run a different one
    t.stop()
