=======
Threads
=======

Enumerating
===========

Enumerating threads is done by calling `process.threads` which is actually a
Threads object.

:class:`revenge.threads.Threads`

This threads object will look for the most current thread information every
time you call methods on it, so if you're looking to be performant and don't
need to refresh the threads, keep the return objects instead of re-enumerating.

Examples
--------

.. code-block:: python3

    threads = process.threads
    print(threads)

    """
    +--------+---------+----------------+--------------+-------+
    |   id   |  state  |       pc       |    module    | Trace |
    +--------+---------+----------------+--------------+-------+
    | 120204 | waiting | nanosleep+0x40 | libc-2.27.so |   No  |
    +--------+---------+----------------+--------------+-------+
    """

    # Or you can go through the threads programmatically
    for thread in threads:
        print(thread)

    # If you know the thread id, you can index to it
    thread = process.threads[81921]

Tracing
=======

Please see `tracing <tracing.html>`_ for more information.

Creating
========

You can easily create new threads using :func:`~revenge.threads.Threads.create`.

Examples
--------

.. code-block:: python3

    # Create a stupid callback that just spins
    func = process.memory.create_c_function("void func() { while ( 1 ) { ; } }")

    # Start the thread
    t = process.threads.create(func.address)
    assert isinstance(t, revenge.threads.thread.Thread)

    # View it running
    print(process.threads)

Return Values
=============

Thread return values are handled by ``revenge`` in the same way the native
operating system does. Specifically, you can call
:meth:`~revenge.threads.Thread.join` to get the return value.

Note, if you're attempting to return something outside a standard integer (such
as a double or float), you will need to malloc space yourself and save off the
value in there, then return the pointer to that space instead.
