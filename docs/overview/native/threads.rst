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
    +-------+---------+----------------+--------------+-------+
    |   id  |  state  |       pc       |    module    | Trace |
    +-------+---------+----------------+--------------+-------+
    | 81921 | waiting | 0x7f2d9b2759d0 | libc-2.27.so |   No  |
    +-------+---------+----------------+--------------+-------+
    """

    # Or you can go through the threads programmatically
    for thread in threads:
        print(thread)

Tracing
=======

Please see `tracing <tracing.html>`_ for more information.
