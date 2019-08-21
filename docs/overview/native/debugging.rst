=========
Debugging
=========

While the driving concept behind ``revenge`` is dynamic binary
instrumentation, you can still do some traditional debugging activities.

Breakpoints
===========
Breakpoints in ``revenge`` are not the normal ``int3`` or even hardware
breakpoints. Instead, ``revenge`` re-writes the address in question with a
small loop that effectively stops it there, while not actually suspending the
thread. This allows for setup to be completed or other activites to be run, and
DBI to proceed part way through the binary.

Examples
--------

.. code-block:: python3

    # Set a breakpoint at main
    process.memory['a.out:main'].breakpoint = True

    # Continue execution from main, later
    process.memory['a.out:main'].breakpoint = False

    # Check if any given point in memory has a breakpoint
    process.memory['a.out:main'].breakpoint
