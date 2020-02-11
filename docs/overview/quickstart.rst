===========
Quick Start
===========

First off, head over to `installation <installation.html>`_ to get setup
initially. Also, once you're done with quick start, please take a moment to
read about the `philosophy <philosophy.html>`_ to get a better understanding
of how to use the tool.

Just Show Me
============

.. code-block:: python3

    from revenge import Process

    # Load up /bin/ls, but don't let it continue
    p = Process("/bin/ls", resume=False)

    # Optionally, specify argv and envp
    p = Process(["/bin/ls", ".."], envp={'var1':'val1'})

    # Print out some basic info about the running process
    print(p.threads)
    print(p.modules)
    print(p.memory)

    # This will remove the breakpoint and resume execution
    p.memory[p.entrypoint_rebased].breakpoint = False

    # Interact with the process
    p.stdout(12) # Read 12 bytes of stdout
    p.stderr(12) # Read 12 bytes of stderr
    p.stdin(b"hello!\n") # Write to stdin
    p.interactive() # Quasi-interactive shell. ctrl-c to exit.

Check out the examples for each platform for more quick start ideas.

A Little Deeper
===============

The two cent starting guide is that everything in ``revenge`` hangs off the
core class called ``Process``.

:meth:`revenge.Process`

This has traditionally been the starting point for opening applications,
however in some cases (Android for the moment) it has become necessary to add a
wrapper aroud Process to get the ball rolling. This is the Device class that is
extended for various platforms. In the future, it will likely be the starting
point for running an application.
