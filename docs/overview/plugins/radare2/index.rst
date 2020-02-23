=======
Radare2
=======

The `radare2` plugin will attempt to utilize `radare2` to enrich local
reversing information. It also exposes the ability to connect to a remote
`radare2` instance and push enrichment data there.

Connecting
==========

If ``revenge`` identifies that `radare2` is installed, the plugin will
automatically load and start up a base instance of `radare2` for the given
binary. By default, it will NOT perform auto analysis, since this can be
expensive and time consuming.

Connecting to a remote instance can be done with the
:meth:`~revenge.plugins.radare2.Radare2.connect` method.

Highlighting
============

One thing that can be very helpful when analyzing code paths is to graphically
:meth:`~revenge.plugins.radare2.Radare2.highlight` them. This allows you to
more easily see where a path travelled. Further, this becomes helpful when
trying to identify where your test cases (or fuzzer) has covered in your code.
While it can be done programmatically, this plugin exposes an easy way to view
(in `radare2`) the paths covered.

Whereas other methods in this plugin can be used without a remote connection,
highlighting likely makes the most sense when connected to a remote `radare2`
session.

Example
-------

.. code-block:: python

    # Startup r2 in a separate window
    # r2 -A ./whatever
    # In that window, start up the HTTP server
    # =h& 12345

    # Connect up to that session from your revenge session
    process.radare2.connect("http://127.0.0.1:12345")

    # Setup a timeless tracer
    timeless = process.techniques.NativeTimelessTracer()
    timeless.apply()
    t = list(timeless)[0]

    # Assuming you need to send some input to this program
    process.memory[process.entrypoint].breakpoint = False
    process.stdin("some input\n")

    # Now that our trace is populated, send that data off to our r2 session
    process.radare2.highlight(t)

    # In your other r2, you should now see highlights for this path in the
    # Visual mode and the Very Visual mode
