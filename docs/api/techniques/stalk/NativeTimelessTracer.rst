.. _NativeTimelessTracerTechnique-page:

====================
NativeTimelessTracer
====================

The ``NativeTimelessTracer``'s purpose is to provide a standard means of
performing timeless tracing. It is similar in concept to other timeless
debuggers such as `qira <https://qira.me/>`_ and `rr
<https://rr-project.org/>`_.

Caveats
=======

The major caveat for now is that it is going to be substantially slower than
the other timeless debugger options. Performance will hopefully be improved in
future releases.

Since this is a newer feature, it is currently only tested against:

- Linux (i386 and x64)

Why?
====

Timeless Debugging (or really, timeless tracing for ``revenge``) is helpful for
more thoroughly inspecting what happens during program execution. Instead of
re-running an application and setting different break points each time, the
tracer will attempt to gather all relevant information at each instruction step
so that you can go forwards and backwards in time of the binary execution
(thus, "timeless").

``revenge``'s implementation has a goal of being platform and architecture
independent. Meaning, the same syntax you would use to timeless trace on an
amd64 Windows machine should work on an i386 MacOS or an ARM Linux.

Also, due to ``revenge``'s modularity, the timeless tracer will be used as a
core component to other techniques and analysis engines, making it a building
block, not an endpoint.

How do I use it?
================

The timeless tracer can be run just like any other
:class:`~revenge.techniques.Technique`. Once the trace is acquired, you can
manually look through it, or use an Analysis module (coming soon).

NativeTimelessTracer
====================

.. autoclass:: revenge.techniques.native_timeless_tracer.NativeTimelessTracer
    :members:
    :undoc-members:
    :show-inheritance:
    
NativeTimelessTrace
===================

.. autoclass:: revenge.techniques.native_timeless_tracer.NativeTimelessTrace
    :members:
    :undoc-members:
    :show-inheritance:

NativeTimelessTraceItem
=======================

.. autoclass:: revenge.techniques.native_timeless_tracer.NativeTimelessTraceItem
    :members:
    :undoc-members:
    :show-inheritance:
