==========
Decompiler
==========

The ``decompiler`` plugin is an abstraction around the concept of decompiling
code. While it registers as a single plugin, the actual decompiler backend is
flexible and can be extended with new decompilers. When ``revenge`` starts up,
a decompiler will be selected from those that ``revenge`` can identify that you
have on your system.

General Usage
=============

Here's a basic example. For more examples, see the code docs under
:class:`~revenge.plugins.decompiler.Decompiler`.

.. code-block:: python
    
    # Attempt to decompile an address
    decomp = process.decompiler.decompile_address(0x1234)

    # Attempt to decompile a function
    decomp = process.decompiler.decompile_function(0x1234)

See notes for each decompiler engine about possible caveats.

Engines
=======

 - :ref:`radare2_ghidra_decompiler` (priority 70)

Building A Decompiler
=====================

To build a decompiler engine (building the decompiler is WAY beyond this little
documentation), you must extend the
:class:`~revenge.plugins.decompiler.DecompilerBase` class. The calls to
decompile MUST return an instance of
:class:`~revenge.plugins.decompiler.Decompiled`, which in turn must have 0 or
more populated :class:`~revenge.plugins.decompiler.DecompiledItem` instances.

On initialization of your decompiler, if it's valid for the current configuration,
register it as an option with ``process.decompiler._register_decompiler``.

The priority is mostly a way to select from multiple competing decompilers. The higher
the number the higher priority.
