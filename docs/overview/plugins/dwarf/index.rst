=====
DWARF
=====

DWARF is a format for debugging info relating to ELF files. Standard
compilations of binaries do not contain DWARF info. However, when you compile
binaries with this info (generally with the `-g` flag), much more useful
inforamtion is available. This plugin attempts to expose that information.

General Interaction
===================

General interaction with the DWARF plugin is via the `modules`. For instance:

.. code-block:: python

    bin = process.modules['bin']
    dwarf = bin.dwarf

Functions
=========

Functions are enumerated and exposed via the
:attr:`~revenge.plugins.dwarf.Dwarf.functions` property. You can utilize the 
:meth:`~revenge.plguins.dwarf.Dwarf.lookup_function` method to resolve an
address to it's function.

Source Lookup
=============

The DWARF plugin can assist with looking up what the corresponding file and
line number would be for a given address. As with all things in ``revenge``
this address is the current loaded address, rather than a base address. This
lookup can be done via :meth:`~revenge.plugins.dwarf.Dwarf.lookup_file_line`.
