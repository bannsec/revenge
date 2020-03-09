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
:attr:`~revenge.plugins.dwarf.Dwarf.functions` property.
