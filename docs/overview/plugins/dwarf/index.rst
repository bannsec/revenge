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
:meth:`~revenge.plugins.dwarf.Dwarf.lookup_function` method to resolve an
address to it's function.

Source Lookup
=============

The DWARF plugin can assist with looking up what the corresponding file and
line number would be for a given address. As with all things in ``revenge``
this address is the current loaded address, rather than a base address. This
lookup can be done via :meth:`~revenge.plugins.dwarf.Dwarf.lookup_file_line`.

You can also ask DWARF to "decompile" an address for you. Note, this isn't
actually decompiling, but the names are kept the same to avoid confusion.
Instead of actually decompiling, the plugin will attempt to lookup the source
address and line for your running address, and then lookup the corresponding
source code for it. You must ensure you have told the plugin where your source
directories are by using :meth:`~revenge.plugins.dwarf.Dwarf.add_source_path`.
Lookups for a source address can be done via
:meth:`~revenge.plugins.dwarf.Dwarf.decompile_address` and
:meth:`~revenge.plugins.dwarf.Dwarf.decompile_function`.
