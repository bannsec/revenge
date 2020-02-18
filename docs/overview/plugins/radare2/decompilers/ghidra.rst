.. _radare2_ghidra_decompiler:

==============
Radare2-Ghidra
==============

The ``radare2`` plugin exposes ``ghidra`` as a decompiler engine through the
use of a plugin called r2ghidra-dec_.

.. note::
    Ghidra does NOT need to be installed for this. r2ghidra-dec actually
    compiles the ghidra decompiler and takes care of the conversions.

Installation
============

You will obviously need to have radare2 installed. Beyond that, for this
decompiler to work, you wlil need to have ``r2ghidra-dec`` installed. Do the
following to install it.

.. code-block:: bash
    
    # This assumes you already have r2 installed
    
    # Install the build dependencies. These should work on ubuntu.
    sudo apt update
    sudo apt install -y wget curl bison flex pkg-config

    # Download and install the latest cmake. Unfortunately, the repo version is
    # likely too old for ubuntu and others.
    # https://github.com/Kitware/CMake/releases/latest

    # Now install the plugin
    r2pm init && r2pm install r2ghidra-dec

.. _r2ghidra-dec: https://github.com/radareorg/r2ghidra-dec
