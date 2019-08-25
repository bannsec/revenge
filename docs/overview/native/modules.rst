=======
Modules
=======

For ``revenge``, a module is any loaded library or shared library.

Listing Modules
===============

.. code-block:: python3

    # List current modules
    print(process.modules)
    """
    +--------------------+----------------+-----------+---------------------------------------------------------------+
    |        name        |      base      |    size   | path                                                          |
    +--------------------+----------------+-----------+---------------------------------------------------------------+
    |       test2        | 0x557781b84000 |  0x202000 | /home/user/tmp/test2                                          |
    |  linux-vdso.so.1   | 0x7ffd3b5ee000 |   0x2000  | linux-vdso.so.1                                               |
    |    libc-2.27.so    | 0x7fc6a8499000 |  0x3ed000 | /lib/x86_64-linux-gnu/libc-2.27.so                            |
    |     ld-2.27.so     | 0x7fc6a888a000 |  0x229000 | /lib/x86_64-linux-gnu/ld-2.27.so                              |
    | libpthread-2.27.so | 0x7fc6a827a000 |  0x21b000 | /lib/x86_64-linux-gnu/libpthread-2.27.so                      |
    | frida-agent-64.so  | 0x7fc6a6294000 | 0x17ba000 | /tmp/frida-7846ef0864a82f3695599c271bf7b0f1/frida-agent-64.so |
    | libresolv-2.27.so  | 0x7fc6a6079000 |  0x219000 | /lib/x86_64-linux-gnu/libresolv-2.27.so                       |
    |   libdl-2.27.so    | 0x7fc6a5e75000 |  0x204000 | /lib/x86_64-linux-gnu/libdl-2.27.so                           |
    |   librt-2.27.so    | 0x7fc6a5c6d000 |  0x208000 | /lib/x86_64-linux-gnu/librt-2.27.so                           |
    |    libm-2.27.so    | 0x7fc6a58cf000 |  0x39e000 | /lib/x86_64-linux-gnu/libm-2.27.so                            |
    +--------------------+----------------+-----------+---------------------------------------------------------------+
    """

Module Lookup
=============

Instead of enumerating modules, you can look up a module by it's full name, a
glob name, or by giving an address.

.. code-block:: python3

    # Get the base address for specific module
    hex(process.modules['test2'].base)
    0x557781b84000

    # Or by glob
    process.modules['libc*']
    """<Module libc-2.27.so @ 0x7f282f7aa000>"""

    # Or resolve address into corresponding module
    process.modules[0x7f282f7ab123]
    """<Module libc-2.27.so @ 0x7f282f7aa000>"""

Symbols
=======

Symbols for modules can be resolved and enumerated in a few ways.

Examples
--------

.. code-block:: python3

    # Grab symbol address for main function in my_bin
    main = process.modules['a.out'].symbols['main']

    # List all symbols from libc
    print(process.modules['*libc*'].symbols)
