======
Memory
======

Resolve Address
===============

Since we're always dealing with running processes, we need a way to quickly
identify locations of things of interest in memory. The primary way to do this
is though a location format.

The location format is simply a string that takes the form ``<module>:<offset
or symbol>``. If no module is specified, the symbol will be resolved in the
normal process manner (local->imports).

Resolving specific non-export symbols for libraries can be done with the
Symbols class instead.

Examples
--------

.. code-block:: python3

    import revenge
    process = revenge.Process("/bin/ls", resume=False, verbose=False)

    # Resolve strlen from libc
    strlen = process.memory[':strlen']

    # Resolve symbol test from the main binary
    t = process.memory['bin:test']

    # Grab memory object directly with address
    thing = process.memory[0x12345]

    # Write memory directly to address
    process.memory[0x12345] = thing

Find
====

One common task is to find something in memory. ``revenge`` exposes this
through the MemoryFind class.

:class:`revenge.memory.MemoryFind`

Examples
--------

.. code-block:: python3

    import revenge

    process = revenge.Process("/bin/ls", resume=False, verbose=False)

    f = process.memory.find(types.StringUTF8('/bin/sh'))
    """<MemoryFind found 1 completed>"""

    [hex(x) for x in f]
    """['0x7f9c1f3ede9a']"""
    

Read/Write
==========

``revenge`` has the ability to read and write to memory. It does this through
the MemoryBytes class.

:class:`revenge.memory.MemoryBytes`

Because of the inherent ambiguities of reading and writing to memory, you must
specify the type of thing that you're reading or writing. Both reading and
writing are done as a property to the class.

Examples
--------

.. code-block:: python3

    import revenge

    # Start up /bin/ls
    process = revenge.Process("/bin/ls", resume=False, verbose=False)

    # Grab some memory location
    mem = process.memory['ls:0x12345']

    # Read UTF8 string from that location
    mem.string_utf8

    # Write UTF8 string to that location
    mem.string_utf8 = "Hello world"

    # Read signed 32-bit integer
    mem.int32

    # Write signed 32-bit integer
    mem.int32 = -5

    # Extract a range of bytes
    mem = process.memory[0x12345:0x22222]
    mem.bytes

    # Write bytes into memory
    mem.bytes = b'AB\x13\x37'

Memory Pages
============

We can investigate the memory layout programmatically or visually. We can also
modify page permissions.

Examples
--------

.. code-block:: python3

    import revenge
    process = revenge.Process("/bin/ls", resume=False, verbose=False)

    # Print out memory layout like proc/<pid>/maps
    print(process.memory)

    """
     564031418000-56403141d000          r-x  /bin/ls
     56403141d000-56403141e000          rwx  /bin/ls
     56403141e000-564031437000          r-x  /bin/ls
     564031636000-564031638000          r--  /bin/ls
     564031638000-564031639000          rw-  /bin/ls
     564031639000-56403163a000          rw-
     5640326bd000-5640326de000          rw-
     7f07f0000000-7f07f0021000          rw-
     7f07f8000000-7f07f8021000          rw-
     7f07fc272000-7f07fca72000          rw-
     7f07fca73000-7f07fd273000          rw-
     7f07fd274000-7f07fda74000          rw-
     7f07fda75000-7f07fe275000          rw-
     7f07fe275000-7f07fe412000          r-x  /lib/x86_64-linux-gnu/libm-2.27.so
     7f07fe611000-7f07fe612000          r--  /lib/x86_64-linux-gnu/libm-2.27.so
     7f07fe612000-7f07fe613000          rw-  /lib/x86_64-linux-gnu/libm-2.27.so
     7f07fe613000-7f07fe61a000          r-x  /lib/x86_64-linux-gnu/librt-2.27.so
     7f07fe819000-7f07fe81a000          r--  /lib/x86_64-linux-gnu/librt-2.27.so
     7f07fe81a000-7f07fe81b000          rw-  /lib/x86_64-linux-gnu/librt-2.27.so
     7f07fffd5000-7f0800000000          rw-
     7f0800000000-7f0800021000          rw-
     7f0804013000-7f080402a000          r-x  /lib/x86_64-linux-gnu/libresolv-2.27.so
     7f080422a000-7f080422b000          r--  /lib/x86_64-linux-gnu/libresolv-2.27.so
     7f080422b000-7f080422c000          rw-  /lib/x86_64-linux-gnu/libresolv-2.27.so
     7f080422c000-7f080422e000          rw-
     7f080422f000-7f0804a2f000          rw-
     7f0804a2f000-7f0804a49000          r-x  /lib/x86_64-linux-gnu/libpthread-2.27.so
     7f0804c48000-7f0804c49000          r--  /lib/x86_64-linux-gnu/libpthread-2.27.so
     7f0804c49000-7f0804c4a000          rw-  /lib/x86_64-linux-gnu/libpthread-2.27.so
     7f0804c4a000-7f0804c4e000          rw-
     7f0804c4e000-7f0804c51000          r-x  /lib/x86_64-linux-gnu/libdl-2.27.so
     <clipped>
    """

    # Loop through the maps programmatically
    for m in process.memory.maps:
        print(m)

    # Make a page rwx
    page = process.memory.maps[0x12345]
    page.protection = 'rwx'

Allocate Memory
===============

We can allocate and free memory with direct calls to the underlying operating
system APIs, or through the memory wrapper.

Examples
--------

.. code-block:: python3

    import revenge
    process = revenge.Process("/bin/ls", resume=False, verbose=False)

    # Allocate a string in memory
    mem = process.memory.alloc_string("Hello!")

    # Use it like a pointer
    # Free it once you're done
    mem.free()

    # Allocate some space generically
    mem = process.memory.alloc(128)
